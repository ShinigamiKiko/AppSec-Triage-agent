"""What triage asks a language server, and what it does with the answers.

Two questions, chosen because each maps onto a measured failure:

1. **Where does this value come from?** On a real Symfony project every CWE-89
   finding landed in `unknown` for one reason: the model saw the query being
   assembled and could not see where the interpolated fragment came from. A
   `definition` lookup answers that in milliseconds.

2. **Is this code reachable from outside?** CodeQL says a tainted path exists;
   it does not say whether anything calls the function containing it. A path
   inside a helper that only tests invoke is hygiene, not a vulnerability. This
   is the one question neither the scanner nor the model can answer, and it is
   where CodeQL and LSP genuinely compose rather than overlap.

Everything here is best-effort. A language server is a large, slow, stateful
dependency; when it is missing or unhappy, triage carries on with less context
and says so, exactly like the source resolver does.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..config import LSPConfig
from ..models import Finding
from .client import Location, LSPClient, uri_to_path

log = logging.getLogger(__name__)

_IDENTIFIER = re.compile(r"\$?[A-Za-z_]\w*")

_KEYWORDS = {
    "if", "else", "elif", "for", "while", "return", "def", "class", "function",
    "public", "private", "protected", "static", "const", "var", "let", "new",
    "true", "false", "null", "none", "self", "this", "and", "or", "not", "in",
    "import", "from", "as", "try", "catch", "except", "finally", "with", "echo",
    "print", "int", "str", "string", "bool", "float", "array", "list", "dict",
}

_NON_PRODUCTION = re.compile(
    r"(^|/)(tests?|spec|__tests__|fixtures?|testdata|docs?|examples?|samples?|"
    r"migrations?|vendor|node_modules)/",
    re.IGNORECASE,
)

_ENTRYPOINT_FILE = re.compile(
    r"(^|/)(urls?|routes?|routing|web|api|endpoints?|controllers?|handlers?|resources?)\.(py|php|js|ts|rb|go|java)$"
    r"|(controller|handler|endpoint|resource|listener|subscriber|consumer|webhook)",
    re.IGNORECASE,
)

_TAINT_SOURCE_RHS = re.compile(
    r"\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)\b"
    r"|\$request\s*->\s*(get|query|request|getContent|headers|cookies|files|attributes|getPayload)"
    r"|->\s*getParameter\s*\("
    r"|php://input"
    r"|\bfilter_input\s*\(",
    re.IGNORECASE,
)

_ENTRYPOINT_CALL = re.compile(
    r"(\bpath\s*\(|\bre_path\s*\(|\burl\s*\(|@app\.route|@router\.|@(Get|Post|Put|Delete|Request)Mapping"
    r"|Route::(get|post|put|delete|any|match)|->(get|post|put|delete)\s*\(\s*['\"]/"
    r"|#\[Route|@Route|app\.(get|post|put|delete)\s*\(|router\.(get|post|put|delete)\s*\()",
    re.IGNORECASE,
)


@dataclass(slots=True)
class SymbolContext:
    """What the server could tell us about one finding."""

    definitions: list[Location] = field(default_factory=list)
    callers: list[Location] = field(default_factory=list)
    taint_sources: list[Location] = field(default_factory=list)
    reachable_from_entrypoint: bool | None = None
    callers_all_non_production: bool | None = None
    resolved: bool = False
    detail: str = ""


class LSPService:
    """One server per language, started lazily and reused for the whole run."""

    def __init__(self, cfg: LSPConfig, roots: list[Path]) -> None:
        self.cfg = cfg
        self.roots = [Path(r).resolve() for r in roots if Path(r).exists()]
        self._clients: dict[str, LSPClient | None] = {}
        self._lines: dict[Path, list[str]] = {}
        self.stats = {"resolved": 0, "no_server": 0, "no_answer": 0, "definitions": 0, "callers": 0}


    def _language_for(self, path: str) -> str | None:
        return self.cfg.language_for(path)

    def ensure_ready(self, language: str) -> str | None:
        """Start the server for `language` now, before any finding is triaged.

        Exists for languages where the resolver is mandatory: discovering a dead
        server on finding 1 of 300 after an hour of inference is the expensive
        way to learn it. Returns a human-readable problem, or None when ready.
        """
        if not self.roots:
            return "none of the configured source roots exist on disk"
        spec = self.cfg.servers.get(language) or {}
        if not spec.get("command"):
            return f"no {language} server configured in lsp.yaml"
        if self._client(language) is None:
            return f"the {language} language server failed to start (see the warning above; try `appsec-triage doctor`)"
        return None

    def _client(self, language: str) -> LSPClient | None:
        if language in self._clients:
            return self._clients[language]

        spec = self.cfg.servers.get(language) or {}
        command = spec.get("command") or []
        if not command or not self.roots:
            self._clients[language] = None
            return None

        client = LSPClient(
            command=list(command),
            root=self.roots[0],
            timeout_s=self.cfg.request_timeout_s,
            init_timeout_s=self.cfg.startup_timeout_s,
            index_timeout_s=self.cfg.index_timeout_s,
            path_map=dict(spec.get("path_map") or {}),
        )
        if not client.start():
            log.warning("language server for %s unavailable: %s", language, client.error)
            self._clients[language] = None
            return None
        log.info("language server for %s ready (%s)", language, " ".join(command[:2]))
        self._clients[language] = client
        return client

    def _resolve_path(self, file_path: str) -> Path | None:
        rel = Path(file_path.replace("\\", "/"))
        for root in self.roots:
            for candidate in (root / rel, *(root / Path(*rel.parts[i:]) for i in range(1, len(rel.parts)))):
                if candidate.is_file():
                    return candidate
        return None

    def _raw_line(self, path: Path, line: int) -> str:
        """The line exactly as it is on disk — indentation included.

        Character offsets are computed against this. `_line_text` strips for
        display, and using the stripped form for positions shifts every column
        by the indent: on a real project that put the cursor inside the wrong
        identifier and the server answered nothing, which looked like a server
        that could not resolve local variables.
        """
        if path not in self._lines:
            try:
                self._lines[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                self._lines[path] = []
        lines = self._lines[path]
        return lines[line - 1] if 0 < line <= len(lines) else ""

    def _line_text(self, path: Path, line: int) -> str:
        """Display form: stripped. Never use this to compute a column."""
        return self._raw_line(path, line).strip()

    def _path_map_for(self, language: str) -> dict[str, str]:
        return dict((self.cfg.servers.get(language) or {}).get("path_map") or {})

    def _to_location(self, item: dict, path_map: dict[str, str] | None = None) -> Location | None:
        """Workspace-relative, or dropped.

        A definition in the standard library or in `site-packages` says nothing
        about this codebase — `subprocess.Popen` is defined in CPython, which
        the reviewer already knows. Left unfiltered these consumed the whole
        definition budget on the first real test.
        """
        try:
            path = uri_to_path(item["uri"], path_map)
            line = int(item["range"]["start"]["line"]) + 1
        except (KeyError, TypeError, ValueError):
            return None
        for root in self.roots:
            try:
                display = str(path.relative_to(root)).replace("\\", "/")
            except ValueError:
                continue
            if _NON_PRODUCTION.search(display):
                return None
            return Location(
                file_path=display, line=line, text=self._line_text(path, line), symbol=item.get("name", "")
            )
        return None


    def enrich(self, finding: Finding) -> SymbolContext:
        ctx = SymbolContext()
        line_no = finding.code_context.start_line
        if not line_no:
            return ctx

        language = self._language_for(finding.code_context.file_path)
        if not language:
            self.stats["no_server"] += 1
            ctx.detail = "no language server configured for this file type"
            return ctx

        path = self._resolve_path(finding.code_context.file_path)
        if path is None:
            self.stats["no_server"] += 1
            ctx.detail = "file not found under the configured roots"
            return ctx

        client = self._client(language)
        if client is None:
            self.stats["no_server"] += 1
            ctx.detail = f"no working {language} language server"
            return ctx

        spec = self.cfg.servers.get(language) or {}
        client.open_document(path, spec.get("language_id", language))

        source_line = self._raw_line(path, line_no)
        ctx.definitions = self._definitions_in(client, path, line_no, source_line)
        ctx.taint_sources = [d for d in ctx.definitions if _TAINT_SOURCE_RHS.search(d.text or "")]
        if self.cfg.reachability:
            ctx.callers = self._callers_of(client, path, line_no, source_line)
            self._judge_reachability(ctx)

        ctx.resolved = bool(ctx.definitions or ctx.callers)
        if ctx.resolved:
            self.stats["resolved"] += 1
            self.stats["definitions"] += len(ctx.definitions)
            self.stats["callers"] += len(ctx.callers)
        else:
            self.stats["no_answer"] += 1
        return ctx

    def _definitions_in(self, client: LSPClient, path: Path, line_no: int, source_line: str) -> list[Location]:
        """Resolve the identifiers on the flagged line, nearest-first.

        Bounded by `max_definitions`: a dense line can hold a dozen names, and
        the point is to answer "where did this value come from", not to paste
        the module into the prompt.
        """
        found: list[Location] = []
        seen: set[tuple[str, int]] = set()

        matches = sorted(
            _IDENTIFIER.finditer(source_line),
            key=lambda m: (0 if m.group(0).startswith("$") else 1, m.start()),
        )
        for match in matches:
            name = match.group(0)
            if name.lstrip("$").lower() in _KEYWORDS or len(name.lstrip("$")) < 2:
                continue
            character = match.start() + (1 if name.startswith("$") else 0)
            for item in client.definition(path, line_no, character):
                loc = self._to_location(item, client.path_map)
                if loc is None or (loc.file_path, loc.line) in seen:
                    continue
                if loc.line == line_no and loc.file_path.endswith(path.name):
                    continue
                seen.add((loc.file_path, loc.line))
                loc.symbol = name
                found.append(loc)
                if len(found) >= self.cfg.max_definitions:
                    return found
        return found

    def _callers_of(self, client: LSPClient, path: Path, line_no: int, source_line: str) -> list[Location]:
        """Callers via callHierarchy, or references as the fallback.

        `callHierarchy` is optional in LSP and plenty of servers skip it —
        python-lsp-server announces no `callHierarchyProvider` at all. References
        are weaker (they include reads, not just calls) but they answer the
        question that matters here: does anything outside this file touch it.
        """
        items = client.incoming_calls(path, line_no, 0)
        via = "callHierarchy"
        if not items:
            enclosing = self._enclosing_definition(path, line_no)
            if enclosing is None:
                return []
            def_line, character = enclosing
            items = client.references(path, def_line, character)
            via = "references"

        out: list[Location] = []
        for item in items[: self.cfg.max_callers]:
            loc = self._to_location(item, client.path_map)
            if loc and loc.line != line_no:
                loc.symbol = loc.symbol or via
                out.append(loc)
        return out

    def _enclosing_definition(self, path: Path, line_no: int) -> tuple[int, int] | None:
        """Walk up to the `def`/`function` that contains the flagged line."""
        if path not in self._lines:
            self._line_text(path, 1)
        lines = self._lines.get(path) or []
        pattern = re.compile(
            r"^\s*(?:(?:public|private|protected|static|final|abstract|async)\s+)*"
            r"(?:def|function|fun|func)\s+&?(\w+)"
        )
        for n in range(min(line_no, len(lines)), 0, -1):
            if m := pattern.match(lines[n - 1]):
                return n, m.start(1)
        return None

    @staticmethod
    def _judge_reachability(ctx: SymbolContext) -> None:
        """Two facts worth stating, and nothing beyond what the callers show.

        Absence of callers is deliberately *not* treated as "unreachable": a
        server that failed to index, a framework that wires routes by
        annotation, or dynamic dispatch all produce an empty list. Concluding
        "nothing calls this, so it is safe" from that would be the exact kind of
        silent false negative this pipeline exists to prevent.
        """
        if not ctx.callers:
            return
        non_production = [c for c in ctx.callers if _NON_PRODUCTION.search(c.file_path)]
        ctx.callers_all_non_production = len(non_production) == len(ctx.callers)
        ctx.reachable_from_entrypoint = any(
            _ENTRYPOINT_CALL.search(c.text or "")
            or _ENTRYPOINT_FILE.search(c.file_path)
            or _ENTRYPOINT_FILE.search(c.symbol or "")
            for c in ctx.callers
            if not _NON_PRODUCTION.search(c.file_path)
        )

    def close(self) -> None:
        for client in self._clients.values():
            if client:
                client.stop()
        self._clients.clear()
