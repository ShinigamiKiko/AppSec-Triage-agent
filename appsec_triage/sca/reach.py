"""Step 4: does untrusted input actually reach the call?"""

from __future__ import annotations

import json
import logging
import posixpath
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from ..prompts import registry

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding
    from .presence import Hit

log = logging.getLogger(__name__)


def _count(lsp, key: str) -> None:
    """Tally an LSP question the chain asked, for the run's language-server line."""
    stats = getattr(lsp, "stats", None)
    if isinstance(stats, dict):
        stats[key] = stats.get(key, 0) + 1

_MAX_HOPS = 4

_INPUT_DRIVEN_CWES = {
    "22", "23", "36", "73",
    "77", "78", "88",
    "79", "80", "83", "87",
    "89", "564", "943",
    "90", "91",
    "94", "95", "96", "98",
    "113", "117", "93",
    "502",
    "611", "776", "827",
    "918",
}


class Reachability(str, Enum):
    REACHABLE = "reachable"
    NO_INPUT_PATH = "no_input_path"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ReachResult:
    verdict: Reachability
    entrypoint: str = ""
    taint_path: str = ""
    tools_used: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def actionable(self) -> bool:
        return self.verdict is Reachability.REACHABLE


def needs_input_path(cwe: str | None) -> bool:
    """Whether this weakness only matters with attacker-controlled input."""
    if not cwe:
        return False
    digits = "".join(ch for ch in str(cwe) if ch.isdigit())
    return digits in _INPUT_DRIVEN_CWES


def _entrypoint_above(
    lsp: LSPService,
    routes: RouteIndex | None,
    hit: Hit,
    root: Path,
) -> tuple[str, str]:
    """Walk incoming calls outwards; return (description, problem)."""
    language = lsp.cfg.language_for(hit.file)
    if not language:
        return "", f"нет языкового сервера для {hit.file}"
    client = lsp._client(language)
    if client is None:
        return "", f"языковой сервер {language} не запустился"
    if not client.supports("callHierarchyProvider"):
        if routes is not None and routes.usable:
            found = routes.perimeter(hit.file)
            if found:
                hops, path = found
                return f"маршрут в {hops} переход(ах): {' -> '.join(path[:4])}", ""
            return "", "файл не связан ни с одним маршрутом"
        return "", f"сервер {language} не умеет callHierarchy, таблицы маршрутов нет"

    path = root / hit.file
    seen: set[tuple[str, int]] = set()
    frontier = [(path, hit.line, [f"{hit.file}:{hit.line}"])]
    for _ in range(_MAX_HOPS):
        next_frontier = []
        for current, line, trail in frontier:
            for call in client.incoming_calls(current, line - 1, 0) or []:
                item = call.get("from") or {}
                uri = item.get("uri") or ""
                name = item.get("name") or "?"
                start = ((item.get("selectionRange") or {}).get("start") or {}).get("line", 0)
                key = (uri, start)
                if key in seen:
                    continue
                seen.add(key)
                step = [*trail, name]
                if routes is not None and routes.usable:
                    rel = uri.replace("file://", "")
                    route = routes.enclosing(rel, start + 1)
                    if route is not None:
                        return f"{route.describe()} через {' -> '.join(step[-3:])}", ""
                next_frontier.append((Path(uri.replace("file://", "")), start + 1, step))
        if not next_frontier:
            break
        frontier = next_frontier
    return "", f"за {_MAX_HOPS} переходов точка входа не найдена"


def _trace_file(file: str, root: Path, *, psalm: bool = False) -> str | None:
    """Repository-relative identity, including scanner-specific virtual roots."""
    file = file.replace("\\", "/")
    if file.startswith("file:"):
        try:
            uri = urlsplit(file)
        except ValueError:
            return None
        if uri.netloc not in ("", "localhost") or uri.query or uri.fragment:
            return None
        file = unquote(uri.path).replace("\\", "/")
        if not file.startswith("/"):
            return None
    if not file or file == "<unknown>" or any(ord(ch) < 32 for ch in file):
        return None
    file = posixpath.normpath(file)
    if psalm and file.startswith("../"):
        candidate = file
        while candidate.startswith("../"):
            candidate = candidate[3:]
            if (root / candidate).is_file():
                file = candidate
                break
    bases = [root.resolve().as_posix().rstrip("/") + "/"]
    for base in bases:
        if file.startswith(base):
            return file[len(base):]
    if file.startswith(("/", "../")) or ":" in file or file in (".", ".."):
        return None
    return file


def _taint_into(
    findings: Iterable[Finding], hits: Iterable[Hit], root: Path,
) -> tuple[str, str, str]:
    """Return (path, problem, scanner) for a trace ending at a call site."""
    targets = {
        (path, h.line)
        for h in hits if h.line > 0
        for path in (_trace_file(h.file, root), _trace_file(h.file, root, psalm=True))
        if path is not None
    }
    for finding in findings:
        scanner = (finding.scanner or "").strip().lower()
        if scanner not in {"codeql", "psalm"}:
            continue
        steps = finding.trace or []
        if len(steps) < 2 or not steps[0].file_path or not steps[0].line or steps[0].line < 1:
            continue
        source = steps[0]
        source_file = _trace_file(source.file_path, root, psalm=scanner == "psalm")
        if source_file is None:
            continue
        sink = steps[-1]
        sink_file = _trace_file(sink.file_path or "", root, psalm=scanner == "psalm")
        if sink_file is None or not sink.line or sink.line < 1:
            continue
        if (sink_file, sink.line) in targets:
            return (f"{scanner}: {source_file}:{source.line} -> {sink_file}:{sink.line} "
                    f"({finding.rule_id or finding.title})"), "", scanner
    # Findings alone cannot establish whether a scanner ran or covered this sink.
    return "", "no matching CodeQL/Psalm source-to-sink trace supplied; coverage unknown", ""


TAINT_SYSTEM = registry.step("taint")

_TAINT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "evidence", "why"],
    "properties": {
        "verdict": {"type": "string", "enum": ["yes", "no", "unknown"]},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}

_TAINT_CONTEXT_LINES = 25


def _taint_by_model(hits, root: Path, client, symbol: str) -> tuple[str, str, str]:
    """(verdict, quote, why) for whether untrusted input reaches the call."""
    if client is None:
        return "unknown", "", "модель не подключена"

    for hit in list(hits)[:3]:
        try:
            lines = (root / hit.file).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = max(0, hit.line - 1 - _TAINT_CONTEXT_LINES)
        end = min(len(lines), hit.line + _TAINT_CONTEXT_LINES)
        imports = [ln for ln in lines[:60]
                   if ln.strip().startswith(("use ", "import ", "from ", "require"))]
        material = "\n".join([
            f"Vulnerable symbol: {symbol}",
            f"=== CALL SITE: {hit.file}:{hit.line} ===", hit.text, "",
            *(["=== IMPORTS ===", *imports[:20], ""] if imports else []),
            f"=== {hit.file} lines {start + 1}-{end} ===",
            *(f"{n}: {lines[n - 1]}" for n in range(start + 1, end + 1)),
        ])
        try:
            answer = json.loads(
                client.complete(TAINT_SYSTEM, material, json_schema=_TAINT_SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - one failed call, not the run
            log.debug("taint question failed at %s: %s", hit, exc)
            continue

        quote = (answer.get("evidence") or "").strip()
        if not quote or quote not in material:
            log.debug("discarding ungrounded taint answer at %s", hit)
            continue
        return ((answer.get("verdict") or "unknown").strip().lower(),
                quote, (answer.get("why") or "")[:200])
    return "unknown", "", "модель не дала заземлённого ответа"


def assess(
    hits: list[Hit],
    root: Path | str,
    *,
    lsp: LSPService | None,
    routes: RouteIndex | None,
    codeql_findings: Iterable[Finding] = (),
    client=None,
) -> ReachResult:
    """Both halves, or `UNKNOWN`."""
    if not hits:
        return ReachResult(Reachability.UNKNOWN, detail="нет мест вызова для проверки")

    root = Path(root)
    used: list[str] = []
    missing: list[str] = []

    entry, entry_problem = "", "языковой сервер не подключён"
    if lsp is not None:
        for hit in hits[:5]:
            entry, entry_problem = _entrypoint_above(lsp, routes, hit, root)
            if entry:
                break
        _count(lsp, "sca_asked")
        if entry:
            _count(lsp, "sca_answered")
    if entry:
        used.append("lsp")
    else:
        missing.append(f"lsp ({entry_problem})")

    findings = list(codeql_findings)
    taint, taint_problem, taint_tool = _taint_into(findings, hits, root)
    if taint:
        used.append(taint_tool)
    else:
        missing.append(f"dataflow ({taint_problem})")

    if not taint:
        verdict, quote, why = _taint_by_model(hits, root, client, str(hits[0]) if hits else "")
        if verdict == "yes":
            taint = f"по чтению кода: {why} | цитата: {quote[:120]}"
            used.append("модель")
            taint_tool = "модель (чтение кода)"
        elif verdict == "no":
            return ReachResult(
                Reachability.NO_INPUT_PATH, entry, "", [*used, "модель"], missing,
                detail=(f"пользовательский ввод сюда не доходит: {why} | "
                        f"цитата: {quote[:120]}"))

    if entry and taint:
        return ReachResult(
            Reachability.REACHABLE, entry, taint, used, missing,
            detail=f"точка входа найдена языковым сервером, поток данных — {taint_tool}",
        )

    return ReachResult(
        Reachability.UNKNOWN, entry, taint, used, missing,
        detail="достижимость не установлена: " + "; ".join(missing),
    )
