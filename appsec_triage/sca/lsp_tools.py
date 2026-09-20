"""The language server as the model's instrument, for Go, PHP, JS and TS."""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from ..lsp.client import uri_to_path
from . import registries

log = logging.getLogger(__name__)

ECOSYSTEM_LANGUAGE = {"npm": "typescript", "composer": "php", "go": "go", "golang": "go"}


@dataclass(frozen=True, slots=True)
class Language:
    """How one language spells the things this module has to recognise.

    Everything language-specific lives here, in one row per language, rather
    than in a chain of checks where whichever language is written last becomes
    the silent default for every language nobody thought about.
    """

    suffixes: tuple[str, ...]
    #: name, class -> the pattern that finds the declaration
    declaration: Callable[[str, str], re.Pattern[str]]
    #: class -> the pattern that must also appear in the file, when the
    #: language declares a method inside a named container. None when a
    #: function stands on its own, as in Go and JavaScript.
    container: Callable[[str], re.Pattern[str]] | None = None


def _php_declaration(name: str, klass: str) -> re.Pattern[str]:
    return re.compile(rf"\bfunction\s+&?{re.escape(name)}\s*\(")


def _php_container(klass: str) -> re.Pattern[str]:
    return re.compile(rf"\b(?:class|trait|interface)\s+{re.escape(klass)}\b")


def _go_declaration(name: str, klass: str) -> re.Pattern[str]:
    receiver = rf"\([^)]*\*?{re.escape(klass)}\)\s*" if klass else r"(?:\([^)]*\)\s*)?"
    return re.compile(rf"\bfunc\s+{receiver}{re.escape(name)}\s*[\[(]")


def _ts_declaration(name: str, klass: str) -> re.Pattern[str]:
    """A declaration in a .d.ts, a function, a method, or an export."""
    n = re.escape(name)
    return re.compile(
        rf"(?:\bfunction\s+{n}\s*[<(]|\bexport\s+(?:declare\s+)?(?:const|let|var|function)\s+{n}\b"
        rf"|^\s*(?:static\s+|async\s+|public\s+|readonly\s+)*{n}\s*[<(:]|\bexports\.{n}\s*=|\b{n}\s*:\s*function\b)",
        re.MULTILINE)


LANGUAGES = {
    "php": Language((".php",), _php_declaration, _php_container),
    "go": Language((".go",), _go_declaration),
    "typescript": Language((".d.ts", ".ts", ".js", ".mjs", ".cjs"), _ts_declaration),
}
_SKIP = {"node_modules", "vendor", ".git", "dist", "build"}
_MAX_DECLARATIONS = 3
_MAX_SCANNED = 3000
_MAX_BYTES = 400_000
_MAX_LISTED = 8
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")


@dataclass(slots=True)
class Usages:
    """What `usages` established for one function."""

    label: str
    answered: bool = False
    declarations: list[str] = field(default_factory=list)
    project_hits: list[str] = field(default_factory=list)
    problem: str = ""


class LSPTools:
    """One dependency's view of the project through its language server."""

    def __init__(self, lsp, root: Path | str, ecosystem: str, package: str, version: str = "") -> None:
        self.lsp = lsp
        self.root = Path(root)
        self.ecosystem = (ecosystem or "").strip().lower()
        self.language = ECOSYSTEM_LANGUAGE.get(self.ecosystem, "")
        self.package = package
        self.package_dir = registries.locate(self.root, self.ecosystem, package, version) if self.language else None
        self._client = None

    def client(self):
        if not self.language or self.lsp is None:
            return None
        if self._client is None:
            self._client = self.lsp._client(self.language)
        return self._client

    @property
    def available(self) -> bool:
        return self.client() is not None

    def unavailable_reason(self) -> str:
        if not self.language:
            return f"для экосистемы {self.ecosystem or '?'} языковой сервер не предлагается"
        if self.lsp is None:
            return "языковые серверы в этом прогоне выключены"
        return f"языковой сервер {self.language} не запустился"

    # ---- helpers -----------------------------------------------------------

    def _language_id(self) -> str:
        spec = self.lsp.cfg.servers.get(self.language) or {}
        return spec.get("language_id", self.language)

    def _path_map(self) -> dict[str, str]:
        return self.lsp._path_map_for(self.language)

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(path)

    def _in_project(self, path: Path) -> bool:
        rel = self._relative(path)
        return not PurePosixPath(rel).is_absolute() and not (_SKIP & set(PurePosixPath(rel).parts))

    def _raw_request(self, client, method: str, path: Path, line: int, character: int):
        """The reply as sent: None when the server failed, [] when it found nothing."""
        from ..lsp.client import path_to_uri

        params = {"textDocument": {"uri": path_to_uri(path, self._path_map())},
                  "position": {"line": max(0, line - 1), "character": max(0, character)}}
        if method == "textDocument/references":
            params["context"] = {"includeDeclaration": False}
        return client._request(method, params)

    def _locations(self, reply) -> list[tuple[Path, int]]:
        if reply is None:
            return []
        items = reply if isinstance(reply, list) else [reply]
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            uri = item.get("uri") or item.get("targetUri") or ""
            rng = item.get("range") or item.get("targetSelectionRange") or {}
            if uri:
                out.append((uri_to_path(uri, self._path_map()), int(((rng.get("start") or {}).get("line") or 0)) + 1))
        return out

    def _line(self, path: Path, line: int) -> str:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return lines[line - 1].strip()[:140] if 0 < line <= len(lines) else ""

    def _where(self, path: Path) -> str:
        if self.package_dir is not None:
            try:
                path.resolve().relative_to(self.package_dir.resolve())
                return f"пакет {self.package}"
            except ValueError:
                pass
        if self._in_project(path):
            return "код проекта"
        return "другая зависимость"

    # ---- the three questions ----------------------------------------------

    def usages(self, klass: str, name: str) -> Usages:
        label = f"{klass}::{name}" if klass else name
        result = Usages(label)
        client = self.client()
        if client is None:
            result.problem = self.unavailable_reason()
            return result
        if self.package_dir is None:
            result.problem = (f"пакет {self.package} не установлен в дереве проекта — объявление "
                              "искать негде, сервер не спрашивался")
            return result
        short = klass.rsplit("\\", 1)[-1].rsplit(".", 1)[-1] if klass else ""
        spoken = LANGUAGES[self.language]
        pattern = spoken.declaration(name, short)
        declarations: list[tuple[Path, int, int]] = []
        scanned = 0
        for path in sorted(self.package_dir.rglob("*")):
            if len(declarations) >= _MAX_DECLARATIONS or scanned >= _MAX_SCANNED:
                break
            if not path.is_file() or not path.name.endswith(spoken.suffixes):
                continue
            if {"test", "tests", "__tests__"} & {p.lower() for p in path.parts}:
                continue
            scanned += 1
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if short and spoken.container and not spoken.container(short).search(text):
                continue
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                column = match.group(0).find(name) + (match.start() - text.rfind("\n", 0, match.start()) - 1)
                declarations.append((path, line, column))
                if len(declarations) >= _MAX_DECLARATIONS:
                    break
        if not declarations:
            result.problem = f"объявление {label} в установленном пакете не найдено"
            return result
        hits: list[str] = []
        for path, line, column in declarations:
            result.declarations.append(f"{self._relative(path)}:{line}")
            client.open_document(path, self._language_id())
            reply = self._raw_request(client, "textDocument/references", path, line, column)
            if reply is None:
                continue
            result.answered = True
            for ref_path, ref_line in self._locations(reply):
                if self._in_project(ref_path):
                    hit = f"{self._relative(ref_path)}:{ref_line} {self._line(ref_path, ref_line)}"
                    if hit not in hits:
                        hits.append(hit)
        result.project_hits = hits
        if not result.answered:
            result.problem = "сервер не ответил на references"
        elif not hits and client.supports("workspaceSymbolProvider") and not getattr(client, "index_ready", True):
            result.answered = False
            result.problem = ("индекс сервера не подтвердился на старте — пустой ответ references "
                              "не считается «0 вызовов»")
        return result

    def definition(self, file: str, line: int, name: str) -> str:
        client = self.client()
        if client is None:
            return self.unavailable_reason()
        path = self.root / file
        text = self._line(path, line)
        if not text:
            return f"строки {file}:{line} нет"
        column = self._column(path, line, name)
        if column < 0:
            return f"имени {name!r} в строке {file}:{line} нет: {text}"
        client.open_document(path, self._language_id())
        reply = self._raw_request(client, "textDocument/definition", path, line, column)
        if reply is None:
            return f"сервер не ответил на definition для {name} в {file}:{line}"
        places = self._locations(reply)
        if not places:
            return f"сервер не нашёл определения {name} в {file}:{line}"
        return "\n".join(f"- {name} → {self._relative(p)}:{ln} ({self._where(p)}): {self._line(p, ln)}"
                         for p, ln in places[:_MAX_LISTED])

    def callers(self, file: str, line: int) -> str:
        client = self.client()
        if client is None:
            return self.unavailable_reason()
        path = self.root / file
        if not self._line(path, line):
            return f"строки {file}:{line} нет"
        client.open_document(path, self._language_id())
        calls = client.incoming_calls(path, line, self._column(path, line, ""))
        if not calls:
            return f"сервер не нашёл вызывающих для {file}:{line}"
        out = []
        for call in calls[:_MAX_LISTED]:
            caller = uri_to_path(call["uri"], self._path_map())
            start = int(((call.get("range") or {}).get("start") or {}).get("line") or 0) + 1
            out.append(f"- {call.get('name') or '?'} в {self._relative(caller)}:{start} ({self._where(caller)})")
        return "\n".join(out)

    def _column(self, path: Path, line: int, name: str) -> int:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace").splitlines()[line - 1]
        except (OSError, IndexError):
            return -1
        if not name:
            return len(raw) - len(raw.lstrip())
        match = re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", raw)
        return match.start() if match else -1


def valid_name(name: str) -> bool:
    return bool(name) and bool(_IDENTIFIER.match(name))
