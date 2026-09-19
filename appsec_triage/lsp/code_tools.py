"""The language servers as the model's way of looking at code, for every language."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath

from .client import path_to_uri, uri_to_path

log = logging.getLogger(__name__)

_KINDS = {1: "file", 2: "module", 3: "namespace", 4: "package", 5: "class", 6: "method",
          7: "property", 8: "field", 9: "constructor", 10: "enum", 11: "interface",
          12: "function", 13: "variable", 14: "constant", 22: "enum member",
          23: "struct", 24: "event", 25: "operator", 26: "type parameter"}
_SKIP = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__", ".venv", "venv", "target"}
_MAX_LISTED = 20
_MAX_SCAN = 20000


class CodeTools:
    """Entity questions for one source root, answered by its language servers."""

    def __init__(self, lsp, root: Path | str) -> None:
        self.lsp = lsp
        self.root = Path(root)
        self._languages: list[str] | None = None
        self._opened: set[str] = set()

    # ---- which servers this project needs ---------------------------------

    def languages(self) -> list[str]:
        """Configured languages that have files in this project, most files first."""
        if self._languages is None:
            counts: dict[str, int] = {}
            seen = 0
            for parent, dirnames, filenames in os.walk(self.root):
                dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
                for name in filenames:
                    seen += 1
                    language = self.lsp.cfg.language_for(name)
                    if language:
                        counts[language] = counts.get(language, 0) + 1
                if seen > _MAX_SCAN:
                    break
            self._languages = sorted(counts, key=lambda lang: -counts[lang])
        return self._languages

    def available(self) -> list[str]:
        return [lang for lang in self.languages() if self._client(lang) is not None]

    def _client(self, language: str):
        return self.lsp._client(language) if language else None

    def _language_id(self, language: str) -> str:
        return (self.lsp.cfg.servers.get(language) or {}).get("language_id", language)

    def _path_map(self, language: str) -> dict[str, str]:
        return self.lsp._path_map_for(language)

    def _open(self, client, language: str, path: Path) -> None:
        key = f"{language}:{path}"
        if key not in self._opened:
            client.open_document(path, self._language_id(language))
            self._opened.add(key)

    def _first_file(self, language: str) -> Path | None:
        for parent, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
            for name in sorted(filenames):
                if self.lsp.cfg.language_for(name) == language:
                    return Path(parent) / name
        return None

    # ---- paths --------------------------------------------------------------

    def resolve(self, file: str) -> Path | None:
        """A repository-relative path inside the root, or None."""
        rel = PurePosixPath(str(file or "").replace("\\", "/"))
        if not str(rel) or rel.is_absolute() or ".." in rel.parts:
            return None
        path = self.root / rel
        return path if path.is_file() else None

    def relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return str(path)

    def where(self, path: Path) -> str:
        rel = self.relative(path)
        parts = set(PurePosixPath(rel).parts)
        if PurePosixPath(rel).is_absolute():
            return "вне проекта (стандартная библиотека или зависимость)"
        if parts & {"node_modules", "vendor"}:
            return "зависимость"
        return "код проекта"

    def _line(self, path: Path, line: int) -> str:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return ""
        return lines[line - 1].strip()[:120] if 0 < line <= len(lines) else ""

    def _column(self, path: Path, line: int, name: str) -> int:
        try:
            raw = path.read_text(encoding="utf-8", errors="replace").splitlines()[line - 1]
        except (OSError, IndexError):
            return -1
        if not name:
            return len(raw) - len(raw.lstrip())
        match = re.search(rf"(?<![\w$]){re.escape(name)}(?![\w$])", raw)
        return match.start() if match else -1

    def _locations(self, reply, language: str) -> list[tuple[Path, int]]:
        items = reply if isinstance(reply, list) else ([reply] if reply else [])
        out = []
        for item in items:
            if not isinstance(item, dict):
                continue
            uri = item.get("uri") or item.get("targetUri") or ((item.get("location") or {}).get("uri")) or ""
            rng = (item.get("range") or item.get("targetSelectionRange")
                   or (item.get("location") or {}).get("range") or {})
            if uri:
                out.append((uri_to_path(uri, self._path_map(language)),
                            int(((rng.get("start") or {}).get("line") or 0)) + 1))
        return out

    def _request(self, client, language: str, method: str, path: Path, line: int, character: int):
        params = {"textDocument": {"uri": path_to_uri(path, self._path_map(language))},
                  "position": {"line": max(0, line - 1), "character": max(0, character)}}
        if method == "textDocument/references":
            params["context"] = {"includeDeclaration": False}
        return client._request(method, params)

    def _for_file(self, file: str):
        path = self.resolve(file)
        if path is None:
            return None, None, None, f"файла {file!r} в репозитории нет"
        language = self.lsp.cfg.language_for(path.name)
        if not language:
            return None, None, None, f"для {file} языковой сервер не настроен — используйте read_file"
        client = self._client(language)
        if client is None:
            return None, None, None, f"языковой сервер {language} не запустился"
        self._open(client, language, path)
        return path, language, client, ""

    # ---- the questions ------------------------------------------------------

    def find_symbol(self, query: str) -> str:
        """Declared entities whose name matches, across every language of the project."""
        query = str(query or "").strip()
        if not query or len(query) > 120:
            return "Not run: give a name or part of a name."
        lines: list[str] = []
        problems: list[str] = []
        for language in self.languages():
            client = self._client(language)
            if client is None:
                problems.append(f"{language}: сервер не запустился")
                continue
            if first := self._first_file(language):
                self._open(client, language, first)
            reply = client._request("workspace/symbol", {"query": query})
            if reply is None:
                problems.append(f"{language}: сервер не ответил")
                continue
            for item in reply or []:
                for path, line in self._locations([item], language):
                    if self.where(path) != "код проекта":
                        continue
                    kind = _KINDS.get(item.get("kind"), "symbol")
                    container = f" в {item['containerName']}" if item.get("containerName") else ""
                    lines.append(f"- {kind} {item.get('name')}{container} — {self.relative(path)}:{line}")
                    if len(lines) >= _MAX_LISTED:
                        break
        if not lines:
            tail = f" ({'; '.join(problems)})" if problems else ""
            return f"LSP: в коде проекта нет объявлений, совпадающих с {query!r}{tail}"
        return "\n".join(lines[:_MAX_LISTED])

    def outline(self, file: str) -> str:
        path, language, client, problem = self._for_file(file)
        if problem:
            return problem
        reply = client._request("textDocument/documentSymbol",
                                {"textDocument": {"uri": path_to_uri(path, self._path_map(language))}})
        if reply is None:
            return f"сервер {language} не ответил на documentSymbol для {file}"
        rows = [f"- {kind} {name} — строки {start}-{end}" for kind, name, start, end in _flatten(reply)]
        return "\n".join(rows[:60]) or f"в {file} сервер не нашёл объявлений"

    def symbol_start(self, file: str, name: str) -> tuple[int | None, str]:
        """The first line of the named declaration in `file`, for `read_file` to show."""
        path, language, client, problem = self._for_file(file)
        if problem:
            return None, problem
        reply = client._request("textDocument/documentSymbol",
                                {"textDocument": {"uri": path_to_uri(path, self._path_map(language))}})
        if reply is None:
            return None, f"сервер {language} не ответил на documentSymbol для {file}"
        wanted = str(name or "").split("::")[-1].split(".")[-1].strip()
        for _, symbol, start, _ in _flatten(reply):
            if symbol.split(".")[-1] == wanted or symbol == name:
                return start, ""
        return None, f"объявления {name!r} в {file} нет"

    def find_usages(self, name: str) -> str:
        """Where the project uses a name, each place resolved by the language server."""
        wanted = str(name or "").strip()
        short = re.split(r"::|\\|\.", wanted)[-1].strip().rstrip("()")
        if not short or not re.match(r"^[A-Za-z_$][\w$]*$", short):
            return "Not run: give a function, method or class name."
        pattern = re.compile(rf"(?<![\w$]){re.escape(short)}(?![\w$])")
        rows: list[str] = []
        unresolved = 0
        scanned = 0
        for parent, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP and not d.startswith(".")]
            for filename in sorted(filenames):
                language = self.lsp.cfg.language_for(filename)
                if not language or language not in self.available():
                    continue
                path = Path(parent) / filename
                try:
                    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
                except OSError:
                    continue
                scanned += 1
                for number, text in enumerate(lines, 1):
                    match = pattern.search(text)
                    if not match or text.lstrip().startswith(("//", "#", "*", "/*")):
                        continue
                    client = self._client(language)
                    self._open(client, language, path)
                    reply = self._request(client, language, "textDocument/definition", path, number, match.start())
                    places = self._locations(reply, language) if reply is not None else []
                    rel = self.relative(path)
                    if places:
                        target, target_line = places[0]
                        rows.append(f"- {rel}:{number}: {text.strip()[:90]} → {self.relative(target)}:{target_line} "
                                    f"({self.where(target)})")
                    else:
                        unresolved += 1
                        rows.append(f"- {rel}:{number}: {text.strip()[:90]} → не разрешено сервером "
                                    "(пакет не установлен или имя не является вызовом)")
                    if len(rows) >= _MAX_LISTED:
                        break
                if len(rows) >= _MAX_LISTED:
                    break
            if len(rows) >= _MAX_LISTED:
                break
        if not rows:
            return (f"LSP: {short!r} не встречается ни в одном из {scanned} файлов кода проекта "
                    f"({', '.join(self.available())})")
        tail = (f"\n{unresolved} мест не разрешено: без установленных зависимостей сервер не видит их "
                "объявлений — это не значит, что вызова нет") if unresolved else ""
        return "\n".join(rows) + tail

    def definition(self, file: str, line: int, name: str) -> str:
        path, language, client, problem = self._for_file(file)
        if problem:
            return problem
        column = self._column(path, line, name)
        if column < 0:
            return f"имени {name!r} в строке {file}:{line} нет"
        reply = self._request(client, language, "textDocument/definition", path, line, column)
        places = self._locations(reply, language) if reply is not None else []
        if reply is None:
            return f"сервер {language} не ответил на definition"
        if not places:
            return f"сервер не нашёл определения {name} в {file}:{line}"
        return "\n".join(f"- {name} → {self.relative(p)}:{ln} ({self.where(p)}): {self._line(p, ln)}"
                         for p, ln in places[:_MAX_LISTED])

    def references(self, file: str, line: int, name: str) -> str:
        path, language, client, problem = self._for_file(file)
        if problem:
            return problem
        column = self._column(path, line, name)
        if column < 0:
            return f"имени {name!r} в строке {file}:{line} нет"
        reply = self._request(client, language, "textDocument/references", path, line, column)
        if reply is None:
            return f"сервер {language} не ответил на references"
        places = [(p, ln) for p, ln in self._locations(reply, language) if self.where(p) == "код проекта"]
        if not places:
            return f"LSP: ссылок на {name} из кода проекта нет (сервер ответил)"
        return "\n".join(f"- {self.relative(p)}:{ln}: {self._line(p, ln)}" for p, ln in places[:_MAX_LISTED])

    def callers(self, file: str, line: int) -> str:
        path, language, client, problem = self._for_file(file)
        if problem:
            return problem
        calls = client.incoming_calls(path, line, self._column(path, line, ""))
        if not calls:
            return f"сервер не нашёл вызывающих для {file}:{line}"
        out = []
        for call in calls[:_MAX_LISTED]:
            caller = uri_to_path(call["uri"], self._path_map(language))
            start = int(((call.get("range") or {}).get("start") or {}).get("line") or 0) + 1
            out.append(f"- {call.get('name') or '?'} в {self.relative(caller)}:{start} ({self.where(caller)})")
        return "\n".join(out)


def _flatten(reply, prefix: str = ""):
    """(kind, qualified name, start line, end line) for DocumentSymbol trees and SymbolInformation lists."""
    for item in reply or []:
        if not isinstance(item, dict):
            continue
        rng = item.get("range") or (item.get("location") or {}).get("range") or {}
        start = int(((rng.get("start") or {}).get("line") or 0)) + 1
        end = int(((rng.get("end") or {}).get("line") or 0)) + 1
        name = f"{prefix}{item.get('name')}"
        yield _KINDS.get(item.get("kind"), "symbol"), name, start, end
        if item.get("children"):
            yield from _flatten(item["children"], f"{name}.")


def function_tools(function_tool) -> list[dict]:
    """Tool definitions, in the caller's `function_tool` shape."""
    file = {"type": "string", "description": "Repository-relative path."}
    line = {"type": "integer", "description": "1-based line."}
    return [
        function_tool("lsp_find_symbol",
                      "Language server: find declared functions, methods, classes, types by name across the "
                      "whole project, in every language (e.g. main, a handler, the function that starts the "
                      "server). Returns file:line of each declaration.",
                      {"query": {"type": "string", "description": "Name or part of a name."}}, ["query"]),
        function_tool("lsp_find_usages",
                      "Language server: every place in project code that uses a name — a library function, "
                      "a class, a method (e.g. Yaml::parse, template, ListenAndServe) — each resolved by the "
                      "server to where it really points: the dependency, the project's own code, or unresolved.",
                      {"name": {"type": "string", "description": "Function, method or class name."}}, ["name"]),
        function_tool("lsp_outline",
                      "Language server: the functions, classes and methods declared in one file, with line ranges.",
                      {"file": file}, ["file"]),
        function_tool("lsp_read_symbol",
                      "Language server: read the source of one declared function, method or class by name.",
                      {"file": file, "name": {"type": "string", "description": "Declaration name."}},
                      ["file", "name"]),
        function_tool("lsp_definition",
                      "Language server: where the name used at this file and line is defined — project code, "
                      "a dependency, or the standard library.",
                      {"file": file, "line": line, "name": {"type": "string", "description": "Identifier on that line."}},
                      ["file", "line", "name"]),
        function_tool("lsp_references",
                      "Language server: every place in project code that uses the name at this file and line.",
                      {"file": file, "line": line, "name": {"type": "string", "description": "Identifier on that line."}},
                      ["file", "line", "name"]),
        function_tool("lsp_callers",
                      "Language server: who calls the function containing this file and line.",
                      {"file": file, "line": line}, ["file", "line"]),
    ]


def as_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None
