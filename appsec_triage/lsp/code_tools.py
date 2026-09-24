"""The language servers as the model's way of looking at code, for every language."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path, PurePosixPath

from ..testpaths import is_test
from .client import path_to_uri, uri_to_path

log = logging.getLogger(__name__)

_KINDS = {1: "file", 2: "module", 3: "namespace", 4: "package", 5: "class", 6: "method",
          7: "property", 8: "field", 9: "constructor", 10: "enum", 11: "interface",
          12: "function", 13: "variable", 14: "constant", 22: "enum member",
          23: "struct", 24: "event", 25: "operator", 26: "type parameter"}
_SKIP = {"node_modules", "vendor", ".git", "dist", "build", "__pycache__", ".venv", "venv", "target"}
_MAX_LISTED = 20
_MAX_SCAN = 20000
_READ_LINES = 80
_SYMBOL_LINES = 160
_LINE_CHARS = 300
_MAX_FILE_BYTES = 1_000_000
# Never shown to the model, whatever it asks for.
_SECRET_NAMES = re.compile(r"^(?:\.env(?:\..*)?|id_rsa.*|id_ed25519.*|credentials.*|.*\.(?:pem|key|p12|pfx|keystore))$",
                           re.IGNORECASE)
_SEARCHABLE = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte", ".php", ".py", ".go",
               ".java", ".kt", ".cs", ".rb", ".rs", ".json", ".yaml", ".yml", ".toml", ".xml", ".ini",
               ".neon", ".twig", ".html", ".conf", ".properties", ".gradle", ".sh"}
_SEARCHABLE_NAMES = {"dockerfile", "makefile", ".gitlab-ci.yml", "go.mod", "composer.json", "package.json"}


def _clip(text: str) -> str:
    """One line as the model sees it: a minified or base64 line is cut, not dropped."""
    if len(text) <= _LINE_CHARS:
        return text
    return f"{text[:_LINE_CHARS]} …[строка обрезана, ещё {len(text) - _LINE_CHARS} симв.]"


def _installed(parts) -> str | None:
    """The package an installed-tree path belongs to ("" if unnamed); None otherwise."""
    parts = list(parts)
    for index, part in enumerate(parts[:-1]):
        if part in ("node_modules", "vendor"):
            rest = parts[index + 1:]
            two = part == "vendor" or rest[0].startswith("@")
            return "/".join(rest[:2]) if two and len(rest) > 2 else rest[0]
    return None


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
        text = str(file or "").replace("\\", "/")
        # The material shows paths as the container mounts them (`/src/server.ts`) or
        # as absolute paths under the root; both name a file of this tree.
        root = self.root.as_posix().rstrip("/")
        if root and text.startswith(root + "/"):
            text = text[len(root) + 1:]
        elif text.startswith("/src/"):
            text = text[len("/src/"):]
        rel = PurePosixPath(text)
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
        if is_test(rel):
            return "тестовый код"
        return "код проекта"

    def provenance(self, file: str) -> str:
        """Whose code this is — said with every read, so no line is taken for another's."""
        rel = PurePosixPath(str(file or "").replace("\\", "/"))
        package = _installed(rel.parts)
        if package is not None:
            return (f"[код зависимости{f' — пакет {package}' if package else ''}: доказывает только то, "
                    "что делает сама библиотека, не то, что делает этот проект]")
        if is_test(rel.as_posix()):
            return "[тестовый код — не продакшен: что здесь вызывается, приложение не вызывает]"
        return "[код проекта]"

    def _readable(self, file: str) -> tuple[Path | None, str]:
        path = self.resolve(file)
        if path is None:
            return None, f"файла {file!r} в репозитории нет"
        if _SECRET_NAMES.match(path.name):
            return None, f"{file}: файл с секретами не показывается"
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                return None, f"{file}: файл больше {_MAX_FILE_BYTES // 1000} КБ — читайте по символам (lsp_read_symbol)"
        except OSError:
            return None, f"{file}: не читается"
        return path, ""

    def read(self, file: str, line: int = 1, count: int = _READ_LINES) -> str:
        """`count` lines of any file in the tree, installed packages included."""
        from ..redact import redact_secrets

        path, problem = self._readable(file)
        if path is None:
            return problem
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        start = max(1, int(line or 1))
        if start > len(lines):
            return f"{self.provenance(file)}\n{file}: в файле {len(lines)} строк, строки {start} нет"
        chunk = lines[start - 1:start - 1 + count]
        body = "\n".join(f"{start + i}: {_clip(text)}" for i, text in enumerate(chunk))
        tail = (f"\n…[ещё {len(lines) - (start - 1 + len(chunk))} строк — read_file с line={start + len(chunk)}]"
                if start - 1 + len(chunk) < len(lines) else "")
        return f"{self.provenance(file)}\n{redact_secrets(body)[0] or ''}{tail}"

    def read_symbol(self, file: str, name: str) -> str:
        """The whole declaration, as the server bounds it — not a fixed window from its first line."""
        start, end, problem = self.symbol_range(file, name)
        if start is None:
            return problem
        count = max(1, min((end or start) - start + 1, _SYMBOL_LINES))
        return self.read(file, start, count)

    def search(self, pattern: str) -> str:
        """A literal substring across the project's own files, code and configuration alike."""
        pattern = str(pattern or "")
        if not pattern.strip() or len(pattern) > 200 or "\n" in pattern:
            return "Not run: give one literal substring of at most 200 characters."
        rows: list[str] = []
        tests = 0
        per_file: dict[str, int] = {}
        for parent, dirnames, filenames in os.walk(self.root):
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP and not d.startswith("."))
            for name in sorted(filenames):
                path = Path(parent) / name
                if (path.suffix.lower() not in _SEARCHABLE and name.lower() not in _SEARCHABLE_NAMES
                        and not name.lower().startswith("dockerfile")) or _SECRET_NAMES.match(name):
                    continue
                try:
                    if path.stat().st_size > _MAX_FILE_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if pattern not in text:
                    continue
                rel = self.relative(path)
                if is_test(rel):
                    tests += text.count(pattern)
                    continue
                for number, line in enumerate(text.splitlines(), 1):
                    if pattern in line and per_file.get(rel, 0) < 3:
                        per_file[rel] = per_file.get(rel, 0) + 1
                        rows.append(f"- {rel}:{number}: {_clip(line.strip())}")
                if len(rows) >= _MAX_LISTED:
                    break
            if len(rows) >= _MAX_LISTED:
                break
        skipped = (f"\nв тестовых и docker-compose файлах ещё {tests} совпадений — не продакшен, пропущены"
                   if tests else "")
        if not rows:
            return f"«{pattern}»: в коде и конфигурации проекта не найдено{skipped}"
        return "\n".join(rows[:_MAX_LISTED]) + skipped

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
        skipped_tests = 0
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
                    if self.where(path) == "тестовый код":
                        skipped_tests += 1
                    if self.where(path) != "код проекта":
                        continue
                    kind = _KINDS.get(item.get("kind"), "symbol")
                    container = f" в {item['containerName']}" if item.get("containerName") else ""
                    lines.append(f"- {kind} {item.get('name')}{container} — {self.relative(path)}:{line}")
                    if len(lines) >= _MAX_LISTED:
                        break
        tests = f"\nв тестовом коде ещё {skipped_tests} — не продакшен, пропущены" if skipped_tests else ""
        if not lines:
            tail = f" ({'; '.join(problems)})" if problems else ""
            return f"LSP: в коде проекта нет объявлений, совпадающих с {query!r}{tail}{tests}"
        return "\n".join(lines[:_MAX_LISTED]) + tests

    def outline(self, file: str) -> str:
        path, language, client, problem = self._for_file(file)
        if problem:
            return problem
        return f"{self.provenance(file)}\n{self._outline(path, language, client, file)}"

    def _outline(self, path: Path, language: str, client, file: str) -> str:
        reply = client._request("textDocument/documentSymbol",
                                {"textDocument": {"uri": path_to_uri(path, self._path_map(language))}})
        if reply is None:
            return f"сервер {language} не ответил на documentSymbol для {file}"
        rows = [f"- {kind} {name} — строки {start}-{end}" for kind, name, start, end in _flatten(reply)]
        return "\n".join(rows[:60]) or f"в {file} сервер не нашёл объявлений"

    def symbol_range(self, file: str, name: str) -> tuple[int | None, int | None, str]:
        """First and last line of the named declaration in `file`."""
        path, language, client, problem = self._for_file(file)
        if problem:
            return None, None, problem
        reply = client._request("textDocument/documentSymbol",
                                {"textDocument": {"uri": path_to_uri(path, self._path_map(language))}})
        if reply is None:
            return None, None, f"сервер {language} не ответил на documentSymbol для {file}"
        wanted = str(name or "").split("::")[-1].split(".")[-1].strip()
        for _, symbol, start, end in _flatten(reply):
            if symbol.split(".")[-1] == wanted or symbol == name:
                return start, end, ""
        return None, None, f"объявления {name!r} в {file} нет"

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
        tests = 0
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
                if is_test(self.relative(path)):
                    tests += sum(1 for text in lines if pattern.search(text))
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
        skipped = (f"\nв тестовых файлах ещё {tests} упоминаний — не продакшен, пропущены" if tests else "")
        if not rows:
            return (f"LSP: {short!r} не встречается ни в одном из {scanned} файлов кода проекта "
                    f"({', '.join(self.available())}){skipped}")
        tail = (f"\n{unresolved} мест не разрешено: без установленных зависимостей сервер не видит их "
                "объявлений — это не значит, что вызова нет") if unresolved else ""
        return "\n".join(rows) + tail + skipped

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
        located = self._locations(reply, language)
        places = [(p, ln) for p, ln in located if self.where(p) == "код проекта"]
        tests = sum(1 for p, _ in located if self.where(p) == "тестовый код")
        skipped = f"\nв тестовом коде ещё {tests} — не продакшен, пропущены" if tests else ""
        if not places:
            return f"LSP: ссылок на {name} из кода проекта нет (сервер ответил){skipped}"
        return "\n".join(f"- {self.relative(p)}:{ln}: {self._line(p, ln)}"
                         for p, ln in places[:_MAX_LISTED]) + skipped

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


def reading_tools(function_tool) -> list[dict]:
    """Plain reading and search, for a conversation that has no evidence reader of its own."""
    return [
        function_tool("read_file",
                      "Read 80 lines of any file in the tree from a 1-based line — the project's code and "
                      "configuration, or an installed package under node_modules/ or vendor/. Ask again with a "
                      "later line to read on.",
                      {"path": {"type": "string", "description": "Repository-relative path."},
                       "line": {"type": "integer", "description": "1-based start line."}},
                      ["path", "line"]),
        function_tool("search_code",
                      "Literal substring search across the project's own code and configuration (tests, "
                      "docker-compose and installed packages left out): a setting, a string, a call.",
                      {"pattern": {"type": "string", "description": "Plain substring, not a regular expression."}},
                      ["pattern"]),
    ]


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
