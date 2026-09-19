"""Where a function is declared, and whether anything outside can call it."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

PHP = "php"
JS = "js"
PYTHON = "python"
GO = "go"

_BY_SUFFIX = {
    ".php": PHP,
    ".js": JS, ".jsx": JS, ".mjs": JS, ".cjs": JS, ".ts": JS, ".tsx": JS, ".mts": JS,
    ".py": PYTHON, ".pyi": PYTHON,
    ".go": GO,
}


def language_of(path: str) -> str | None:
    return _BY_SUFFIX.get(Path(path).suffix.lower())


@dataclass(slots=True, frozen=True)
class Declaration:
    name: str
    owner: str = ""
    visibility: str = "public"
    line: int = 1
    offset: int = 0

    @property
    def public(self) -> bool:
        return self.visibility == "public"

    def __str__(self) -> str:
        return f"{self.owner}::{self.name}" if self.owner else self.name


_PHP_DECL = re.compile(
    r"^[ \t]*(?:(public|protected|private)\s+)?(?:static\s+|final\s+|abstract\s+)*"
    r"function\s+&?\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(", re.MULTILINE)
_PHP_OWNER = re.compile(
    r"^[ \t]*(?:final\s+|abstract\s+)*(?:class|trait|interface)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)

_JS_DECL = re.compile(
    r"^[ \t]*(?P<exp>export\s+(?:default\s+)?)?"
    r"(?:(?P<vis>public|private|protected)\s+)?"
    r"(?:(?:async|static|get|set)\s+)*"
    r"(?:function\s*\*?\s*(?P<fn>[A-Za-z_$][\w$]*)"
    r"|(?:const|let|var)\s+(?P<var>[A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?"
    r"(?:function\b|\([^)]*\)\s*=>|[A-Za-z_$][\w$]*\s*=>)"
    r"|(?P<meth>[A-Za-z_$#][\w$]*)\s*\([^)]*\)\s*\{)", re.MULTILINE)
_JS_OWNER = re.compile(r"^[ \t]*(?:export\s+(?:default\s+)?)?class\s+([A-Za-z_$][\w$]*)", re.MULTILINE)
_JS_KEYWORD = {"if", "for", "while", "switch", "catch", "return", "do", "else", "function"}

_PY_DECL = re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<fn>[A-Za-z_]\w*)\s*\(", re.MULTILINE)
_PY_OWNER = re.compile(r"^(?P<indent>[ \t]*)class\s+([A-Za-z_]\w*)", re.MULTILINE)

_GO_DECL = re.compile(
    r"^func\s*(?:\(\s*\w+\s+\*?(?P<recv>[A-Za-z_]\w*)\s*\)\s*)?(?P<fn>[A-Za-z_]\w*)\s*\(", re.MULTILINE)


def _php(text: str) -> list[Declaration]:
    owners = [(m.start(), m.group(1)) for m in _PHP_OWNER.finditer(text)]
    out = []
    for match in _PHP_DECL.finditer(text):
        owner = ""
        for start, name in owners:
            if start < match.start():
                owner = name
        out.append(Declaration(match.group(2), owner, match.group(1) or "public",
                               text.count("\n", 0, match.start()) + 1, match.start()))
    return out


def _js(text: str) -> list[Declaration]:
    owners = [(m.start(), m.group(1)) for m in _JS_OWNER.finditer(text)]
    exported = set(re.findall(r"(?:module\.)?exports(?:\.(\w+))?\s*=", text))
    exported |= set(re.findall(r"export\s*\{([^}]*)\}", text))
    exported = {part.strip().split(" as ")[0] for chunk in exported for part in chunk.split(",")}

    out = []
    for match in _JS_DECL.finditer(text):
        name = match.group("fn") or match.group("var") or match.group("meth")
        if not name or name in _JS_KEYWORD:
            continue
        owner = ""
        for start, cls in owners:
            if start < match.start():
                owner = cls
        declared = match.group("vis")
        if name.startswith("#"):
            visibility = "private"
        elif declared:
            visibility = declared
        elif match.group("exp") or name in exported:
            visibility = "public"
        elif owner:
            visibility = "public" if not name.startswith("_") else "private"
        else:
            visibility = "private"
        out.append(Declaration(name.lstrip("#"), owner, visibility,
                               text.count("\n", 0, match.start()) + 1, match.start()))
    return out


def _python(text: str) -> list[Declaration]:
    exported = set()
    for block in re.findall(r"__all__\s*=\s*[\[(](.*?)[\])]", text, re.DOTALL):
        exported |= {m.group(1) for m in re.finditer(r"[\"']([^\"']+)[\"']", block)}

    owners = [(m.start(), len(m.group("indent")), m.group(2)) for m in _PY_OWNER.finditer(text)]
    out = []
    for match in _PY_DECL.finditer(text):
        indent = len(match.group("indent"))
        owner = ""
        for start, class_indent, name in owners:
            if start < match.start() and class_indent < indent:
                owner = name
            elif start < match.start() and class_indent >= indent:
                owner = ""
        name = match.group("fn")
        if exported:
            visibility = "public" if name in exported or owner else "private"
        else:
            visibility = "private" if name.startswith("_") and not name.startswith("__") else "public"
        if name.startswith("__") and not name.endswith("__"):
            visibility = "private"
        out.append(Declaration(name, owner, visibility,
                               text.count("\n", 0, match.start()) + 1, match.start()))
    return out


def _go(text: str) -> list[Declaration]:
    out = []
    for match in _GO_DECL.finditer(text):
        name = match.group("fn")
        visibility = "public" if name[:1].isupper() else "private"
        out.append(Declaration(name, match.group("recv") or "", visibility,
                               text.count("\n", 0, match.start()) + 1, match.start()))
    return out


_PARSERS = {PHP: _php, JS: _js, PYTHON: _python, GO: _go}


def declarations(path: str, text: str) -> list[Declaration]:
    """Every function declared in `text`, ordered by position."""
    parser = _PARSERS.get(language_of(path) or "")
    return parser(text) if parser else []


def enclosing_in(parsed: list[Declaration], offset: int) -> Declaration | None:
    """The declaration containing `offset`, from an already-parsed file."""
    best = None
    for declaration in parsed:
        if declaration.offset < offset:
            best = declaration
        else:
            break
    return best


def enclosing(path: str, text: str, offset: int) -> Declaration | None:
    """The declaration containing `offset` — the nearest one before it."""
    return enclosing_in(declarations(path, text), offset)


def call_pattern(function: str, language: str | None = None) -> re.Pattern[str]:
    """Call syntax for a named function, across the languages we scan."""
    name = re.escape(function)
    return re.compile(
        rf"(?:->|::|\.|\$)\s*{name}\s*\(" rf"|(?<![\w$.>:]){name}\s*\(",
        re.IGNORECASE if language == PHP else 0,
    )
