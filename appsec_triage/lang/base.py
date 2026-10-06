"""What every language module answers: which local names a file binds to a package,
and which calls of a function go through one of those names.

A call counts as the package's call only when its receiver is a name the file
bound to that package — an import, a `require`, a `use`, or one assignment away
from one (`const api = axios.create()`). A bare name that merely matches is a
lead at most, and a name that belongs to the language or the browser
(`Date.parse`, `JSON.parse`, `Object.assign`, `new FormData()`,
`decodeURIComponent`) is not even that.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

_LANG_DIR = Path(__file__).parent


@lru_cache(maxsize=None)
def builtin_names(language: str) -> frozenset[str]:
    """Names the language or its runtime owns, from `<language>/builtins.txt`."""
    path = _LANG_DIR / language / "builtins.txt"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    names = set()
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            names.update(line.split())
    return frozenset(names)


@dataclass(slots=True)
class Bindings:
    """Local names tied to one package in one file."""

    # Names that stand for the package or an object from it: `axios`, `_`, `$yaml`, `yaml`.
    receivers: set[str] = field(default_factory=set)
    # Names that are one function of the package, and which one: {"tpl": "template"}.
    functions: dict[str, str] = field(default_factory=dict)
    # Names that are one class of the package: {"Parser": "Parser"}.
    classes: dict[str, str] = field(default_factory=dict)
    # Lines where the package is brought in.
    import_lines: list[int] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not (self.receivers or self.functions or self.classes)


@dataclass(slots=True)
class CallMatch:
    line: int
    text: str
    column: int
    bound: bool
    how: str = ""


def blank_comments(text: str, *, line_comments: tuple[str, ...], hash_comments: bool = False,
                   backtick_strings: bool = True) -> str:
    """Comments replaced by spaces, strings and line numbers kept.

    Strings are tracked so that `"https://x"` is not cut at `//`.
    """
    out: list[str] = []
    i, n = 0, len(text)
    quote = ""
    while i < n:
        ch = text[i]
        if quote:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = ""
            i += 1
            continue
        if ch in "'\"" or (ch == "`" and backtick_strings):
            quote = ch
            out.append(ch)
            i += 1
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            end = n if end < 0 else end + 2
            out.append("".join("\n" if c == "\n" else " " for c in text[i:end]))
            i = end
            continue
        if any(text.startswith(marker, i) for marker in line_comments) or (hash_comments and ch == "#"
                                                                            and not text.startswith("#[", i)):
            end = text.find("\n", i)
            end = n if end < 0 else end
            out.append(" " * (end - i))
            i = end
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class LanguageRules:
    """Shared machinery; each language supplies its binding and call syntax."""

    name = ""
    suffixes: frozenset[str] = frozenset()
    # Ecosystem names a package of this language is reported under.
    ecosystems: frozenset[str] = frozenset()
    # Method names so common that a match without a binding says nothing.
    ubiquitous: frozenset[str] = frozenset({
        "get", "set", "post", "put", "delete", "patch", "request", "load", "parse", "format",
        "merge", "assign", "create", "read", "write", "send", "open", "close", "run", "call",
        "apply", "bind", "push", "pop", "map", "filter", "reduce", "find", "forEach", "then",
        "catch", "toString", "valueOf", "stringify", "update", "save", "render", "resolve",
        "reject", "match", "replace", "split", "join", "trim", "test", "exec", "init", "start",
        "stop", "reset", "clear", "count", "execute", "handle", "process", "validate", "log",
        "debug", "info", "warn", "error", "emit", "on", "off", "once", "use", "listen", "next",
        "expand", "random", "watch", "normalize", "encode", "decode", "escape",
    })

    def strip_comments(self, text: str) -> str:
        raise NotImplementedError

    def bindings(self, text: str, package: str, *, namespaces: list[str] | None = None) -> Bindings:
        raise NotImplementedError

    def is_builtin(self, name: str) -> bool:
        return name in builtin_names(self.name)

    def calls(self, text: str, bindings: Bindings, function: str, klass: str = "") -> list[CallMatch]:
        raise NotImplementedError

    def declares(self, line: str, function: str) -> bool:
        """The line defines `function` rather than calling it."""
        return False

    def is_ubiquitous(self, function: str) -> bool:
        return function.lower() in _lowered(self.ubiquitous)

    # Re-exports across project files; only a language with module-level exports has them.
    def exports_bound(self, text: str, found: Bindings) -> set[str]:
        """Names this file exports that stand for the package."""
        return set()

    def local_imports(self, text: str) -> list[tuple[str, str, str]]:
        """(spec, imported name, local name) for each import of a project file."""
        return []

    def _derive(self, text: str, found: Bindings) -> None:
        """Extend `found` with names built from the bound ones."""


@lru_cache(maxsize=None)
def _lowered(names: frozenset[str]) -> frozenset[str]:
    return frozenset(n.lower() for n in names)


def call_regex(function: str) -> re.Pattern[str]:
    """`<receiver-chain>.function(` / `?.function(` / `->function(` / `::function(` / bare `function(`."""
    name = re.escape(function)
    return re.compile(
        rf"(?P<recv>(?:[A-Za-z_$\\][\w$\\]*)(?:\s*(?:\??\.|->|::)\s*[A-Za-z_$][\w$]*|\s*\[[^\]\n]*\]|\s*\([^()\n]*\))*)"
        rf"\s*(?P<sep>\??\.|->|::)\s*{name}\s*\("
        rf"|(?<![\w$.>:\\])(?P<bare>{name})\s*\("
    )

