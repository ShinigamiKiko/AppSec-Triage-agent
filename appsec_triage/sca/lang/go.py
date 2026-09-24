"""Go: import paths, package-qualified calls, and values typed or built from them."""

from __future__ import annotations

import re

from .base import Bindings, CallMatch, LanguageRules, blank_comments, call_regex, line_of

_IMPORT_ONE = re.compile(r'^\s*import\s+(?P<alias>[\w.]+\s+)?"(?P<path>[^"]+)"', re.M)
_IMPORT_BLOCK = re.compile(r"^\s*import\s*\((?P<body>.*?)\)", re.M | re.S)
_BLOCK_LINE = re.compile(r'^\s*(?P<alias>[\w.]+\s+)?"(?P<path>[^"]+)"', re.M)
_FUNC_DECL = re.compile(r"^\s*func\s*(?:\([^)]*\)\s*)?(?P<name>\w+)\s*[\[(]")


def default_name(path: str) -> str:
    """The name Go gives an import without an alias, as far as the path tells it."""
    parts = [p for p in path.split("/") if p]
    last = parts[-1] if parts else path
    if re.fullmatch(r"v\d+", last) and len(parts) > 1:
        last = parts[-2]
    last = re.sub(r"\.v\d+$", "", last)
    if last.startswith("go-"):
        last = last[3:]
    return re.sub(r"[^\w]", "", last)


def in_module(path: str, module: str) -> bool:
    return path == module or path.startswith(module.rstrip("/") + "/")


class GoRules(LanguageRules):
    name = "go"
    suffixes = frozenset({".go"})

    def strip_comments(self, text: str) -> str:
        return blank_comments(text, line_comments=("//",))

    def bindings(self, text: str, package: str, *, namespaces: list[str] | None = None) -> Bindings:
        found = Bindings()
        imports: list[tuple[str, str, int]] = []
        for match in _IMPORT_ONE.finditer(text):
            imports.append(((match.group("alias") or "").strip(), match.group("path"), line_of(text, match.start())))
        for block in _IMPORT_BLOCK.finditer(text):
            base = line_of(text, block.start("body"))
            for match in _BLOCK_LINE.finditer(block.group("body")):
                imports.append(((match.group("alias") or "").strip(), match.group("path"),
                                base + block.group("body").count("\n", 0, match.start())))
        for alias, path, line in imports:
            if not in_module(path, package):
                continue
            found.import_lines.append(line)
            if alias == "_":
                continue
            if alias == ".":
                found.functions["*"] = "*"
                continue
            found.receivers.add(alias or default_name(path))
        if found.receivers:
            self._derive(text, found)
        return found

    def _derive(self, text: str, found: Bindings) -> None:
        packages = sorted(found.receivers)
        alternation = "|".join(re.escape(p) for p in packages)
        typed = re.compile(rf"\b(?P<var>[a-zA-Z_]\w*)\s+(?:\[\])?\*?(?:{alternation})\.[A-Z]\w*")
        built = re.compile(
            rf"\b(?P<vars>[a-zA-Z_]\w*(?:\s*,\s*[a-zA-Z_]\w*)*)\s*:?=\s*&?(?:{alternation})\.[A-Z]\w*\s*[({{]")
        for match in typed.finditer(text):
            if match.group("var") not in ("func", "return", "var", "type", "struct"):
                found.receivers.add(match.group("var"))
        for match in built.finditer(text):
            first = match.group("vars").split(",")[0].strip()
            if first and first != "_":
                found.receivers.add(first)

    def declares(self, line: str, function: str) -> bool:
        declared = _FUNC_DECL.match(line)
        return bool(declared and declared.group("name") == function)

    def calls(self, text: str, bindings: Bindings, function: str, klass: str = "") -> list[CallMatch]:
        out: list[CallMatch] = []
        pattern = call_regex(function)
        for number, line in enumerate(text.splitlines(), 1):
            if function not in line or self.declares(line, function):
                continue
            for match in pattern.finditer(line):
                receiver = match.group("recv")
                snippet = line.strip()[:160]
                if receiver is None:
                    bound = "*" in bindings.functions
                    if bound or not self.is_builtin(function):
                        out.append(CallMatch(number, snippet, match.start(), bound, "dot import" if bound else "bare"))
                    continue
                if match.group("sep") != ".":
                    continue
                root = re.sub(r"\s+", "", receiver).split(".")[0]
                if root in bindings.receivers:
                    out.append(CallMatch(number, snippet, match.start(), True, "import"))
                elif not self.is_builtin(root):
                    out.append(CallMatch(number, snippet, match.start(), False, "name"))
        return out
