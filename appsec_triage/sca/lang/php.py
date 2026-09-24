"""PHP: `use` statements, fully qualified names, and objects built from bound classes."""

from __future__ import annotations

import re

from .base import Bindings, CallMatch, LanguageRules, blank_comments, call_regex, line_of

_QNAME = r"\\?[A-Za-z_][\w]*(?:\\[A-Za-z_][\w]*)*"
_USE = re.compile(rf"^\s*use\s+(?P<kind>function\s+|const\s+)?(?P<body>[^;]+);", re.M)
_NEW_ASSIGN = re.compile(
    rf"(?P<target>\$[A-Za-z_]\w*(?:\s*->\s*[A-Za-z_]\w*)*)\s*=\s*(?:new\s+(?P<new>{_QNAME})\s*\(|(?P<static>{_QNAME})\s*::\s*\w+\s*\()")
_TYPED = re.compile(rf"(?P<type>\??{_QNAME})\s+(?:&\s*)?(?:\.\.\.\s*)?(?P<var>\$[A-Za-z_]\w*)")
_PROPERTY = re.compile(
    rf"(?:public|protected|private|readonly|var)(?:\s+(?:readonly|static))*\s+(?P<type>\??{_QNAME})\s+\$(?P<prop>[A-Za-z_]\w*)")
_PROMOTED = re.compile(
    rf"(?:public|protected|private)(?:\s+readonly)?\s+(?P<type>\??{_QNAME})\s+\$(?P<prop>[A-Za-z_]\w*)")
_FUNCTION_DECL = re.compile(r"\bfunction\s+&?\s*(?P<name>[A-Za-z_]\w*)\s*\(")


def _short(name: str) -> str:
    return name.strip().lstrip("\\?").rsplit("\\", 1)[-1]


def _in_namespaces(qname: str, namespaces: list[str]) -> bool:
    qname = qname.strip().lstrip("\\?").lower()
    return any(qname == ns.lower().strip("\\") or qname.startswith(ns.lower().strip("\\") + "\\")
               for ns in namespaces if ns)


class PhpRules(LanguageRules):
    name = "php"
    suffixes = frozenset({".php", ".phtml", ".inc"})

    def strip_comments(self, text: str) -> str:
        return blank_comments(text, line_comments=("//",), hash_comments=True, backtick_strings=False)

    def bindings(self, text: str, package: str, *, namespaces: list[str] | None = None) -> Bindings:
        namespaces = list(namespaces or [])
        found = Bindings()
        for match in _USE.finditer(text):
            kind = (match.group("kind") or "").strip()
            body = match.group("body").strip()
            entries: list[tuple[str, str]] = []
            if "{" in body:
                prefix, _, group = body.partition("{")
                for part in group.rstrip("}").split(","):
                    part = part.strip()
                    if part:
                        name, _, alias = part.partition(" as ")
                        entries.append((prefix.strip().rstrip("\\") + "\\" + name.strip(), alias.strip()))
            else:
                for part in body.split(","):
                    name, _, alias = part.strip().partition(" as ")
                    entries.append((name.strip(), alias.strip()))
            for qname, alias in entries:
                if not _in_namespaces(qname, namespaces):
                    continue
                local = alias or _short(qname)
                found.import_lines.append(line_of(text, match.start()))
                if kind == "function":
                    found.functions[local] = _short(qname)
                elif kind != "const":
                    found.classes[local] = _short(qname)
        # Fully qualified use without a `use` statement.
        for ns in namespaces:
            for match in re.finditer(rf"\\?{re.escape(ns.strip(chr(92)))}\\(?P<cls>[A-Za-z_]\w*)\b", text):
                found.classes.setdefault(match.group(0).lstrip("\\"), match.group("cls"))
        if not found.empty:
            self._derive(text, found)
        return found

    def _class_bound(self, name: str, found: Bindings) -> bool:
        name = name.strip().lstrip("?")
        return name.lstrip("\\") in found.classes or _short(name) in found.classes and "\\" not in name

    def _derive(self, text: str, found: Bindings) -> None:
        for match in _NEW_ASSIGN.finditer(text):
            cls = match.group("new") or match.group("static")
            if cls and self._class_bound(cls, found):
                found.receivers.add(re.sub(r"\s+", "", match.group("target")))
        for match in _TYPED.finditer(text):
            if self._class_bound(match.group("type"), found):
                found.receivers.add(match.group("var"))
        for pattern in (_PROPERTY, _PROMOTED):
            for match in pattern.finditer(text):
                if self._class_bound(match.group("type"), found):
                    found.receivers.add(f"$this->{match.group('prop')}")

    def declares(self, line: str, function: str) -> bool:
        declared = _FUNCTION_DECL.search(line)
        return bool(declared and declared.group("name").lower() == function.lower())

    def calls(self, text: str, bindings: Bindings, function: str, klass: str = "") -> list[CallMatch]:
        out: list[CallMatch] = []
        pattern = call_regex(function)
        for number, line in enumerate(text.splitlines(), 1):
            if function.lower() not in line.lower() or self.declares(line, function):
                continue
            for match in pattern.finditer(line):
                receiver = match.group("recv")
                snippet = line.strip()[:160]
                if receiver is None:
                    if function in bindings.functions or bindings.functions.get(function):
                        out.append(CallMatch(number, snippet, match.start(), True, "use function"))
                    elif not self.is_builtin(function.lower()):
                        out.append(CallMatch(number, snippet, match.start(), False, "bare"))
                    continue
                chain = re.sub(r"\s+", "", receiver)
                if match.group("sep") == "::":
                    cls = chain.lstrip("\\")
                    bound = cls in bindings.classes or _short(cls) in bindings.classes
                    if klass and bound:
                        bound = bindings.classes.get(cls, bindings.classes.get(_short(cls), "")).lower() == klass.lower()
                    out.append(CallMatch(number, snippet, match.start(), bound, "static" if bound else "name"))
                    continue
                if match.group("sep") != "->":
                    continue
                bound = any(chain == r or chain.startswith(r + "->") for r in bindings.receivers)
                out.append(CallMatch(number, snippet, match.start(), bound, "object" if bound else "name"))
        return out
