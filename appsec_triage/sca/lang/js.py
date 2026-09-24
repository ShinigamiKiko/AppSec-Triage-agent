"""JavaScript, TypeScript and Vue single-file components."""

from __future__ import annotations

import re

from .base import Bindings, CallMatch, LanguageRules, blank_comments, call_regex, line_of

_SPEC = r"""(?P<q>['"`])(?P<spec>[^'"`\n]+)(?P=q)"""
_NAME = r"[A-Za-z_$][\w$]*"

_IMPORT_FROM = re.compile(
    rf"\bimport\s+(?P<type>type\s+)?(?P<clause>[^;'\"`]*?)\s+from\s+{_SPEC}", re.S)
_IMPORT_BARE = re.compile(rf"\bimport\s+{_SPEC}")
_IMPORT_EQUALS = re.compile(rf"\bimport\s+(?P<name>{_NAME})\s*=\s*require\s*\(\s*{_SPEC}\s*\)")
_REQUIRE = re.compile(
    rf"\b(?:const|let|var)\s+(?P<target>{_NAME}|\{{[^}}]*\}})\s*=\s*(?:await\s+)?"
    rf"(?:require|import)\s*\(\s*{_SPEC}\s*\)(?P<member>(?:\s*\.\s*{_NAME})*)")
_INLINE_REQUIRE = re.compile(rf"\brequire\s*\(\s*{_SPEC}\s*\)")
_ASSIGN = re.compile(
    rf"(?:\b(?:const|let|var)\s+(?P<decl>{_NAME})|(?P<lhs>(?:this|{_NAME})(?:\s*\.\s*[\w$]+)+))\s*"
    rf"(?::\s*[\w$.<>\[\]| ]+)?=\s*(?:await\s+)?(?P<new>new\s+)?(?P<rhs>{_NAME}(?:\s*\??\.\s*[\w$]+)*)\s*(?P<call>\()?")
_CONTAINER_ASSIGN = re.compile(
    rf"(?P<container>(?:this\s*\.\s*)?{_NAME})\s*\[[^\]\n]*\]\s*=\s*(?:await\s+)?(?:new\s+)?(?P<rhs>{_NAME}(?:\s*\??\.\s*[\w$]+)*)")
_HANDLER_PARAMS = r"\.\s*(?:use|get|post|put|delete|patch|all|options|head|on)\s*\([^)]*?(?:async\s*)?(?:function\s*[\w$]*\s*)?\(\s*(?P<a>[A-Za-z_$][\w$]*)\s*(?::[^,)]*)?,\s*(?P<b>[A-Za-z_$][\w$]*)"
_LOCAL_FUNCTION = re.compile(
    rf"\bfunction\s*\*?\s*(?P<f>{_NAME})\s*\(|\b(?:const|let|var)\s+(?P<v>{_NAME})\s*(?::[^=]+)?=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*(?::[^=]+)?=>|{_NAME}\s*=>)")
_EXPORT_DEFAULT = re.compile(
    rf"\bexport\s+default\s+(?:await\s+)?(?:new\s+)?(?P<name>{_NAME}(?:\s*\??\.\s*[\w$]+)*)\s*(?:[;\n(])")
_EXPORT_CONST = re.compile(rf"\bexport\s+(?:const|let|var)\s+(?P<name>{_NAME})\s*(?::[^=]+)?=")
_EXPORT_LIST = re.compile(r"\bexport\s*\{(?P<names>[^}]*)\}")
_METHOD_DECL = re.compile(rf"^\s*(?:(?:async|static|public|private|protected|get|set)\s+)*(?P<name>{_NAME})\s*\([^)]*\)\s*(?::[^{{]+)?\{{")
_FUNCTION_DECL = re.compile(rf"\bfunction\s*\*?\s*(?P<name>{_NAME})\s*\(")


def spec_matches(spec: str, package: str) -> str | None:
    """'' for the package itself, the subpath for `pkg/sub`, None for anything else."""
    spec = spec.strip()
    if spec == package:
        return ""
    if spec.startswith(package + "/"):
        return spec[len(package) + 1:]
    return None


def _named(clause: str) -> list[tuple[str, str]]:
    """`{ a, b as c, type D }` -> [(a, a), (b, c)]."""
    out = []
    for part in clause.strip().strip("{}").split(","):
        part = part.strip()
        if not part or part.startswith("type "):
            continue
        original, _, local = part.partition(" as ")
        original, local = original.strip(), (local.strip() or original.strip())
        if re.fullmatch(_NAME, local) and re.fullmatch(_NAME + r"|default", original):
            out.append((original, local))
    return out


def _destructured(target: str) -> list[tuple[str, str]]:
    """`{ a, b: c }` -> [(a, a), (b, c)]."""
    out = []
    for part in target.strip().strip("{}").split(","):
        part = part.strip()
        if not part or part.startswith("..."):
            continue
        original, _, local = part.partition(":")
        original, local = original.strip(), (local.strip() or original.strip())
        local = local.split("=")[0].strip()
        if re.fullmatch(_NAME, original) and re.fullmatch(_NAME, local):
            out.append((original, local))
    return out


def _add_member(bindings: Bindings, original: str, local: str) -> None:
    bindings.functions[local] = original
    bindings.receivers.add(local)
    if original[:1].isupper():
        bindings.classes[local] = original


class JavaScriptRules(LanguageRules):
    name = "js"
    suffixes = frozenset({".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".vue", ".svelte"})

    def strip_comments(self, text: str) -> str:
        return blank_comments(text, line_comments=("//",))

    def bindings(self, text: str, package: str, *, namespaces: list[str] | None = None) -> Bindings:
        found = Bindings()
        for match in _IMPORT_FROM.finditer(text):
            sub = spec_matches(match.group("spec"), package)
            if sub is None:
                continue
            found.import_lines.append(line_of(text, match.start()))
            if match.group("type"):
                continue
            clause = match.group("clause").strip()
            default, _, rest = clause.partition(",") if not clause.startswith(("{", "*")) else ("", "", clause)
            default = default.strip()
            if default and re.fullmatch(_NAME, default):
                if sub:
                    _add_member(found, sub.rsplit("/", 1)[-1], default)
                else:
                    found.receivers.add(default)
            rest = rest.strip()
            if star := re.match(rf"\*\s+as\s+({_NAME})", rest):
                found.receivers.add(star.group(1))
            elif "{" in rest:
                for original, local in _named(rest[rest.index("{"):]):
                    if original == "default":
                        found.receivers.add(local)
                    else:
                        _add_member(found, original, local)
        for match in _IMPORT_EQUALS.finditer(text):
            if spec_matches(match.group("spec"), package) is not None:
                found.import_lines.append(line_of(text, match.start()))
                found.receivers.add(match.group("name"))
        for match in _IMPORT_BARE.finditer(text):
            if spec_matches(match.group("spec"), package) is not None:
                found.import_lines.append(line_of(text, match.start()))
        for match in _REQUIRE.finditer(text):
            sub = spec_matches(match.group("spec"), package)
            if sub is None:
                continue
            found.import_lines.append(line_of(text, match.start()))
            target = match.group("target")
            members = [m.strip() for m in (match.group("member") or "").split(".") if m.strip()]
            if target.startswith("{"):
                for original, local in _destructured(target):
                    _add_member(found, original, local)
            elif members:
                _add_member(found, members[-1], target)
            elif sub:
                _add_member(found, sub.rsplit("/", 1)[-1], target)
            else:
                found.receivers.add(target)
        for match in _INLINE_REQUIRE.finditer(text):
            if spec_matches(match.group("spec"), package) is not None:
                line = line_of(text, match.start())
                if line not in found.import_lines:
                    found.import_lines.append(line)
        if not found.empty:
            self._derive(text, found)
        return found

    def _derive(self, text: str, found: Bindings) -> None:
        """One or two assignments away: `const api = axios.create()`, `this.client = new Client()`."""
        for _ in range(2):
            grown = False
            for match in _ASSIGN.finditer(text):
                rhs = re.sub(r"\s+", "", match.group("rhs")).replace("?.", ".")
                if not self._bound_chain(rhs, found) and rhs.split(".")[0] not in found.classes:
                    continue
                target = match.group("decl") or re.sub(r"\s+", "", match.group("lhs") or "")
                if target and target not in found.receivers:
                    found.receivers.add(target)
                    grown = True
            # A registry of instances: `instances[name] = axios.create(...)`.
            for match in _CONTAINER_ASSIGN.finditer(text):
                rhs = re.sub(r"\s+", "", match.group("rhs")).replace("?.", ".")
                target = re.sub(r"\s+", "", match.group("container"))
                if self._bound_chain(rhs, found) and target not in found.receivers:
                    found.receivers.add(target)
                    grown = True
            # Request handlers registered on a bound app: `app.use('*', async (req, res) => …)`.
            for receiver in sorted(found.receivers):
                if "." in receiver or "[" in receiver:
                    continue
                for match in re.finditer(re.escape(receiver) + _HANDLER_PARAMS, text):
                    for name in (match.group("a"), match.group("b")):
                        if name not in found.receivers:
                            found.receivers.add(name)
                            grown = True
            if not grown:
                return

    @staticmethod
    def _bound_chain(chain: str, found: Bindings) -> bool:
        chain = chain.replace("?.", ".")
        for receiver in found.receivers:
            if chain == receiver or chain.startswith(receiver + "."):
                return True
        return False

    def exports_bound(self, text: str, found: Bindings) -> set[str]:
        """Which of this module's exports are the package or an object from it."""
        out: set[str] = set()
        for match in _EXPORT_DEFAULT.finditer(text):
            name = re.sub(r"\s+", "", match.group("name")).replace("?.", ".")
            if self._bound_chain(name, found) or name.split(".")[0] in found.classes:
                out.add("default")
        for match in _EXPORT_CONST.finditer(text):
            if self._bound_chain(match.group("name"), found):
                out.add(match.group("name"))
        for match in _EXPORT_LIST.finditer(text):
            for original, local in _named(match.group("names")):
                if self._bound_chain(original, found):
                    out.add(local if local != original else original)
        return out

    def local_imports(self, text: str) -> list[tuple[str, str, str]]:
        """(spec, imported name or 'default', local name) for project-relative imports."""
        out = []
        for match in _IMPORT_FROM.finditer(text):
            spec = match.group("spec")
            if not spec.startswith((".", "@/", "~/", "/")) or match.group("type"):
                continue
            clause = match.group("clause").strip()
            default, _, rest = clause.partition(",") if not clause.startswith(("{", "*")) else ("", "", clause)
            if default.strip() and re.fullmatch(_NAME, default.strip()):
                out.append((spec, "default", default.strip()))
            if "{" in rest:
                for original, local in _named(rest[rest.index("{"):]):
                    out.append((spec, original, local))
        for match in _REQUIRE.finditer(text):
            spec = match.group("spec")
            if spec.startswith((".", "@/", "~/", "/")) and not match.group("target").startswith("{"):
                out.append((spec, "default", match.group("target")))
        return out

    def declares(self, line: str, function: str) -> bool:
        method = _METHOD_DECL.match(line)
        if method and method.group("name") == function and not line.strip().startswith(("if", "for", "while", "return")):
            return True
        declared = _FUNCTION_DECL.search(line)
        return bool(declared and declared.group("name") == function)

    def calls(self, text: str, bindings: Bindings, function: str, klass: str = "") -> list[CallMatch]:
        out: list[CallMatch] = []
        # A function this file defines itself is not the package's, whatever its name.
        local = {m.group("f") or m.group("v") for m in _LOCAL_FUNCTION.finditer(text)}
        names = [function] + [local for local, original in bindings.functions.items()
                              if original == function and local != function]
        lines = text.splitlines()
        for name in dict.fromkeys(names):
            pattern = call_regex(name)
            for number, line in enumerate(lines, 1):
                if function not in line and name not in line:
                    continue
                if self.declares(line, name):
                    continue
                for match in pattern.finditer(line):
                    receiver = match.group("recv")
                    if receiver is not None:
                        if match.group("sep") in ("->", "::"):
                            continue
                        chain = re.sub(r"\s+", "", receiver).replace("?.", ".")
                        chain = re.sub(r"\([^()]*\)|\[[^\]]*\]", "", chain)
                        root = chain.split(".")[0]
                        if root in ("this", "self", "window", "globalThis") and not self._bound_chain(chain, bindings):
                            out.append(CallMatch(number, line.strip()[:160], match.start(), False, "this"))
                            continue
                        if self.is_builtin(root) and root not in bindings.receivers:
                            continue
                        if klass and root in bindings.classes and bindings.classes[root] == klass:
                            out.append(CallMatch(number, line.strip()[:160], match.start(), True, "static"))
                        elif self._bound_chain(chain, bindings):
                            out.append(CallMatch(number, line.strip()[:160], match.start(), True, "import"))
                        else:
                            out.append(CallMatch(number, line.strip()[:160], match.start(), False, "name"))
                    else:
                        if bindings.functions.get(name) == function:
                            out.append(CallMatch(number, line.strip()[:160], match.start(), True, "import"))
                        elif self.is_builtin(name) or name in local:
                            continue
                        else:
                            out.append(CallMatch(number, line.strip()[:160], match.start(), False, "bare"))
        return out
