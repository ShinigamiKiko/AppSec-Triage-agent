"""Which application code is an HTTP entry point — read from routing, not the LSP.

The gap this closes was measured, not guessed. On a real Symfony project every
PHP finding came back with zero callers: Phpactor advertises no
`callHierarchy`, and the `references` fallback answers nothing useful for a
controller action because *nothing in the codebase calls it*. The framework
does, from a route table the language server never looks at.

So reachability for PHP is answered where the answer actually lives:

* `#[Route(...)]` attributes (Symfony 5.2+, and the modern default)
* `@Route(...)` docblock annotations, including the multi-line form — this is
  what the project that exposed the gap actually uses
* `config/routes*.yaml`, where an entry names `Controller::action` explicitly

The question asked of this index is deliberately narrow and answerable: **is the
flagged line inside a method the framework will call for an HTTP request?** That
is a fact about the routing table, and it is either true or unknown — never
"false, therefore safe". A route can be registered by a bundle, a subscriber, a
parent class or a compiler pass, and none of those appear here.

Parsing, not evaluating: this reads source as text and never includes it. The
files are the user's own repository, but they are still input.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "vendor", "node_modules", "var", "cache", "build", "public/build"}

_ATTRIBUTE_OPEN = re.compile(r"#\[\s*(?:[\w\\]+\\)?Route\b")
_ANNOTATION_OPEN = re.compile(r"@(?:[\w\\]+\\)?Route\b")
_PATH_NAMED = re.compile(r"""path\s*[:=]\s*["']([^"']*)["']""")
_PATH_POSITIONAL = re.compile(r"""["']([^"']*)["']""")
_METHODS_ARG = re.compile(r"""methods\s*[:=]\s*(\[[^\]]*\]|["'][^"']*["'])""")

_METHOD_DEF = re.compile(
    r"^\s*(?:(?:public|private|protected|static|final|abstract)\s+)*function\s+&?(\w+)"
)
_CLASS_DEF = re.compile(r"^\s*(?:final\s+|abstract\s+)?class\s+(\w+)")

_YAML_CONTROLLER = re.compile(r"controller\s*:\s*['\"]?([\w\\]+)::(\w+)")
_GO_ROUTER = re.compile(r"@Router\s+(\S+)\s+\[([A-Za-z]+)\]", re.IGNORECASE)
_GO_FUNC_DEF = re.compile(
    r"^\s*func\s*(?:\(\s*\w+\s+\*?([\w.]+)\s*\)\s*)?(\w+)\s*\("
)
_JS_ROUTE = re.compile(
    r"\b(?:router|app)\.(get|post|put|patch|delete|options|head|all|use)"
    r"\s*\(\s*['\"]([^'\"]+)['\"]",
    re.IGNORECASE,
)
_JS_FUNCTION = re.compile(
    r"^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(|"
    r"^\s*(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\([^\n]*\)\s*=>"
)
_JS_IMPORT = re.compile(
    r"(?:require\s*\(\s*|from\s+|import\s*\(\s*)['\"](\.?\.?/[^'\"]+)['\"]"
)

_MAX_FILES = 6000
_MAX_HOPS = 3

_REFERENCED = re.compile(r"\b([A-Z][A-Za-z0-9_]{2,})\b")


def _stem(file_path: str) -> str:
    return Path(file_path.replace("\\", "/")).stem


@dataclass(slots=True)
class Route:
    """One method the framework will call for an HTTP request."""

    file_path: str
    class_name: str | None
    method: str
    line: int
    end_line: int
    path: str | None = None
    http_methods: str | None = None
    declared_by: str = "attribute"

    def describe(self) -> str:
        verb = self.http_methods or "any method"
        where = f"{self.class_name}::{self.method}" if self.class_name else self.method
        return f"{where} is routed ({verb} {self.path or 'path not parsed'}, via {self.declared_by})"


@dataclass(slots=True)
class RouteIndex:
    routes: list[Route] = field(default_factory=list)
    files_scanned: int = 0
    _naming_cache: dict[str, list[Route]] = field(default_factory=dict, repr=False)
    _perimeter: dict[str, int] | None = field(default=None, repr=False)
    _perimeter_via: dict[str, list[str]] = field(default_factory=dict, repr=False)

    @property
    def usable(self) -> bool:
        return bool(self.routes)

    def enclosing(self, file_path: str, line: int) -> Route | None:
        """The routed method containing this line, if any.

        Matching is on the path suffix because scanner reports, LSP answers and
        the filesystem disagree about how absolute a path is, and normalising
        three conventions into one has already been a source of silent misses.
        """
        needle = file_path.replace("\\", "/").lstrip("./")
        for route in self.routes:
            haystack = route.file_path.replace("\\", "/")
            if not (haystack.endswith(needle) or needle.endswith(haystack)):
                continue
            if route.line <= line <= route.end_line:
                return route
        return None

    def perimeter(self, file_path: str) -> tuple[int, list[str]] | None:
        """How many hops from an HTTP entry point this file sits, and via what.

        Routed controllers are hop 0. A file whose class a controller names is
        hop 1, a file that one names is hop 2, and so on to `_MAX_HOPS`. This is
        the question the reviewer actually opens with — *is this function inside
        the request perimeter or outside it?* — and on a real Symfony project it
        is the only form of the question that has an answer, because the
        dangerous code lives in services that no controller line calls directly.

        `None` means "not found", never "unreachable". Console commands, message
        handlers, event subscribers and cron entry points are all real ways in
        that this index does not model.
        """
        if self._perimeter is None:
            return None
        key = _stem(file_path)
        hop = self._perimeter.get(key)
        if hop is None:
            return None
        return hop, self._perimeter_via.get(key, [])

    def routes_naming(self, symbol: str, limit: int = 3) -> list[Route]:
        """Routed methods whose file mentions `symbol` — one hop out.

        Weaker than `enclosing` and labelled as such wherever it is used: a
        controller naming a class is not proof it reaches this particular
        method. It answers "is this class in the request-handling perimeter at
        all", which is the question a reviewer actually starts from.
        """
        if not symbol or len(symbol) < 3:
            return []
        if symbol in self._naming_cache:
            return self._naming_cache[symbol]
        out: list[Route] = []
        seen: set[str] = set()
        for route in self.routes:
            if route.file_path in seen:
                continue
            try:
                text = Path(route.file_path).read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if re.search(rf"\b{re.escape(symbol)}\b", text):
                seen.add(route.file_path)
                out.append(route)
                if len(out) >= limit:
                    break
        self._naming_cache[symbol] = out
        return out


def _method_spans(lines: list[str]) -> list[tuple[int, int, str]]:
    """(start, end, name) for each method, 1-indexed and inclusive.

    The end is the line before the next method definition rather than a matched
    closing brace. Brace counting breaks on braces inside strings and heredocs,
    and being one method too generous costs a slightly wide window; being wrong
    about *which* method contains the sink costs a wrong answer.
    """
    starts = [(n, m.group(1)) for n, line in enumerate(lines, 1) if (m := _METHOD_DEF.match(line))]
    spans = []
    for i, (start, name) in enumerate(starts):
        end = starts[i + 1][0] - 1 if i + 1 < len(starts) else len(lines)
        spans.append((start, end, name))
    return spans


def _go_function_spans(lines: list[str]) -> list[tuple[int, int, str, str | None]]:
    starts = [
        (number, match.group(2), match.group(1))
        for number, line in enumerate(lines, 1)
        if (match := _GO_FUNC_DEF.match(line))
    ]
    return [
        (
            start,
            starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines),
            name,
            receiver,
        )
        for index, (start, name, receiver) in enumerate(starts)
    ]


def _parse_go(path: Path, index: RouteIndex) -> None:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return
    spans = _go_function_spans(lines)
    for number, line in enumerate(lines, 1):
        match = _GO_ROUTER.search(line)
        if not match:
            continue
        function = next((span for span in spans if span[0] > number), None)
        if function is None:
            continue
        start, end, method, receiver = function
        index.routes.append(
            Route(
                file_path=str(path),
                class_name=receiver,
                method=method,
                line=start,
                end_line=end,
                path=match.group(1),
                http_methods=match.group(2).upper(),
                declared_by="Go @Router annotation",
            )
        )


def _js_function_spans(lines: list[str]) -> list[tuple[int, int, str]]:
    starts = []
    for number, line in enumerate(lines, 1):
        match = _JS_FUNCTION.match(line)
        if match:
            starts.append((number, match.group(1) or match.group(2) or "anonymous"))
    return [
        (start, starts[index + 1][0] - 1 if index + 1 < len(starts) else len(lines), name)
        for index, (start, name) in enumerate(starts)
    ]


def _parse_js(path: Path, index: RouteIndex) -> set[str]:
    """Index Express registrations and return relative imported module stems."""
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return set()
    route_lines = [number for number, line in enumerate(lines, 1) if _JS_ROUTE.search(line)]
    for index_number, number in enumerate(route_lines):
        match = _JS_ROUTE.search(lines[number - 1])
        if not match:
            continue
        end = route_lines[index_number + 1] - 1 if index_number + 1 < len(route_lines) else len(lines)
        start = number
        # Function spans are intentionally broad for JavaScript; a named helper
        # declared above a top-level router call must not be reported as the route.
        method = f"{match.group(1).lower()} {match.group(2)}"
        index.routes.append(Route(
            file_path=str(path), class_name=None, method=method,
            line=start, end_line=end, path=match.group(2),
            http_methods=match.group(1).upper(), declared_by="Express route",
        ))
    return {
        Path(value).stem
        for line in lines
        for match in _JS_IMPORT.finditer(line)
        for value in [match.group(1)]
    }


def _args_after(lines: list[str], start: int, limit: int = 8) -> str:
    """The annotation's arguments, which routinely run over several lines."""
    return " ".join(lines[start - 1 : start - 1 + limit])


def _parse_php(path: Path, index: RouteIndex) -> None:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return
    if "Route" not in text:
        return
    lines = text.splitlines()
    class_name = next((m.group(1) for line in lines if (m := _CLASS_DEF.match(line))), None)
    spans = _method_spans(lines)
    if not spans:
        return

    for n, line in enumerate(lines, 1):
        is_attribute = bool(_ATTRIBUTE_OPEN.search(line))
        if not is_attribute and not _ANNOTATION_OPEN.search(line):
            continue
        span = next((s for s in spans if s[0] > n), None)
        if span is None:
            continue
        args = _args_after(lines, n)
        path_arg = _PATH_NAMED.search(args) or _PATH_POSITIONAL.search(args)
        methods_arg = _METHODS_ARG.search(args)
        index.routes.append(
            Route(
                file_path=str(path),
                class_name=class_name,
                method=span[2],
                line=span[0],
                end_line=span[1],
                path=path_arg.group(1) if path_arg else None,
                http_methods=methods_arg.group(1).strip("[]\"' ") if methods_arg else None,
                declared_by="attribute" if is_attribute else "annotation",
            )
        )


def _parse_yaml_routes(root: Path, index: RouteIndex) -> None:
    """`controller: App\\Controller\\Foo::bar` entries in config/routes*.

    Read as text rather than through a YAML parser on purpose: these files are
    full of Symfony-specific tags and imports, and the one line that matters is
    unambiguous on its own.
    """
    candidates = list(root.glob("config/routes.yaml")) + list(root.glob("config/routes/**/*.yaml"))
    known = {(r.class_name, r.method) for r in index.routes}
    for cfg in candidates:
        try:
            text = cfg.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _YAML_CONTROLLER.finditer(text):
            fqcn, method = match.group(1), match.group(2)
            short = fqcn.rsplit("\\", 1)[-1]
            if (short, method) in known:
                continue
            for php in root.rglob(f"{short}.php"):
                if _SKIP_DIRS & set(php.parts):
                    continue
                lines = php.read_text(encoding="utf-8", errors="replace").splitlines()
                span = next((s for s in _method_spans(lines) if s[2] == method), None)
                if span:
                    index.routes.append(
                        Route(
                            file_path=str(php),
                            class_name=short,
                            method=method,
                            line=span[0],
                            end_line=span[1],
                            declared_by="yaml",
                        )
                    )
                break


def _build_perimeter(files: dict[str, set[str]], index: RouteIndex) -> None:
    """Breadth-first from the routed files outward, over class references.

    One pass over the sources collects the capitalised identifiers each file
    mentions; the walk then only intersects sets. Matching class *stems* rather
    than fully-qualified names is imprecise in both directions, and that is the
    right trade here: this output is phrased as a question to the reviewer, so a
    spurious hop costs a sentence and a missing hop costs an unasked question.
    """
    hops: dict[str, int] = {}
    via: dict[str, list[str]] = {}
    frontier = []
    for route in index.routes:
        stem = _stem(route.file_path)
        if stem not in hops:
            hops[stem] = 0
            via[stem] = [route.describe()]
            frontier.append(stem)

    known = set(files)
    for hop in range(1, _MAX_HOPS + 1):
        nxt = []
        for parent in frontier:
            for ref in files.get(parent, ()) & known:
                if ref in hops:
                    continue
                hops[ref] = hop
                via[ref] = [*via.get(parent, [])[-2:], f"named by {parent}"]
                nxt.append(ref)
        frontier = nxt
        if not frontier:
            break

    index._perimeter = hops
    index._perimeter_via = via


def build_index(roots: list[Path]) -> RouteIndex:
    index = RouteIndex()
    references: dict[str, set[str]] = {}
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        source_paths = [*root.rglob("*.php"), *root.rglob("*.go"),
                        *root.rglob("*.js"), *root.rglob("*.jsx"),
                        *root.rglob("*.ts"), *root.rglob("*.tsx")]
        for path in source_paths:
            if index.files_scanned >= _MAX_FILES:
                log.warning("route index hit the %d-file budget; reachability may be incomplete", _MAX_FILES)
                break
            if _SKIP_DIRS & set(path.parts):
                continue
            index.files_scanned += 1
            if path.suffix.lower() == ".php":
                _parse_php(path, index)
            elif path.suffix.lower() == ".go":
                _parse_go(path, index)
            else:
                imported = _parse_js(path, index)
                if imported:
                    references[path.stem] = imported
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            references.setdefault(path.stem, set()).update(
                set(_REFERENCED.findall(text)) - {path.stem})
        _parse_yaml_routes(root, index)
    if index.routes:
        _build_perimeter(references, index)
        log.info(
            "route index: %d HTTP entry points across %d files; %d files within %d hops of one",
            len(index.routes),
            index.files_scanned,
            len(index._perimeter or {}),
            _MAX_HOPS,
        )
    return index
