"""Which PHP code is an HTTP entry point — read from the routing, not the LSP."""

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
        """The routed method containing this line, if any."""
        needle = file_path.replace("\\", "/").lstrip("./")
        for route in self.routes:
            haystack = route.file_path.replace("\\", "/")
            if not (haystack.endswith(needle) or needle.endswith(haystack)):
                continue
            if route.line <= line <= route.end_line:
                return route
        return None

    def perimeter(self, file_path: str) -> tuple[int, list[str]] | None:
        """How many hops from an HTTP entry point this file sits, and via what."""
        if self._perimeter is None:
            return None
        key = _stem(file_path)
        hop = self._perimeter.get(key)
        if hop is None:
            return None
        return hop, self._perimeter_via.get(key, [])



def _method_spans(lines: list[str]) -> list[tuple[int, int, str]]:
    """(start, end, name) for each method, 1-indexed and inclusive."""
    starts = [(n, m.group(1)) for n, line in enumerate(lines, 1) if (m := _METHOD_DEF.match(line))]
    spans = []
    for i, (start, name) in enumerate(starts):
        end = starts[i + 1][0] - 1 if i + 1 < len(starts) else len(lines)
        spans.append((start, end, name))
    return spans


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
    """`controller: App\\Controller\\Foo::bar` entries in config/routes*."""
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
    """Breadth-first from the routed files outward, over class references."""
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
        for path in root.rglob("*.php"):
            if index.files_scanned >= _MAX_FILES:
                log.warning("route index hit the %d-file budget; reachability may be incomplete", _MAX_FILES)
                break
            if _SKIP_DIRS & set(path.parts):
                continue
            index.files_scanned += 1
            _parse_php(path, index)
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            references[path.stem] = set(_REFERENCED.findall(text)) - {path.stem}
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
