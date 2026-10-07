"""What a Go program runs without any of its own code calling it: blank imports.

`import _ "net/http/pprof"` names no function, yet the package's `init()` runs on
start — pprof registers its HTTP handlers, a database driver registers itself. A
"no call from the project" closure is wrong for such a package.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

_MAX_FILES = 4000
_MAX_BYTES = 600_000
_BLANK = re.compile(r'''^\s*(?:import\s+)?_\s+"(?P<path>[^"]+)"''', re.M)
_SKIP = {".git", "vendor", "node_modules", "testdata", "build", "dist"}
_REQUIRE = re.compile(r"^\s*(?:require\s+)?(?P<module>[A-Za-z0-9][\w.\-~/]*\.[\w.\-~/]+)\s+v\S+", re.M)


def _modules(root: Path) -> list[str]:
    """Module paths the project requires, longest first."""
    try:
        text = (root / "go.mod").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return sorted({m.group("module") for m in _REQUIRE.finditer(text)}, key=len, reverse=True)


def _module_of(path: str, modules: list[str]) -> str:
    # The standard library is one "package" for advisories: a blank import of one of its
    # packages (`embed` is a compiler directive) would claim the whole of it. Left out.
    if "." not in path.split("/", 1)[0]:
        return ""
    return next((m for m in modules if path == m or path.startswith(m + "/")), "")


def _go_files(root: Path) -> list[Path]:
    """The project's own .go files, vendored and test-data trees skipped."""
    out: list[Path] = []
    for parent, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP and not d.startswith("."))
        out += [Path(parent) / name for name in sorted(filenames) if name.endswith(".go")]
        if len(out) >= _MAX_FILES:
            break
    return out[:_MAX_FILES]


def framework_invoked(root: Path | str) -> dict[str, str]:
    """module -> `file:line: import` of a blank import in first-party, non-test code."""
    root = Path(root)
    modules = _modules(root)
    found: dict[str, str] = {}
    for path in _go_files(root):
        if path.name.endswith("_test.go"):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for match in _BLANK.finditer(text):
            module = _module_of(match.group("path"), modules)
            if module and module.lower() not in found:
                line = text.count("\n", 0, match.start()) + 1
                found[module.lower()] = f'{path.relative_to(root).as_posix()}:{line}: _ "{match.group("path")}"'
    return found
