"""A package's own source, read from the installed tree and never fetched.

Confirming a symbol and walking the bridge both need the library's code. There
are two ways to get it and only one of them is allowed here: reading what the
package manager already put on disk. Downloading a published archive — even
read-only, even from the official registry — sends the project's dependency
list to a third party and pulls foreign code into the scanning container, and
the scanner is not the place for either.

So this looks in `vendor/`, `node_modules/`, `site-packages/` and the Go module
cache, and when the tree is not there it says so. "Not installed" is a real
answer with real consequences — the symbol cannot be confirmed and the bridge
cannot be walked — and those consequences are reported rather than worked
around.
"""

from __future__ import annotations

import logging
from pathlib import Path

log = logging.getLogger(__name__)

_CODE_SUFFIXES = {".php", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".go", ".java"}
_SKIP_PARTS = {"test", "tests", "spec", "specs", "fixtures", "__tests__", "docs",
               "node_modules"}
_MAX_FILES = 4000
_MAX_BYTES = 400_000

_LAYOUTS: dict[str, tuple[str, ...]] = {
    "composer": ("vendor/{name}",),
    "packagist": ("vendor/{name}",),
    "php": ("vendor/{name}",),
    "npm": ("node_modules/{name}",),
    "node": ("node_modules/{name}",),
    "javascript": ("node_modules/{name}",),
    "pypi": ("{venv}/lib/python*/site-packages/{flat}",
             ".venv/lib/python*/site-packages/{flat}",
             "venv/lib/python*/site-packages/{flat}"),
    "python": ("{venv}/lib/python*/site-packages/{flat}",
               ".venv/lib/python*/site-packages/{flat}"),
    "go": ("vendor/{name}",),
    "golang": ("vendor/{name}",),
}


def supported(ecosystem: str | None) -> bool:
    return (ecosystem or "").strip().lower() in _LAYOUTS


def _interesting(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & _SKIP_PARTS:
        return False
    return path.suffix.lower() in _CODE_SUFFIXES


def locate(root: Path | str, ecosystem: str | None, name: str) -> Path | None:
    """The installed directory for one package, or None when it is not there."""
    key = (ecosystem or "").strip().lower()
    patterns = _LAYOUTS.get(key)
    if not patterns or not name:
        return None

    root = Path(root)
    flat = name.replace("-", "_").lower()
    for pattern in patterns:
        template = pattern.format(name=name, flat=flat, venv=".venv")
        if "*" in template:
            for candidate in sorted(root.glob(template)):
                if candidate.is_dir():
                    return candidate
            continue
        candidate = root / template
        if candidate.is_dir():
            return candidate
    return None


def package_source(
    ecosystem: str | None, name: str, version: str = "", root: Path | str | None = None
) -> dict[str, str]:
    """`{path: text}` for an installed package, or empty when it is not installed.

    Empty is a normal outcome and must be treated as "could not check", never as
    "the symbol is not there" — the difference is the whole point of reading the
    tree rather than guessing at it.
    """
    if root is None:
        return {}
    directory = locate(root, ecosystem, name)
    if directory is None:
        log.debug("%s %s is not installed under %s", ecosystem, name, root)
        return {}

    files: dict[str, str] = {}
    for path in directory.rglob("*"):
        if len(files) >= _MAX_FILES:
            log.debug("stopped reading %s at %d files", directory, _MAX_FILES)
            break
        if not path.is_file() or not _interesting(path.relative_to(directory)):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            files[str(path.relative_to(directory))] = path.read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            continue
    return files
