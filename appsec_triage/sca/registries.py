"""A package's own source, read from the installed tree and never fetched."""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path

log = logging.getLogger(__name__)

_CODE_SUFFIXES = {".php", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".go", ".java"}
_SKIP_PARTS = {"test", "tests", "spec", "specs", "fixtures", "__tests__", "docs",
               "node_modules"}
_MAX_FILES = 4000
_MAX_BYTES = 400_000

_LAYOUTS: dict[str, tuple] = {
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
    # Vendor first: a project that vendors its modules is the stronger answer.
    "go": ("vendor/{name}", lambda name, version: _go_module_cache_dir(name, version)),
    "golang": ("vendor/{name}", lambda name, version: _go_module_cache_dir(name, version)),
}


def supported(ecosystem: str | None) -> bool:
    return (ecosystem or "").strip().lower() in _LAYOUTS


def _interesting(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & _SKIP_PARTS:
        return False
    return path.suffix.lower() in _CODE_SUFFIXES


def _escape_go_module(name: str) -> str:
    """Go's module-cache spelling: an upper-case letter becomes `!` + its lower."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)


def _go_module_cache_dir(name: str, version: str) -> Path | None:
    """The versioned source directory Go already unpacked, or None."""
    if not version:
        return None
    cache = os.environ.get("GOMODCACHE") or str(Path.home() / "go" / "pkg" / "mod")
    ver = version if version.startswith("v") else f"v{version}"
    candidate = Path(cache) / f"{_escape_go_module(name)}@{ver}"
    return candidate if candidate.is_dir() else None


def locate(root: Path | str, ecosystem: str | None, name: str,
           version: str = "") -> Path | None:
    """The installed directory for one package, or None when it is not there."""
    key = (ecosystem or "").strip().lower()
    patterns = _LAYOUTS.get(key)
    if not patterns or not name:
        return None

    root = Path(root)
    flat = name.replace("-", "_").lower()
    for pattern in patterns:
        if callable(pattern):
            found = pattern(name, version)
            if found is not None:
                return found
            continue
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
    """`{path: text}` for an installed package, or empty when it is not installed."""
    if root is None:
        return {}
    directory = locate(root, ecosystem, name, version)
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
