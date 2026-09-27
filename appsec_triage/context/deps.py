"""Two facts about a vulnerable dependency that the scanner does not report."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path

from .. import sourcetext
from .detection import get_source_suffixes

log = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git", "vendor", "node_modules", "venv", ".venv", "target", "build",
    "dist", "__pycache__", ".idea", ".vscode",
}


def _skip_path(path: Path) -> bool:
    """Do not treat generated triage output as first-party source."""
    return bool(_SKIP_DIRS & set(path.parts)) or any(
        part.lower().startswith("appsec-out") for part in path.parts
    )

_MAX_FILES = 4000
_MAX_BYTES = 400_000


@dataclass(slots=True)
class DependencyIndex:
    """Lockfile facts for one project, read once per run."""

    dev_only: set[str] = field(default_factory=set)
    production: set[str] = field(default_factory=set)
    lockfiles_read: list[str] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return bool(self.dev_only or self.production)

    def is_dev_only(self, package: str) -> bool | None:
        key = package.strip().lower()
        if not self.usable:
            return None
        if key in self.production:
            return False
        if key in self.dev_only:
            return True
        return None


def _composer(path: Path, index: DependencyIndex) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for name in (p.get("name") for p in data.get("packages") or []):
        if name:
            index.production.add(name.lower())
    for name in (p.get("name") for p in data.get("packages-dev") or []):
        if name:
            index.dev_only.add(name.lower())


def _package_lock(path: Path, index: DependencyIndex) -> None:
    data = json.loads(path.read_text(encoding="utf-8"))
    for key, meta in (data.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue
        name = meta.get("name") or key.split("node_modules/")[-1]
        if not name:
            continue
        (index.dev_only if meta.get("dev") else index.production).add(name.lower())
    for name, meta in (data.get("dependencies") or {}).items():
        if isinstance(meta, dict):
            (index.dev_only if meta.get("dev") else index.production).add(name.lower())


def _manifests(path: Path, index: DependencyIndex) -> None:
    """What the project itself declares — the only source when the lock file is
    one nothing here parses (yarn.lock, pnpm-lock.yaml). It covers direct
    dependencies only, and a package named in both halves counts as shipped."""
    from ..sca.graph import declared_dependencies

    declared = declared_dependencies(path)
    if declared is None:
        return
    prod, dev = declared
    index.production.update(prod)
    index.dev_only.update(dev - prod)


_READERS = {"composer.lock": _composer, "package-lock.json": _package_lock}


def build_index(roots: list[Path]) -> DependencyIndex:
    index = DependencyIndex()
    for root in roots:
        root = Path(root)
        for name, reader in _READERS.items():
            path = root / name
            if not path.is_file():
                continue
            try:
                reader(path, index)
                index.lockfiles_read.append(str(path))
            except (OSError, json.JSONDecodeError, KeyError) as exc:
                log.warning("cannot read %s: %s — dev/production split unavailable", path, exc)
        try:
            before = len(index.production) + len(index.dev_only)
            _manifests(root, index)
            if len(index.production) + len(index.dev_only) > before:
                index.lockfiles_read.append(f"{root} (манифесты)")
        except (OSError, ValueError) as exc:
            log.warning("cannot read manifests under %s: %s", root, exc)
    return index


def _import_patterns(package: str, ecosystem: str | None) -> list[re.Pattern[str]]:
    """How this package would appear if the code used it."""
    vendor, _, short = package.partition("/")
    patterns: list[str] = []

    if ecosystem == "packagist" or (ecosystem is None and "/" in package):
        for part in (vendor, short.replace("-", "")):
            if len(part) >= 3:
                patterns.append(rf"\\{re.escape(part)}\\")
                patterns.append(rf"use\s+{re.escape(part)}\b")
        patterns.append(re.escape(package))
    else:
        patterns.append(rf"""["'`]{re.escape(package)}(?:/[^"'`]*)?["'`]""")

    return [re.compile(p, re.IGNORECASE) for p in patterns]


# Asked for every dependency finding, and the answer depends only on the package and
# the tree: each ask walked the whole tree — vendor/ with it — and read the project again.
_IMPORTED: dict[tuple, bool | None] = {}
_SOURCE_LISTS: dict[tuple[str, frozenset], list[Path]] = {}
_CACHE_LOCK = threading.Lock()


def _source_paths(root: Path, suffixes: set[str]) -> list[Path]:
    """Files of these types under the root, in walk order, listed once per run."""
    key = (str(root), frozenset(suffixes))
    with _CACHE_LOCK:
        cached = _SOURCE_LISTS.get(key)
    if cached is None:
        cached = []
        for directory, dirs, names in os.walk(root):
            dirs[:] = sorted(d for d in dirs if not _skip_path(Path(directory) / d))
            for name in sorted(names):
                path = Path(directory) / name
                if path.suffix.lower() in suffixes and not _skip_path(path) and path.is_file():
                    cached.append(path)
        with _CACHE_LOCK:
            cached = _SOURCE_LISTS.setdefault(key, cached)
    return cached


def is_imported(package: str, ecosystem: str | None, roots: list[Path]) -> bool | None:
    """Does any source file here reference the package?"""
    key = (package, ecosystem, tuple(str(r) for r in roots))
    with _CACHE_LOCK:
        if key in _IMPORTED:
            return _IMPORTED[key]
    answer = _is_imported(package, ecosystem, roots)
    with _CACHE_LOCK:
        _IMPORTED[key] = answer
    return answer


def _is_imported(package: str, ecosystem: str | None, roots: list[Path]) -> bool | None:
    patterns = _import_patterns(package, ecosystem)
    if not patterns:
        return None
    
    try:
        suffixes = get_source_suffixes(roots, for_ecosystem=ecosystem)
    except Exception as exc:
        log.warning("Cannot determine suffixes for %s: %s", ecosystem, exc)
        return None

    scanned = 0
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for path in _source_paths(root, suffixes):
            if scanned >= _MAX_FILES:
                log.debug("import search for %s hit the file budget", package)
                return None
            text = sourcetext.read(path, _MAX_BYTES)
            if text is None:
                continue
            scanned += 1
            if any(p.search(text) for p in patterns):
                return True
    return False if scanned else None
