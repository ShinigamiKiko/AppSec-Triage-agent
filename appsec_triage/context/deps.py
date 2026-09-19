"""Two facts about a vulnerable dependency that the scanner does not report."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

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
        if key in self.dev_only:
            return True
        if key in self.production:
            return False
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
        name = package.lstrip("@")
        patterns.append(rf"""["'`]{re.escape(package)}(?:/[^"'`]*)?["'`]""")

    return [re.compile(p, re.IGNORECASE) for p in patterns]


def is_imported(package: str, ecosystem: str | None, roots: list[Path]) -> bool | None:
    """Does any source file here reference the package?"""
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
        for path in root.rglob("*"):
            if scanned >= _MAX_FILES:
                log.debug("import search for %s hit the file budget", package)
                return None
            if path.suffix.lower() not in suffixes:
                continue
            if _skip_path(path):
                continue
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            if any(p.search(text) for p in patterns):
                return True
    return False if scanned else None
