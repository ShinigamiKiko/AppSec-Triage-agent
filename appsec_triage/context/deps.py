"""Two facts about a vulnerable dependency that the scanner does not report.

**Does it ship?** A CVE in PHPUnit is not an attack surface: the package builds
and tests the application and never reaches a server. Scanners do not make the
distinction — on a real project a PHPUnit advisory arrived tagged HIGH — but the
lockfile does, and reading it is cheap and exact.

**Does anything here use it?** A transitive package pulled in by something else
and never imported cannot be reached through our code. This is the SCA analogue
of reachability, and the honest version of it is textual: we look for imports.

Both are deliberately conservative. `dev_only` is only ever set from an explicit
lockfile section, and `imported` is only ever set to False when the lockfile was
readable and the search ran — "we could not tell" stays `None`, because a
missing answer must never read as "safe".
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git", "vendor", "node_modules", "venv", ".venv", "target", "build",
    "dist", "__pycache__", ".idea", ".vscode",
}

_SOURCE_SUFFIXES = {".php", ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".java", ".kt", ".cs"}

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
    """How this package would appear if the code used it.

    Namespace-based for PHP (`Symfony\\Component\\Routing`), literal for the
    module-name ecosystems. Kept loose on purpose: a false "imported" costs a
    review, a false "not imported" hides a reachable vulnerability.
    """
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
        if len(name) >= 3:
            patterns.append(rf"\b{re.escape(name.split('/')[-1])}\b")

    return [re.compile(p, re.IGNORECASE) for p in patterns]


def is_imported(package: str, ecosystem: str | None, roots: list[Path]) -> bool | None:
    """Does any source file here reference the package? None when unanswerable.

    Read the answers asymmetrically. `True` is evidence: the code names the
    package, so our code can reach it. `False` is **not** evidence of the
    opposite — a framework wires plenty of packages through its container and
    they never appear in an import. Measured on a Symfony project, `twig/twig`
    came back False while every rendered template goes through it.

    So callers turn `True` into a signal and `False` into a question.
    """
    patterns = _import_patterns(package, ecosystem)
    if not patterns:
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
            if path.suffix.lower() not in _SOURCE_SUFFIXES:
                continue
            if _SKIP_DIRS & set(path.parts):
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
