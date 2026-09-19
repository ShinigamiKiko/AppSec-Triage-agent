"""Which scanners to run against a tree, decided by the languages in it."""

from __future__ import annotations

import sys
from pathlib import Path

from . import probe_all


def usable_scanners() -> list[str]:
    return [n for n, a in probe_all().items() if a.usable]


_LANG_SCANNERS = {
    ".php": ["psalm"],
    ".phtml": ["psalm"], ".inc": ["psalm"],
    ".php3": ["psalm"], ".php4": ["psalm"], ".php5": ["psalm"],
    ".php7": ["psalm"], ".php8": ["psalm"],
    ".go":  ["codeql"],
    ".ts": ["codeql"], ".tsx": ["codeql"],
    ".js": ["codeql"], ".jsx": ["codeql"],
    ".py": ["codeql"],
    ".java": ["codeql"], ".kt": ["codeql"],
    ".rb": ["codeql"], ".cs": ["codeql"],
    ".c": ["codeql"], ".h": ["codeql"],
    ".cc": ["codeql"], ".cp": ["codeql"], ".cpp": ["codeql"],
    ".cxx": ["codeql"], ".c++": ["codeql"],
    ".rs": ["codeql"], ".swift": ["codeql"],
}
_ALWAYS_SCANNERS = ["wolfee"]
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "vendor", "target", "build", "dist", "__pycache__"}


def scanners_for_target(target: Path) -> list[str]:
    """Pick scanners by the languages actually present, then keep only usable ones."""
    wanted: list[str] = []
    seen_ext: set[str] = set()
    for path in Path(target).rglob("*"):
        if not path.is_file() or _SKIP_DIRS & set(path.parts):
            continue
        ext = path.suffix.lower()
        if ext in _LANG_SCANNERS and ext not in seen_ext:
            seen_ext.add(ext)
            for s in _LANG_SCANNERS[ext]:
                if s not in wanted:
                    wanted.append(s)
    wanted += [s for s in _ALWAYS_SCANNERS if s not in wanted]

    usable = set(usable_scanners())
    chosen = [s for s in wanted if s in usable]
    skipped = [s for s in wanted if s not in usable]
    if skipped:
        print(f"→ language-relevant but unavailable: {', '.join(skipped)} "
              "(run `appsec-triage doctor`)", file=sys.stderr)
    return chosen if seen_ext or chosen else sorted(usable)
