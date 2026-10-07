"""Which scanners to run against a tree, decided by the languages in it."""

from __future__ import annotations

import sys
from pathlib import Path

from . import probe_all


# Order is run order: on PHP code Opengrep's quick pass comes first, then Psalm.
_PHP = ["opengrep", "psalm"]
_LANG_SCANNERS = {
    ".php": _PHP,
    ".phtml": _PHP, ".inc": _PHP,
    ".php3": _PHP, ".php4": _PHP, ".php5": _PHP,
    ".php7": _PHP, ".php8": _PHP,
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

    probed = probe_all()
    usable = {n for n, a in probed.items() if a.usable}
    chosen = [s for s in wanted if s in usable]
    # A scanner the languages call for and that will not run: its own line, with the reason.
    for s in wanted:
        if s not in usable:
            print(f"  ✗ {s:<10} не запущен: {probed.get(s, 'нет в реестре')}", file=sys.stderr)
    return chosen if seen_ext or chosen else sorted(usable)
