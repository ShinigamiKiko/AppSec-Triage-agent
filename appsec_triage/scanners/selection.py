"""Which scanners to run against a tree, decided by the languages in it.

Lives with the scanners rather than in the CLI: the routing rule is a fact
about the tools, not about how a command line is parsed. The CLI asks the
question; this answers it.
"""

from __future__ import annotations

import sys
from pathlib import Path

from . import probe_all


def usable_scanners() -> list[str]:
    return [n for n, a in probe_all().items() if a.usable]


_LANG_SCANNERS = {
    ".php": ["semgrep", "psalm"],
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
_ALWAYS_SCANNERS = ["gitleaks", "trivy"]
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "vendor", "target", "build", "dist", "__pycache__"}


def scanners_for_target(target: Path) -> list[str]:
    """Pick scanners by the languages actually present, then keep only usable ones.

    This is what makes a PHP target run semgrep+Psalm and a Go target run
    CodeQL, without the operator having to know which tool covers which
    language. Falls back to every usable scanner when nothing is recognised —
    a strange tree should still get looked at, not silently skipped.
    """
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
    if chosen:
        skipped = [s for s in wanted if s not in usable]
        if skipped:
            print(f"→ language-relevant but unavailable: {', '.join(skipped)} "
                  "(run `appsec-triage doctor`)", file=sys.stderr)
        return chosen
    return sorted(usable)
