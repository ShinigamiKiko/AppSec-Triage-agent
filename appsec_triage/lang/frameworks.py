"""What a framework's own configuration says about an advisory precondition.

Each language package brings its detectors (`<language>/frameworks.py`); the
registry that tries them in order is `appsec_triage.lang.detect_framework_condition`.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

from ..fs import SKIP_DIRS


@dataclass(slots=True)
class DetectorResult:
    """What a framework detector found."""
    state: str
    evidence: str = ""
    reason: str = ""
    file: str = ""


def clean_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def project_files(root: Path, suffixes: tuple[str, ...], limit: int,
                  skip: frozenset[str] = frozenset()) -> tuple[list[Path], bool]:
    """The project's own files with these suffixes, and whether the walk saw all of them.

    Installed dependencies, build output and dot-directories (a module cache kept inside
    the checkout, `.nuxt`) are not the project's code: a setting read there is somebody
    else's. A detector that did not see every file may say what it found, never what is absent.
    """
    found: list[Path] = []
    for parent, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS and d not in skip and not d.startswith("."))
        for name in sorted(filenames):
            if not name.lower().endswith(suffixes):
                continue
            if len(found) >= limit:
                return found, False
            found.append(Path(parent) / name)
    return found, True


class FrameworkDetector:
    """Base class for framework-specific configuration readers."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        """Return a decided result, or None when this framework is not present."""
        raise NotImplementedError
