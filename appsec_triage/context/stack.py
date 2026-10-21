"""Detect the frameworks in play, so the model can reason with their conventions."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import REPO_ROOT

log = logging.getLogger(__name__)

STACKS_ROOT = REPO_ROOT / "prompts" / "stacks"
_FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

_MAX_MARKER_BYTES = 400_000
# A project inside the repository counts down to this depth (`services/api/composer.json`);
# installed packages, tests and samples carry manifests that are not the project's own.
_MAX_MARKER_DEPTH = 3
_SKIP_MARKER_DIRS = {".git", "vendor", "node_modules", "var", "dist", "build", "tests", "test",
                     "fixtures", "samples", "examples", "docs"}


def find_marker(roots, files, markers) -> str:
    """`path:line (marker)` of the first manifest among `files` that contains a marker, or ""."""
    names = {str(f) for f in files if str(f)}
    wanted = [str(m) for m in markers if str(m)]
    if not names or not wanted:
        return ""
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        for parent, dirnames, filenames in os.walk(root):
            here = Path(parent)
            depth = len(here.relative_to(root).parts)
            dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_MARKER_DIRS and not d.startswith(".")
                                 and not d.startswith("appsec-out")) if depth < _MAX_MARKER_DEPTH - 1 else []
            for name in sorted(names & set(filenames)):
                path = here / name
                try:
                    if path.stat().st_size > _MAX_MARKER_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for marker in wanted:
                    index = text.find(marker)
                    if index >= 0:
                        line = text.count("\n", 0, index) + 1
                        return f"{path.relative_to(root).as_posix()}:{line} ({marker})"
    return ""


@dataclass(slots=True, frozen=True)
class StackProfile:
    id: str
    version: str
    name: str
    marker_files: tuple[str, ...]
    markers: tuple[str, ...]
    body: str
    path: Path
    where: tuple[tuple[str, tuple[str, ...]], ...] = ()
    """Role -> path patterns, for the project map (`context.project_map`). Not part of `body`:
    the conventions go to every prompt, the map only to the code walk."""
    exclude: tuple[str, ...] = ()
    """`where_exclude`: parts of the tree another stack owns, kept out of this map."""

    def matches(self, root: Path) -> bool:
        return bool(find_marker([root], self.marker_files, self.markers))


def _where(raw) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """`where:` from the front matter as ((role, (pattern, ...)), ...), in file order."""
    if not isinstance(raw, dict):
        return ()
    out = []
    for role, patterns in raw.items():
        if isinstance(patterns, str):
            patterns = [patterns]
        clean = tuple(str(p).strip() for p in (patterns or []) if str(p).strip())
        if clean:
            out.append((str(role).strip(), clean))
    return tuple(out)


def _parse(path: Path) -> StackProfile:
    text = path.read_text(encoding="utf-8")
    m = _FRONT_MATTER.match(text)
    if not m:
        raise ValueError(f"{path}: missing YAML front matter")
    meta = yaml.safe_load(m.group(1)) or {}
    detect = meta.get("detect") or {}
    return StackProfile(
        id=str(meta["id"]),
        version=str(meta.get("version", "1.0")),
        name=str(meta.get("name", meta["id"])),
        marker_files=tuple(detect.get("files") or []),
        markers=tuple(detect.get("contains") or []),
        body=text[m.end():].strip(),
        path=path,
        where=_where(meta.get("where")),
        exclude=tuple(str(p).strip() for p in (meta.get("where_exclude") or []) if str(p).strip()),
    )


def load_all() -> list[StackProfile]:
    if not STACKS_ROOT.is_dir():
        return []
    profiles = []
    for f in sorted(STACKS_ROOT.glob("*.md")):
        try:
            profiles.append(_parse(f))
        except (ValueError, KeyError) as exc:
            log.warning("stack profile %s ignored: %s", f.name, exc)
    return profiles


def detect(roots: list[Path]) -> list[StackProfile]:
    """Which stack profiles apply to these source roots."""
    found: dict[str, StackProfile] = {}
    for profile in load_all():
        for root in roots:
            root = Path(root)
            if root.is_dir() and profile.matches(root):
                found[profile.id] = profile
                break
    return list(found.values())


def render(profiles: list[StackProfile]) -> str:
    """The section appended to the system prompt."""
    if not profiles:
        return ""
    parts = [
        "## Stack conventions",
        "",
        ("The following describes frameworks detected in this repository. Treat it as "
        "**context, not permission**:"),
        "",
        ("- A convention may *explain* evidence you can see — why a placeholder is not a secret, "
        "why a query is parameterised."),
        ("- A convention may never *outrank* evidence. If the code plainly does the dangerous thing, "
        "the convention is being violated, and that is a finding, not a false positive."),
        ("- A deterministic HEURISTIC SIGNAL always wins over a convention. Signals are computed from "
        "this exact code; conventions are general."),
        "",
    ]
    for p in profiles:
        parts.append(f"### {p.name}")
        parts.append("")
        parts.append(p.body)
        parts.append("")
    return "\n".join(parts).strip()
