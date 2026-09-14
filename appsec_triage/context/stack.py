"""Detect the frameworks in play, so the model can reason with their conventions.

The gap this closes is real and was measured: on a Symfony project six of
fifteen `unknown` verdicts were `%env(resolve:DB_PASSWORD)%` — a placeholder the
container resolves at compile time, with no secret anywhere in the repository.
Deterministic signals can flag that pattern, but a signal only says "this is a
template". A model that understands *why* Symfony works that way can also judge
the cases nobody wrote a regex for.

Detection is deliberately dumb: marker files plus a substring. Guessing a stack
wrong is worse than not guessing, so the checks are narrow and a miss simply
means no stack section is added.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from ..config import REPO_ROOT

log = logging.getLogger(__name__)

STACKS_ROOT = REPO_ROOT / "prompts" / "stacks"
_FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)

_MAX_MARKER_BYTES = 400_000


@dataclass(slots=True, frozen=True)
class StackProfile:
    id: str
    version: str
    name: str
    marker_files: tuple[str, ...]
    markers: tuple[str, ...]
    body: str
    path: Path

    def matches(self, root: Path) -> bool:
        for filename in self.marker_files:
            for candidate in (root / filename, *root.glob(f"*/{filename}")):
                if not candidate.is_file():
                    continue
                try:
                    if candidate.stat().st_size > _MAX_MARKER_BYTES:
                        continue
                    text = candidate.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if any(marker in text for marker in self.markers):
                    return True
        return False


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
    """The section appended to the system prompt.

    The framing matters as much as the content: conventions are *context*, and a
    convention must never outrank what the code plainly shows. Without that line
    a stack profile becomes an excuse generator — "Twig escapes by default" would
    start closing findings where the template clearly uses `|raw`.
    """
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
