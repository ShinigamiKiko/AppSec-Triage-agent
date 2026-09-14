"""A component the platform does not run closes a CVE before anything looks for it.

Some flaws live in a part of a library only one kind of program uses. An
authorization bypass in `ssh.ServerConfig.PublicKeyCallback` needs the
application to accept SSH connections; a service in a Kubernetes pod, reached
through an ingress and `kubectl exec`, accepts none. When the operator declares
that as a fact of the platform, searching the code and asking CodeQL about such
a CVE spends minutes confirming a decision already made.

So the question is asked first, and split the usual way. The operator's fact
decides — it is written in `deployment.yaml`, next to its reason. The model only
says whether this advisory needs that component, with a sentence of the advisory
quoted verbatim: a flaw that also reaches clients, or one the text does not tie
to the component, is not excluded. A keyword filter keeps the question away from
advisories that never mention the component at all.

The code is still searched for the component. A server found in a service the
operator says runs none does not reopen the finding — that call belongs to the
operator — but it goes into the report as an anti-pattern, with the line, so the
exception is visible instead of silently covered.
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from ..prompts import registry
from .verdict import CVEDecision, CVEVerdict

log = logging.getLogger(__name__)

SYSTEM = registry.step("component")

_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["component", "quote", "why"],
    "properties": {
        "component": {"type": "string"},
        "quote": {"type": "string"},
        "why": {"type": "string"},
    },
}

_SKIP_DIRS = {".git", "vendor", "node_modules", "venv", ".venv", "target", "build", "dist", "__pycache__"}
_MARKER_SUFFIXES = {".go", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".java", ".kt", ".php", ".cs",
                    ".yaml", ".yml", ".json", ".toml", ".conf", ".sh"}
_MAX_FILES = 8000
_MAX_BYTES = 600_000
_MAX_MARKERS = 5


def _normalized(text: str) -> str:
    return " ".join((text or "").split())


@dataclass(slots=True)
class Exclusion:
    """The component this CVE needs, the advisory's words for it, and any sign of it in the code."""

    component: object
    quote: str
    why: str = ""
    markers: list[str] = field(default_factory=list)

    def render(self) -> str:
        head = (f"вне платформы: {self.component.why} (факт среды {self.component.requires}); "
                f"advisory: «{self.quote[:160]}»")
        if not self.markers:
            return head
        return (f"{head}. АНТИПАТТЕРН: в проекте есть признаки компонента, который платформа "
                f"не запускает — {', '.join(self.markers)}")

    def decision(self) -> CVEDecision:
        reasons = [f"advisory требует компонент «{self.component.id}»: «{self.quote[:200]}»",
                   f"по факту среды {self.component.requires}: {self.component.why}",
                   "закрыто по заявленному факту платформы, до поиска в коде и до CodeQL"]
        if self.why:
            reasons.insert(1, self.why)
        if self.markers:
            reasons.append("антипаттерн — компонент всё же найден в проекте: " + ", ".join(self.markers))
        return CVEDecision(CVEVerdict.CONDITION_ABSENT,
                           f"к сервису не относится: {self.component.why}", reasons, list(self.markers))


def candidates(advisory, deployment) -> list:
    """Components in effect whose keyword the advisory mentions."""
    active = getattr(deployment, "components_out_of_scope", None)
    if active is None:
        return []
    text = "\n".join([advisory.summary or "", advisory.details or "", " ".join(advisory.symbols or [])])
    return [
        component for component in active()
        if not component.keywords or any(
            re.search(rf"(?<![\w]){re.escape(keyword)}(?![\w])", text, re.IGNORECASE)
            for keyword in component.keywords)
    ]


def markers_in(roots, markers: list[str]) -> list[str]:
    """`file:line (marker)` for the first marker in each file, bounded."""
    wanted = [m for m in markers if m]
    hits: list[str] = []
    if not wanted:
        return hits
    for root in roots:
        root = Path(root)
        visited = 0
        # Pruned during the walk: filtering after `rglob` still enumerated all of
        # node_modules/ and vendor/, and the file limit never counted them.
        for parent, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for name in filenames:
                visited += 1
                if len(hits) >= _MAX_MARKERS or visited > _MAX_FILES:
                    break
                path = Path(parent) / name
                if (path.suffix.lower() not in _MARKER_SUFFIXES
                        and not name.lower().startswith(("dockerfile", "containerfile"))):
                    continue
                try:
                    if path.stat().st_size > _MAX_BYTES:
                        continue
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                for marker in wanted:
                    index = text.find(marker)
                    if index >= 0:
                        relative = path.relative_to(root).as_posix()
                        hits.append(f"{relative}:{text.count(chr(10), 0, index) + 1} ({marker})")
                        break
            if len(hits) >= _MAX_MARKERS or visited > _MAX_FILES:
                break
    return hits


def classify(advisory, deployment, client, roots) -> Exclusion | None:
    """The out-of-scope component this CVE needs, or None to analyse it normally."""
    if client is None:
        return None
    found = candidates(advisory, deployment)
    if not found:
        return None

    advisory_text = "\n".join(part for part in (advisory.summary, advisory.details) if part)
    symbols = ", ".join(advisory.symbols or [])
    material = "\n".join([
        f"Advisory: {advisory.advisory_id}",
        f"Package: {advisory.package} ({advisory.ecosystem})",
        "=== ADVISORY TEXT ===", advisory_text[:6000] or "(нет текста)",
        *(["=== VULNERABLE SYMBOLS (from the vulnerability database) ===", symbols] if symbols else []),
        "", "=== COMPONENTS THE PLATFORM DOES NOT RUN ===",
        *(f"- {component.id}: {component.describe}" for component in found),
    ])
    try:
        answer = json.loads(client.complete(SYSTEM, material, json_schema=_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - a failed question leaves the finding to the normal chain
        log.warning("component question failed for %s: %s", advisory.advisory_id, exc)
        return None

    chosen = str(answer.get("component") or "").strip()
    component = next((c for c in found if c.id == chosen), None)
    if component is None:
        return None
    quote = str(answer.get("quote") or "").strip()
    if not quote or _normalized(quote) not in _normalized(f"{advisory_text}\n{symbols}"):
        log.info("discarding ungrounded component answer for %s", advisory.advisory_id)
        return None
    return Exclusion(component, quote, str(answer.get("why") or "").strip()[:300],
                     markers_in(roots, component.markers))
