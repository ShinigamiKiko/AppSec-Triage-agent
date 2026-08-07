"""Where the application actually runs, and what that is allowed to change.

A finding is judged against a deployment, not against an abstract program. An
app behind a Kubernetes ingress genuinely does not need a `HEALTHCHECK` in its
image, because the kubelet probes it — that check is not about the application
at all. Withholding that fact makes the tool report things the team has already
solved, which is how a security tool loses its audience.

The danger is the same fact used one step too far. "We are behind an ingress"
is not a reason to close a SQL injection: the ingress passes the request
through. So the split is deliberate and enforced in two different places:

* **Platform-handled rules** — a small, explicit list where the check is about
  infrastructure the platform owns. These close deterministically, and each
  entry must name the fact it rests on, so the list cannot quietly become a
  bucket of exceptions.
* **Everything else** — the description reaches the model as *context*, framed
  as something that changes priority and answers exposure questions, and
  explicitly barred from closing a dataflow finding.

An empty or missing config is normal and means "no claims made".
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

DEFAULT_PATH = Path("configs/deployment.yaml")


@dataclass(slots=True)
class PlatformRule:
    rule: str
    requires: str
    why: str


@dataclass(slots=True)
class CompensatingControl:
    """An external security control with bounded, machine-matchable coverage."""

    id: str
    kind: str
    direction: str = "inbound"
    covered_cwes: list[str] = field(default_factory=list)
    covered_routes: list[str] = field(default_factory=list)
    covered_rules: list[str] = field(default_factory=list)
    covered_paths: list[str] = field(default_factory=list)
    evidence: str = ""
    verified: bool = False
    bypass_possible: bool = True

    def matches(self, finding, route: str | None = None) -> bool:
        """Match every declared selector; an empty selector set proves nothing."""
        if not self.verified or self.bypass_possible or not self.evidence:
            return False
        selectors = (
            self.covered_cwes,
            self.covered_routes,
            self.covered_rules,
            self.covered_paths,
        )
        if not any(selectors):
            return False
        if not (self.covered_cwes or self.covered_rules):
            return False
        if self.direction == "inbound" and not self.covered_routes:
            return False
        cwe = (finding.cwe or "").upper()
        rule = finding.rule_id or ""
        path = finding.code_context.file_path.replace("\\", "/")
        if self.covered_cwes and cwe not in {value.upper() for value in self.covered_cwes}:
            return False
        if self.covered_rules and not any(fnmatch(rule, pattern) for pattern in self.covered_rules):
            return False
        if self.covered_paths and not any(fnmatch(path, pattern) for pattern in self.covered_paths):
            return False
        if self.covered_routes:
            if route is None and "*" not in self.covered_routes:
                return False
            if route is not None and not any(fnmatch(route, pattern) for pattern in self.covered_routes):
                return False
        return True

    def as_evidence(self, route: str | None = None):
        from .models import ExternalControlEvidence

        coverage = []
        if self.covered_cwes:
            coverage.append(f"CWE: {', '.join(self.covered_cwes)}")
        if self.covered_routes:
            coverage.append(f"routes: {', '.join(self.covered_routes)}")
        if self.covered_rules:
            coverage.append(f"rules: {', '.join(self.covered_rules)}")
        if self.covered_paths:
            coverage.append(f"paths: {', '.join(self.covered_paths)}")
        if route:
            coverage.append(f"matched route: {route}")
        return ExternalControlEvidence(
            control_id=self.id,
            kind=self.kind,
            direction=self.direction,
            coverage="; ".join(coverage),
            evidence=self.evidence,
            bypass_precluded=not self.bypass_possible,
        )


@dataclass(slots=True)
class DeploymentContext:
    enabled: bool = False
    description: str = ""
    facts: dict[str, bool] = field(default_factory=dict)
    platform_handles: list[PlatformRule] = field(default_factory=list)
    compensating_controls: list[CompensatingControl] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.enabled and bool(self.description or self.facts or self.compensating_controls)

    def handled_by_platform(self, rule_id: str | None) -> PlatformRule | None:
        """The entry covering this rule, if its supporting fact is actually set.

        Both halves are required. An entry whose fact is absent or false is
        inert — the list describes what the platform does, and a claim nobody
        confirmed does not get to close a finding.
        """
        if not rule_id or not self.enabled:
            return None
        for entry in self.platform_handles:
            if entry.rule.lower() in rule_id.lower() and self.facts.get(entry.requires) is True:
                return entry
        return None

    def matching_controls(self, finding, route: str | None = None):
        """Controls that are verified, non-bypassable and cover this exact finding."""
        if not self.enabled:
            return []
        return [control.as_evidence(route) for control in self.compensating_controls if control.matches(finding, route)]

    def render(self) -> str:
        """The section the model sees. Last in the prompt, and framed as context."""
        if not self.usable:
            return ""
        lines = [
            "## Where this runs",
            "",
            self.description.strip(),
            "",
        ]
        stated = [name for name, value in self.facts.items() if value is True]
        if stated:
            lines += ["Confirmed about the environment:", *(f"- {name.replace('_', ' ')}" for name in stated), ""]
        lines += [
            "Use this for **priority and exposure**, and for nothing else.",
            "",
            "- It answers 'is this reachable from the internet' and 'who terminates TLS'.",
            "- It does **not** close an injection, a traversal, a deserialization or any other",
            "  dataflow finding. A request that arrives through an ingress is still a request,",
            "  and the payload inside it is unchanged by how it got there.",
            "- It does **not** make a committed credential safe. A key in the repository has",
            "  leaked even if the running system reads its value from elsewhere.",
            "- If a verdict depends on one of these facts, say which one in `reason`, so a",
            "  reviewer can check the claim against the manifests.",
        ]
        if self.compensating_controls:
            lines += [
                "",
                "Declared compensating controls are not generic infrastructure claims. Only controls",
                "listed in the finding evidence with matching route/CWE coverage and no known bypass",
                "may support `external_fp`.",
            ]
        return "\n".join(lines)


def load(path: Path | None = None) -> DeploymentContext:
    path = Path(path or DEFAULT_PATH)
    if not path.is_file():
        return DeploymentContext()
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as exc:
        log.warning("cannot read %s: %s — deployment context unavailable", path, exc)
        return DeploymentContext()

    facts = {k: v for k, v in (data.get("facts") or {}).items() if isinstance(v, bool)}
    handles = [
        PlatformRule(rule=str(e["rule"]), requires=str(e.get("requires", "")), why=str(e.get("why", "")))
        for e in (data.get("platform_handles") or [])
        if isinstance(e, dict) and e.get("rule")
    ]
    controls = []
    for entry in data.get("compensating_controls") or []:
        if not isinstance(entry, dict) or not entry.get("id") or not entry.get("kind"):
            continue
        direction = str(entry.get("direction") or "inbound")
        if direction not in {"inbound", "outbound", "bidirectional"}:
            log.warning("ignoring compensating control %s with invalid direction %s", entry.get("id"), direction)
            continue
        controls.append(
            CompensatingControl(
                id=str(entry["id"]),
                kind=str(entry["kind"]),
                direction=direction,
                covered_cwes=[str(v) for v in entry.get("covered_cwes") or []],
                covered_routes=[str(v) for v in entry.get("covered_routes") or []],
                covered_rules=[str(v) for v in entry.get("covered_rules") or []],
                covered_paths=[str(v) for v in entry.get("covered_paths") or []],
                evidence=str(entry.get("evidence") or ""),
                verified=entry.get("verified") is True,
                bypass_possible=entry.get("bypass_possible") is not False,
            )
        )
    return DeploymentContext(
        enabled=bool(data.get("enabled", False)),
        description=str(data.get("description") or ""),
        facts=facts,
        platform_handles=handles,
        compensating_controls=controls,
    )
