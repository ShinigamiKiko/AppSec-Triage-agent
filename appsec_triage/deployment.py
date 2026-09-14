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
class OutOfScopeComponent:
    """A component no service on this platform runs, and the fact that says so."""

    id: str
    requires: str
    describe: str = ""
    why: str = ""
    keywords: list[str] = field(default_factory=list)
    markers: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DeploymentContext:
    enabled: bool = False
    description: str = ""
    facts: dict[str, bool] = field(default_factory=dict)
    platform_handles: list[PlatformRule] = field(default_factory=list)
    out_of_scope: list[OutOfScopeComponent] = field(default_factory=list)

    @property
    def usable(self) -> bool:
        return self.enabled and bool(self.description or self.facts)

    def components_out_of_scope(self) -> list[OutOfScopeComponent]:
        """Entries whose fact is set. Like platform rules, a claim nobody confirmed is inert."""
        if not self.enabled:
            return []
        return [c for c in self.out_of_scope if c.requires and self.facts.get(c.requires) is True]

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
            "Use these deployment facts when checking advisory preconditions, exposure,",
            "and priority. They are operator-provided facts, not guesses from conventions.",
            "",
            "- Windows-only issues do not apply to the confirmed Linux container.",
            "- TLS termination at ingress rules out TLS termination at the application",
            "  only when the backend connection is confirmed plaintext; check its config.",
            "- Incoming TLS and outgoing HTTPS, LDAPS, or StartTLS are separate paths.",
            "- Do not confuse HTTP/2 over TLS with unencrypted HTTP/2 (h2c).",
            "- Kubernetes/ingress do not by themselves remove injection, SSRF, auth, or DoS risk.",
            "- A missing or unsearched setting is UNKNOWN, not proof that a feature is disabled.",
            "- To reject a finding, name the advisory precondition and quote the fact that",
            "  contradicts it. If the fact is not established, preserve the finding as unresolved.",
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
    out_of_scope = [
        OutOfScopeComponent(
            id=str(e["id"]), requires=str(e.get("requires") or ""),
            describe=" ".join(str(e.get("describe") or "").split()), why=str(e.get("why") or ""),
            keywords=[str(k) for k in (e.get("keywords") or []) if str(k).strip()],
            markers=[str(m) for m in (e.get("markers") or []) if str(m).strip()],
        )
        for e in (data.get("out_of_scope_components") or [])
        if isinstance(e, dict) and e.get("id")
    ]
    return DeploymentContext(
        enabled=bool(data.get("enabled", False)),
        description=str(data.get("description") or ""),
        facts=facts,
        platform_handles=handles,
        out_of_scope=out_of_scope,
    )
