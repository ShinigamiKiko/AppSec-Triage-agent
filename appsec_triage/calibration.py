"""Replace the model's self-reported confidence with a measured one."""

from __future__ import annotations

from dataclasses import dataclass, field

from .models import EvidencePackage, Finding, Verdict, VerdictLabel


@dataclass(slots=True)
class Calibration:
    """A computed certainty plus the reasons for it, in the reviewer's words."""

    score: float
    reasons: list[str] = field(default_factory=list)

    @property
    def band(self) -> str:
        if self.score >= 0.75:
            return "high"
        return "medium" if self.score >= 0.5 else "low"


DATAFLOW_CLEARABLE_SIGNALS = {"sql_value_interpolated"}

_BASE = 0.5


def calibrate(verdict: Verdict, pkg: EvidencePackage, finding: Finding, overrides: list[str]) -> Calibration:
    score = _BASE
    reasons: list[str] = []

    grounded = [e for e in verdict.evidence if e.grounded]
    ungrounded = [e for e in verdict.evidence if not e.grounded]
    if grounded:
        score += 0.15 if len(grounded) >= 2 else 0.08
        reasons.append(f"{len(grounded)} quoted line(s) verified verbatim against the input")
    else:
        score -= 0.15
        reasons.append("no quoted line survived the grounding check — the argument rests on assertion")
    if ungrounded:
        score -= 0.1 * min(len(ungrounded), 3)
        reasons.append(f"{len(ungrounded)} cited 'quote(s)' could not be found in the input")

    if verdict.verdict is VerdictLabel.confirmed:
        if any(s.grounded for s in verdict.dataflow):
            score += 0.1
            reasons.append("the reconstructed dataflow is anchored in quoted code")
        elif pkg.trace:
            score += 0.05
            reasons.append("the scanner supplied a source-to-sink trace")

    if finding.corroborated_by:
        score += 0.1
        reasons.append(f"corroborated by {', '.join(finding.corroborated_by)}")

    agreeing = _signal_weight(pkg, verdict, agree=True)
    opposing = _signal_weight(pkg, verdict, agree=False)
    if agreeing:
        score += min(0.15, agreeing * 0.2)
        reasons.append("deterministic pre-checks point the same way")
    if opposing:
        score -= min(0.25, opposing * 0.3)
        reasons.append("deterministic pre-checks point the other way")

    if pkg.code_source == "description_only" and not pkg.repository_code_collected and pkg.dependency is None:
        score = min(score, 0.45)
        reasons.append("no code was available — the verdict rests on the scanner's description alone")
    elif pkg.dependency is not None:
        dep = pkg.dependency
        if dep.installed_version and dep.fixed_versions:
            score += 0.15
            reasons.append("the advisory gave both an installed version and a published fix to compare")
        elif not dep.installed_version:
            score = min(score, 0.5)
            reasons.append("the scanner did not report an installed version, so the range cannot be checked")
    if pkg.lsp_required_missing:
        score = min(score, 0.55)
        reasons.append("the mandatory language server answered nothing for this file")
    if overrides:
        score = min(score, 0.6)
        reasons.append(f"post-validation had to rewrite this verdict ({len(overrides)} override(s))")

    return Calibration(score=max(0.05, min(0.95, round(score, 2))), reasons=reasons)


_CLOSURE_STRENGTH = {
    "version_unaffected": 0.95,
    "not_applicable": 0.90,
    "wrong_receiver": 0.85,
    # A tool compiled the program, or a query traced the data.
    "not_reached": 0.80,
    "condition_absent": 0.75,
    "not_shipped": 0.70,
    "test_only_import": 0.70,
    "unused": 0.60,
    "not_called": 0.60,
    # An operator's statement about the platform, not a property of this code.
    "infrastructure": 0.60,
}

_CLOSURE_EVIDENCE = {
    "version_unaffected": "the installed version lies outside every affected range of the advisory",
    "not_applicable": "the vulnerable path is not inside the installed package",
    "wrong_receiver": "the language server resolved every call site outside the flawed package",
    "not_reached": "a compiled call graph found no path to the vulnerable function",
    "condition_absent": "the condition the advisory requires is not met in this code",
    "not_shipped": "the bill of materials marks the package build-only",
    "test_only_import": "the package is imported only from paths the project lists as tests",
    "unused": "a search of the source tree found no use of the package",
    "not_called": "the language server found no project caller of the vulnerable function",
    "infrastructure": "the declared deployment owns this component, not the service",
}

_AUDIT_GATED = {"not_reached", "unused", "not_shipped", "test_only_import", "wrong_receiver",
                "not_called"}


def calibrate_closure(outcome: str, audited: bool, audit_note: str = "") -> Calibration:
    """Confidence for a finding the dependency chain closed without the model."""
    score = _CLOSURE_STRENGTH.get(outcome, 0.5)
    reasons = ["closed by the dependency chain on a checked fact, without a verdict call"]
    if evidence := _CLOSURE_EVIDENCE.get(outcome):
        reasons.append(evidence)
    if outcome in _AUDIT_GATED:
        if audited:
            score += 0.05
            reasons.append("the audit of this closure's blind spot ran and did not overturn it")
        else:
            score = min(score, 0.45)
            reasons.append(audit_note or "no audit of this closure's blind spot is recorded")
    return Calibration(score=max(0.05, min(0.95, round(score, 2))), reasons=reasons)


def _signal_weight(pkg: EvidencePackage, verdict: Verdict, *, agree: bool) -> float:
    """Total weight of signals pointing with (or against) the verdict."""
    if verdict.verdict is VerdictLabel.unknown:
        return 0.0
    wanted = "toward_confirmed" if verdict.verdict is VerdictLabel.confirmed else "toward_fp"
    other = "toward_fp" if wanted == "toward_confirmed" else "toward_confirmed"
    target = wanted if agree else other
    return sum(
        s.weight
        for s in pkg.heuristic_signals
        if s.direction == target
        and not (pkg.lsp_resolved_clean and s.name in DATAFLOW_CLEARABLE_SIGNALS)
    )
