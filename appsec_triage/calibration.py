"""Replace the model's self-reported confidence with a measured one.

Measured on a real run: every one of 14 decided verdicts came back at 0.95 or
above. A number that never varies carries no information, and it was being used
for two real decisions — the post-validation floor and the ordering of the review
queue. Both were effectively no-ops that looked like controls.

This is not a flaw in the prompt to be fixed by asking harder. A model asked how
sure it is answers from the same context that produced the answer; there is no
independent second look inside a single generation. So the number is computed
here instead, from facts nothing in the generation can fake:

* how much of the model's own evidence survived the verbatim grounding check
* whether a second scanner reported the same weakness
* whether a resolver or a scanner trace actually established the dataflow
* whether the deterministic signals agree with the verdict or contradict it
* whether the model was working from code at all

The model's own number is kept — it goes to the report as
`self_reported_confidence`, so a reviewer can see the gap — but it no longer
decides anything.

Direction matters here: the score is a **downgrade** instrument. It starts from
the evidence actually present and only rises with corroboration, so a thin
verdict cannot inherit certainty from an assertive tone.
"""

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


def _signal_weight(pkg: EvidencePackage, verdict: Verdict, *, agree: bool) -> float:
    """Total weight of signals pointing with (or against) the verdict.

    `unknown` has no direction to agree with, so it scores neither way — an
    abstention is not made more certain by evidence it declined to weigh.
    """
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
