"""Records the pipeline can write without asking the model.

Four cases end a finding before the verdict step: the dependency chain closed
it on a checked fact, the platform owns the misconfiguration, a
misconfiguration has no code to reason about, and a secret is a fact rather
than a judgement. Each builds the same TriageRecord the model path builds, so
a report cannot tell where a decision came from except by `decided_by`.
"""

from __future__ import annotations

from . import calibration as calibration_mod
from . import reuse as reuse_mod
from .models import (
    EvidenceClass,
    EvidenceQuote,
    Finding,
    TriageRecord,
    Verdict,
    VerdictLabel,
    VulnerableSymbol,
)

def dependency_closed(finding: Finding, result, sca, *, provider: str) -> TriageRecord:
    """Closed by the dependency chain on a checked fact, without a verdict call."""
    closure = calibration_mod.calibrate_closure(
        result.decision.verdict.value,
        bool(getattr(result, "audited", False)),
        getattr(result, "audit", ""),
    )
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        kind="dependency",
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=Verdict(
            verdict=VerdictLabel.false_positive,
            evidence_class=EvidenceClass.identifier_only,
            confidence=closure.score,
            confidence_band=closure.band,
            confidence_rationale=(
                f"{'; '.join(closure.reasons)} — {result.decision.headline}."
            ),
            cwe=finding.cwe,
            reason=" ".join([result.decision.headline, *result.decision.reasons[:2]]),
            requires_human_review=closure.band == "low",
        ),
        decided_by="heuristics",
        provider=provider,
        model=None,
        sca=sca,
        trace=list(finding.trace),
    )

def dependency_decided(finding: Finding, result, sca, decision, *, provider: str) -> TriageRecord:
    """Decided by the dependency policy (sca/policy.py) on the chain's facts, without a verdict call.

    `confirmed` here means "an affected version reaches the shipped artifact";
    how urgent that is lives in `sca.priority`, not in the verdict label.
    """
    label = VerdictLabel(decision.label)
    actual = decision.rule == "actual"
    headline = result.decision.headline if result is not None else ""
    reasons = list(result.decision.reasons[:2]) if result is not None else []
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        kind="dependency",
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=Verdict(
            verdict=label,
            evidence_class=(EvidenceClass.exploitable_dataflow if actual else
                            EvidenceClass.insufficient_context if label is VerdictLabel.unknown else
                            EvidenceClass.identifier_only),
            confidence=0.9 if label is not VerdictLabel.unknown else 0.5,
            confidence_band="high" if label is not VerdictLabel.unknown else "low",
            confidence_rationale=(
                "Decided by the dependency policy on checked facts — installed version against the "
                f"advisory ranges, shipping and the chain outcome ({decision.rule}) — without a model call."),
            cwe=finding.cwe,
            reason=" ".join(x for x in [decision.reason, headline, *reasons] if x)[:1500],
            missing_information=([decision.reason] if label is VerdictLabel.unknown else []),
            blocking_question=(decision.reason if label is VerdictLabel.unknown else None),
            requires_human_review=decision.needs_person,
        ),
        decided_by="policy",
        provider=provider,
        model=None,
        sca=sca,
        trace=list(finding.trace),
    )


def platform_handled(finding: Finding, entry, *, provider: str) -> TriageRecord:
    """Closed because the deployment owns the check, with the fact named."""
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        kind="misconfiguration",
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=Verdict(
            verdict=VerdictLabel.false_positive,
            evidence_class=EvidenceClass.identifier_only,
            confidence=0.85,
            confidence_band="high",
            confidence_rationale=(
                f"Closed on a declared deployment fact (`{entry.requires}`), not on inference. "
                "If that declaration is wrong, this verdict is wrong with it."
            ),
            cwe=finding.cwe,
            reason=f"The platform handles this: {entry.why}.",
            requires_human_review=False,
        ),
        decided_by="heuristics",
        provider=provider,
        model=None,
    )

def misconfiguration(finding: Finding, *, provider: str) -> TriageRecord:
    line = (finding.code_context.snippet or "").strip().splitlines()
    verdict = Verdict(
        verdict=VerdictLabel.confirmed,
        evidence_class=EvidenceClass.identifier_only,
        confidence=0.9,
        confidence_band="high",
        confidence_rationale=(
            "The scanner parsed the file and read the directive itself, at very-high precision. "
            "Nothing here rests on inference."
        ),
        cwe=finding.cwe,
        vulnerable_symbol=VulnerableSymbol(
            name=(line[0][:120] if line else (finding.rule_id or "configuration")),
            kind="config_key",
            location=f"{finding.code_context.file_path}:{finding.code_context.start_line or '?'}",
            why=finding.title or "configuration check failed",
        ),
        evidence=[EvidenceQuote(quote=line[0][:200], why="the flagged directive")] if line else [],
        reason=(finding.description or finding.title or "Configuration check failed.").strip()[:1500],
        requires_human_review=False,
    )
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=verdict,
        kind="misconfiguration",
        decided_by="heuristics",
        provider=provider,
        model=None,
    )

def secret(finding: Finding, *, provider: str) -> TriageRecord | None:
    """Decide a credential finding from its value, or hand it over unjudged."""
    from . import secrets as secret_policy

    value = secret_policy.flagged_value(finding.code_context.snippet)
    kind, why = secret_policy.classify(value)
    if kind == "unclear":
        return None

    placeholder = kind == "placeholder"
    line = (finding.code_context.snippet or "").strip().splitlines()
    verdict = Verdict(
        verdict=VerdictLabel.false_positive if placeholder else VerdictLabel.confirmed,
        evidence_class=EvidenceClass.test_placeholder if placeholder else EvidenceClass.secret_value,
        confidence=0.9,
        confidence_band="high",
        confidence_rationale=(
            "Decided from the value itself — length, alphabet and entropy — with no inference "
            "and no model call."
        ),
        cwe=finding.cwe,
        vulnerable_symbol=None
        if placeholder
        else VulnerableSymbol(
            name=(line[0].split("=")[0].strip()[:80] if line else (finding.rule_id or "credential")),
            kind="literal",
            location=f"{finding.code_context.file_path}:{finding.code_context.start_line or '?'}",
            why="a generated credential committed to the repository",
        ),
        evidence=[EvidenceQuote(quote=line[0][:200], why=why)] if line else [],
        reason=(
            why
            if placeholder
            else f"{why}. Whether it is still valid and whether this file is published are the two "
            "facts that set the urgency, and neither can be read from the code — rotate it if in doubt."
        ),
        requires_human_review=not placeholder,
    )
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        severity=finding.severity,
        rule_id=finding.rule_id,
        start_line=finding.code_context.start_line,
        fingerprint=reuse_mod.fingerprint(finding),
        verdict=verdict,
        decided_by="heuristics",
        provider=provider,
        model=None,
    )
