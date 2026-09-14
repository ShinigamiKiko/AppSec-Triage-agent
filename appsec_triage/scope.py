"""Scope filter — the layer before the layers.

Some findings should not be triaged at all, and that is a policy decision, not a
judgement call for a model. `B101 assert_used` across a test suite is the
    canonical case: a large batch of low-value findings, none of them a question
anyone wants an LLM to answer.

Two rules make this safe rather than a silent hole:

 1. **Nothing disappears.** An excluded finding still produces a TriageRecord,
    marked `decided_by="scope"` with the rule that excluded it. It lands in the
    audit log like everything else.
 2. **Exclusions are explicit and counted.** They come from config, never from
    a heuristic guess, and the summary reports how many were dropped by which
    rule — a filter you cannot see is a filter you cannot review.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field

from .config import ScopeConfig
from .models import EvidenceClass, Finding, TriageRecord, Verdict, VerdictLabel
from .reuse import fingerprint as _fingerprint

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


@dataclass(slots=True)
class ScopeResult:
    kept: list[Finding] = field(default_factory=list)
    excluded: list[TriageRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def _matches(value: str | None, patterns: list[str]) -> str | None:
    """Return the pattern that matched, so the record can name it."""
    if not value:
        return None
    for pat in patterns:
        if fnmatch.fnmatch(value, pat) or re.search(pat, value):
            return pat
    return None


def _excluded_record(finding: Finding, rule: str, why: str) -> TriageRecord:
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        rule_id=finding.rule_id,
        fingerprint=_fingerprint(finding),
        verdict=Verdict(
            verdict=VerdictLabel.false_positive,
            evidence_class=EvidenceClass.test_placeholder,
            confidence=1.0,
            confidence_rationale=(
                "Not a model judgement: this finding is outside the configured triage scope, "
                "so no confidence is being asserted about the code itself."
            ),
            cwe=finding.cwe,
            evidence=[],
            reason=f"Out of triage scope: {why} (rule: {rule})",
            missing_information=[],
            requires_human_review=False,
        ),
        decided_by="scope",
        overrides=[f"scope_excluded: {rule}"],
    )


def apply(findings: list[Finding], cfg: ScopeConfig) -> ScopeResult:
    result = ScopeResult()
    if not cfg.enabled:
        result.kept = list(findings)
        return result

    min_idx = _SEVERITY_ORDER.index(cfg.min_severity) if cfg.min_severity else -1

    for f in findings:
        if pat := _matches(f.rule_id, cfg.exclude_rules):
            result.excluded.append(_excluded_record(f, pat, "rule is excluded from triage"))
            result.counts[f"rule:{pat}"] = result.counts.get(f"rule:{pat}", 0) + 1
            continue
        if pat := _matches(f.code_context.file_path, cfg.exclude_paths):
            result.excluded.append(_excluded_record(f, pat, "path is excluded from triage"))
            result.counts[f"path:{pat}"] = result.counts.get(f"path:{pat}", 0) + 1
            continue
        if cfg.only_cwes and f.cwe not in cfg.only_cwes:
            rule = f"only_cwes={cfg.only_cwes}"
            result.excluded.append(_excluded_record(f, rule, f"CWE {f.cwe} is not in the triaged set"))
            result.counts["cwe_not_in_scope"] = result.counts.get("cwe_not_in_scope", 0) + 1
            continue
        if (
            min_idx >= 0
            and f.severity.value in _SEVERITY_ORDER
            and _SEVERITY_ORDER.index(f.severity.value) < min_idx
        ):
            rule = f"min_severity={cfg.min_severity}"
            result.excluded.append(_excluded_record(f, rule, f"severity {f.severity.value} is below the floor"))
            result.counts["below_min_severity"] = result.counts.get("below_min_severity", 0) + 1
            continue
        result.kept.append(f)

    return result
