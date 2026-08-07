"""Turning verdicts into a review queue an engineer can actually finish.

Triage answers "is this real". Prioritisation answers "what do I open first, and
what can wait" — a different question, and the one that decides whether the tool
saves anyone time.

Three mechanisms, in order of how much work they remove:

1. **Clustering.** 59 of one rule firing across a codebase is one decision, not
   59. Reviewing a representative and applying the call to its cluster is by far
   the biggest lever — bigger than any model improvement.
2. **Scoring.** Rank by *risk*, not by the scanner's severity field. A weak hash
   guarding a cache key and a weak hash guarding a signature are both `WARNING`
   to Semgrep and are not remotely the same thing.
3. **Budget.** Take the top N% and mark the rest deferred.

The safety rule that makes the budget honest: **nothing is deleted or hidden.**
Deferred items stay in the report and in the audit log, and a small set of
conditions is exempt from the budget entirely — a live-credential shape or a
self-contradicting verdict is cheap to check and expensive to miss. If those
exemptions alone exceed the budget, the queue overflows and says so rather than
quietly dropping them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import TriageQueueConfig
from .consequence import CWE_WEIGHT as _CWE_WEIGHT, DEFAULT_WEIGHT as _DEFAULT_CWE_WEIGHT
from .models import Finding, Priority, RiskContext, Severity, TriageRecord, VerdictLabel

_SEVERITY_WEIGHT = {"critical": 12, "high": 9, "medium": 5, "low": 2, "info": 0, "unknown": 4}

_EXPLOITABILITY_WEIGHT = {"trivial": 8, "moderate": 3, "difficult": 0}
_IMPACT_WEIGHT = {"critical": 8, "high": 5, "medium": 2, "low": 0}

_ALWAYS_REVIEW_SIGNALS = {"known_secret_shape", "tls_validation_disabled"}
_ALWAYS_REVIEW_OVERRIDES = ("contradictory_rationale", "sanity_conflict")

_NORMALIZE = [
    (re.compile(r"""(["'])(?:\\.|(?!\1).)*\1"""), "S"),
    (re.compile(r"\b\d+\b"), "N"),
    (re.compile(r"\$\w+"), "V"),
    (re.compile(r"\b[A-Za-z_]\w*\b"), "I"),
    (re.compile(r"\s+"), ""),
]


@dataclass(slots=True)
class QueueItem:
    """One decision for a human, standing for a whole cluster of findings."""

    record: TriageRecord
    score: int
    priority: Priority
    reasons: list[str] = field(default_factory=list)
    cluster: list[TriageRecord] = field(default_factory=list)
    deferred: bool = False
    exempt: bool = False

    @property
    def cluster_size(self) -> int:
        return 1 + len(self.cluster)

    @property
    def all_records(self) -> list[TriageRecord]:
        return [self.record, *self.cluster]

    def as_dict(self) -> dict:
        return {
            "finding_id": self.record.finding_id,
            "score": self.score,
            "priority": self.priority.value,
            "deferred": self.deferred,
            "exempt_from_budget": self.exempt,
            "cluster_size": self.cluster_size,
            "cwe": self.record.cwe,
            "rule_id": self.record.rule_id,
            "verdict": self.record.verdict.verdict.value,
            "file_path": self.record.file_path,
            "why_ranked_here": self.reasons,
            "other_locations": [r.file_path for r in self.cluster[:20]],
        }


def cluster_key(record: TriageRecord, finding: Finding | None = None) -> tuple:
    """Same rule + same code shape = one decision.

    Deliberately ignores the file path: the whole point is that forty copies of
    one pattern are one call. Verdict is part of the key so a cluster never mixes
    a `confirmed` with a `false_positive`.
    """
    if finding is not None and finding.dependency is not None:
        return ("dependency", finding.dependency.package, record.verdict.verdict.value)

    snippet = (finding.code_context.snippet if finding else None) or ""
    shape = snippet
    for pattern, repl in _NORMALIZE:
        shape = pattern.sub(repl, shape)
    rule_id = record.rule_id or (finding.rule_id if finding else None)
    return (rule_id, record.cwe, record.verdict.verdict.value, shape[:120])


def score(record: TriageRecord, finding: Finding | None = None) -> tuple[int, list[str]]:
    """0-100. Higher means "open this sooner"."""
    reasons: list[str] = []
    verdict = record.verdict

    base = {
        VerdictLabel.confirmed: 45,
        VerdictLabel.unknown: 28,
        VerdictLabel.false_positive: 3,
        VerdictLabel.external_fp: 0,
    }[verdict.verdict]
    total = base
    reasons.append(f"verdict `{verdict.verdict.value}` (+{base})")

    cwe_w = _CWE_WEIGHT.get((record.cwe or "").upper(), _DEFAULT_CWE_WEIGHT)
    total += cwe_w
    reasons.append(f"{record.cwe or 'unclassified'} consequence weight (+{cwe_w})")

    severity = finding.severity if finding is not None else record.scanner_severity
    if finding is not None or severity is not Severity.unknown:
        sev_w = _SEVERITY_WEIGHT.get(severity.value, 4)
        total += sev_w
        reasons.append(f"scanner severity {severity.value} (+{sev_w})")

    path = (
        finding.code_context.file_path if finding is not None else record.file_path
    ).replace("\\", "/").lower()
    if re.search(r"(^|/)(tests?|spec|docs?|examples?|fixtures?|vendor|node_modules)/", path):
        total -= 12
        reasons.append("non-production path (-12)")

    for sig_name in _ALWAYS_REVIEW_SIGNALS:
        if any(sig_name in o for o in record.overrides):
            total += 15
            reasons.append(f"deterministic signal {sig_name} (+15)")

    for kind in _ALWAYS_REVIEW_OVERRIDES:
        if any(o.startswith(kind) for o in record.overrides):
            total += 12
            reasons.append(f"post-validation raised {kind} (+12)")

    if any(o.startswith("hallucinated_evidence") for o in record.overrides):
        total += 8
        reasons.append("no verifiable evidence — a human has to read the code (+8)")

    if record.error:
        total += 10
        reasons.append("triage failed, verdict unavailable (+10)")

    if verdict.verdict is not VerdictLabel.unknown and verdict.confidence_band == "medium":
        total += 6
        reasons.append("the evidence behind this verdict is thin (+6)")

    if verdict.verdict is VerdictLabel.confirmed:
        if bonus := _EXPLOITABILITY_WEIGHT.get(verdict.exploitability or ""):
            total += bonus
            reasons.append(f"exploitability {verdict.exploitability} (+{bonus})")
        if bonus := _IMPACT_WEIGHT.get(verdict.impact or ""):
            total += bonus
            reasons.append(f"impact {verdict.impact} (+{bonus})")

    if not verdict.verdict.is_closed:
        total = _apply_risk_context(total, reasons, record.risk_context, record.cwe)

    return max(0, min(100, total)), reasons


def _apply_risk_context(total: int, reasons: list[str], risk: RiskContext, cwe: str | None) -> int:
    if risk.internet_exposed is True:
        total += 15
        reasons.append("service is internet exposed (+15)")
    elif risk.internet_exposed is False:
        total -= 10
        reasons.append("service is not internet exposed (-10)")
    else:
        reasons.append("internet exposure unknown (+0)")

    if risk.auth_required is False:
        total += 10
        reasons.append("authentication is not required (+10)")
    elif risk.auth_required is True:
        total -= 5
        reasons.append("authentication is required (-5)")
    else:
        reasons.append("authentication requirement unknown (+0)")

    if risk.business_critical is True:
        total += 15
        reasons.append("service is business critical (+15; minimum High)")
    elif risk.business_critical is False:
        total -= 3
        reasons.append("service is not business critical (-3)")
    else:
        reasons.append("business criticality unknown (+0)")

    if risk.egress_restricted and (cwe or "").upper() == "CWE-918":
        total -= 6
        reasons.append("Kubernetes egress is restricted; SSRF blast radius is reduced, not removed (-6)")
    if risk.shared_ingress:
        reasons.append("shared nginx ingress/load balancer is routing only (+0)")
    return total


def priority_for(score_value: int, record: TriageRecord) -> Priority:
    if record.verdict.verdict.is_closed:
        return Priority.low
    if score_value >= 75:
        priority = Priority.critical
    elif score_value >= 55:
        priority = Priority.high
    elif score_value >= 30:
        priority = Priority.medium
    else:
        priority = Priority.low
    if record.risk_context.business_critical is True and priority in (Priority.medium, Priority.low):
        return Priority.high
    return priority


def assign_priority(
    record: TriageRecord,
    finding: Finding | None = None,
    risk_context: RiskContext | None = None,
) -> TriageRecord:
    if risk_context is not None:
        record = record.model_copy(update={"risk_context": risk_context})
    value, reasons = score(record, finding)
    priority = priority_for(value, record)
    if record.risk_context.business_critical is True and priority is Priority.high and value < 55:
        reasons.append("business-critical floor raised priority to High")
    return record.model_copy(
        update={"priority": priority, "priority_score": value, "priority_reasons": reasons}
    )


def is_exempt(record: TriageRecord) -> bool:
    """Never deferred by the budget, however tight it is."""
    if any(sig in o for o in record.overrides for sig in _ALWAYS_REVIEW_SIGNALS):
        return True
    if any(o.startswith(kind) for o in record.overrides for kind in _ALWAYS_REVIEW_OVERRIDES):
        return True
    return False


@dataclass(slots=True)
class Queue:
    items: list[QueueItem]
    total_findings: int
    budget_pct: float
    external_closed: int = 0
    overflowed: bool = False

    @property
    def to_review(self) -> list[QueueItem]:
        return [i for i in self.items if not i.deferred]

    @property
    def deferred(self) -> list[QueueItem]:
        return [i for i in self.items if i.deferred]

    @property
    def manual_findings(self) -> int:
        """Findings behind the review items — the number that matters to a human."""
        return sum(i.cluster_size for i in self.to_review)

    @property
    def manual_pct(self) -> float:
        return round(100 * self.manual_findings / self.total_findings, 1) if self.total_findings else 0.0

    @property
    def to_decide(self) -> list["QueueItem"]:
        """Items where a human still has to work something out.

        `unknown` means the pipeline could not settle it, and a `confirmed`
        finding with no named remediation still needs someone to work out what
        to do about it. These are the ones that cost thinking time.
        """
        return [
            i for i in self.to_review
            if not i.record.verdict.verdict.is_closed
            and (i.record.verdict.verdict is not VerdictLabel.confirmed
                 or i.record.verdict.requires_human_review)
        ]

    @property
    def to_do(self) -> list["QueueItem"]:
        """Confirmed with the remediation already named — work, not judgement.

        Mostly dependency upgrades. Reporting these together with the undecided
        ones made "20% manual review" read as 20% of *triage*, when the triage
        load behind it was a fraction of that: on four real projects, 50 queue
        items of which 7 actually needed a decision.
        """
        return [i for i in self.to_review if i not in self.to_decide]

    def summary(self) -> dict:
        return {
            "total_findings": self.total_findings,
            "review_items": len(self.to_review),
            "items_needing_a_decision": len(self.to_decide),
            "items_needing_an_action": len(self.to_do),
            "findings_behind_review_items": self.manual_findings,
            "manual_share_pct": self.manual_pct,
            "budget_pct": self.budget_pct,
            "budget_overflowed": self.overflowed,
            "deferred_items": len(self.deferred),
            "clusters_collapsed": sum(i.cluster_size - 1 for i in self.items),
            "external_ai_closed": self.external_closed,
        }


def build(
    records: list[TriageRecord],
    cfg: TriageQueueConfig,
    findings: dict[str, Finding] | None = None,
) -> Queue:
    findings = findings or {}

    live = [r for r in records if r.decided_by != "scope"]
    candidates = [
        r
        for r in live
        if not r.verdict.verdict.is_closed
        or (r.verdict.verdict is VerdictLabel.false_positive and is_exempt(r))
    ]

    groups: dict[tuple, list[TriageRecord]] = {}
    for record in candidates:
        key = cluster_key(record, findings.get(record.finding_id)) if cfg.cluster else (record.finding_id,)
        groups.setdefault(key, []).append(record)

    items: list[QueueItem] = []
    for members in groups.values():
        scored = sorted(
            ((score(r, findings.get(r.finding_id)), r) for r in members),
            key=lambda pair: -pair[0][0],
        )
        (best_score, reasons), representative = scored[0]
        rest = [r for (_, r) in scored[1:]]
        if rest:
            reasons = [*reasons, f"stands for {len(rest)} more occurrence(s) of the same pattern"]
        items.append(
            QueueItem(
                record=representative,
                score=best_score,
                priority=priority_for(best_score, representative),
                reasons=reasons,
                cluster=rest,
                exempt=any(is_exempt(r) for r in members),
            )
        )

    items.sort(key=lambda i: (-i.score, i.record.file_path))

    allowed = max(1, round(len(live) * cfg.review_budget_pct / 100)) if live else 0
    spent = 0
    exempt_spend = 0

    for item in items:
        if item.exempt:
            spent += item.cluster_size
            exempt_spend += item.cluster_size
            continue
        if item.score < cfg.min_score:
            item.deferred = True
            continue
        if spent + item.cluster_size > allowed:
            item.deferred = True
            continue
        spent += item.cluster_size

    return Queue(
        items=items,
        total_findings=len(live),
        budget_pct=cfg.review_budget_pct,
        external_closed=sum(
            1 for record in live if record.verdict.verdict is VerdictLabel.external_fp
        ),
        overflowed=exempt_spend > allowed,
    )
