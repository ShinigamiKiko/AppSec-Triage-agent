"""Turning verdicts into a review queue an engineer can actually finish."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import TriageQueueConfig
from .consequence import CWE_WEIGHT as _CWE_WEIGHT
from .consequence import DEFAULT_WEIGHT as _DEFAULT_CWE_WEIGHT
from .models import Finding, TriageRecord, VerdictLabel

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
    """Same rule + same code shape = one decision."""
    if finding is not None and finding.dependency is not None:
        return ("dependency", finding.dependency.package, record.verdict.verdict.value)

    snippet = (finding.code_context.snippet if finding else None) or ""
    shape = snippet
    for pattern, repl in _NORMALIZE:
        shape = pattern.sub(repl, shape)
    rule_id = record.rule_id or (finding.rule_id if finding else None)
    return (rule_id, record.cwe, record.verdict.verdict.value, shape[:120])


def score(record: TriageRecord, finding: Finding | None = None) -> tuple[int, list[str]]:
    """0-100."""
    reasons: list[str] = []
    verdict = record.verdict

    base = {VerdictLabel.confirmed: 45, VerdictLabel.unknown: 28, VerdictLabel.false_positive: 3}[
        verdict.verdict
    ]
    total = base
    reasons.append(f"verdict `{verdict.verdict.value}` (+{base})")

    cwe_w = _CWE_WEIGHT.get((record.cwe or "").upper(), _DEFAULT_CWE_WEIGHT)
    total += cwe_w
    reasons.append(f"{record.cwe or 'unclassified'} consequence weight (+{cwe_w})")

    if finding is not None:
        sev_w = _SEVERITY_WEIGHT.get(finding.severity.value, 4)
        total += sev_w
        reasons.append(f"scanner severity {finding.severity.value} (+{sev_w})")

        path = finding.code_context.file_path.replace("\\", "/").lower()
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

    return max(0, min(100, total)), reasons


def is_exempt(record: TriageRecord) -> bool:
    """Never deferred by the budget, however tight it is."""
    if any(sig in o for o in record.overrides for sig in _ALWAYS_REVIEW_SIGNALS):
        return True
    return bool(any(o.startswith(kind) for o in record.overrides for kind in _ALWAYS_REVIEW_OVERRIDES))


@dataclass(slots=True)
class Queue:
    items: list[QueueItem]
    total_findings: int
    budget_pct: float
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
    def to_decide(self) -> list[QueueItem]:
        """Items where a human still has to work something out."""
        return [i for i in self.to_review if i.record.verdict.verdict is not VerdictLabel.confirmed
                or i.record.verdict.requires_human_review]

    @property
    def to_do(self) -> list[QueueItem]:
        """Confirmed with the remediation already named — work, not judgement."""
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
        }


def build(
    records: list[TriageRecord],
    cfg: TriageQueueConfig,
    findings: dict[str, Finding] | None = None,
) -> Queue:
    findings = findings or {}

    live = [r for r in records if r.decided_by != "scope"]

    groups: dict[tuple, list[TriageRecord]] = {}
    for record in live:
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
        overflowed=exempt_spend > allowed,
    )
