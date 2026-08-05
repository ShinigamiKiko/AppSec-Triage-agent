"""Scoring against a labelled corpus.

Three numbers matter, and they are deliberately reported separately because the
article's headline figures (47.5% / 80.8% / 93.8%) are three different questions:

* `agreement_all`   — strict 3-class match including `unknown`. Pessimistic:
                      the model saying "I don't know" where a human decided
                      counts as a miss, even though it is the safe behaviour.
* `agreement_decided` — accuracy on findings the model actually decided.
                      This is the number that says "when it commits, is it right".
* `agreement_by_cwe` — the same, per CWE, which is how you find the narrow
                      classes worth automating and the ones to leave alone.

Plus the one that governs risk: `dangerous_misses` — a real vulnerability the
model closed as a false positive. That number should be zero, and it is tracked
separately from generic accuracy because it is not interchangeable with it.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable

from ..models import TriageRecord, VerdictLabel


@dataclass(slots=True)
class Scorecard:
    provider: str
    model: str
    total: int = 0
    decided: int = 0
    agree_all: int = 0
    agree_decided: int = 0
    unknown_count: int = 0
    dangerous_misses: list[str] = field(default_factory=list)
    false_alarms: list[str] = field(default_factory=list)
    by_cwe: dict[str, dict[str, int]] = field(default_factory=lambda: defaultdict(lambda: {"n": 0, "agree": 0, "decided": 0, "agree_decided": 0}))
    schema_failures: int = 0
    overridden: int = 0
    latencies_ms: list[int] = field(default_factory=list)
    cost_usd: float = 0.0
    calibration: dict[str, dict[str, int]] = field(
        default_factory=lambda: defaultdict(lambda: {"n": 0, "correct": 0})
    )
    explained: int = 0
    with_dataflow: int = 0
    with_symbol: int = 0
    unknowns_with_blocking_question: int = 0

    def as_dict(self) -> dict:
        lat = sorted(self.latencies_ms)
        return {
            "provider": self.provider,
            "model": self.model,
            "total": self.total,
            "agreement_all": _pct(self.agree_all, self.total),
            "agreement_decided": _pct(self.agree_decided, self.decided),
            "abstention_rate": _pct(self.unknown_count, self.total),
            "dangerous_misses": len(self.dangerous_misses),
            "dangerous_miss_ids": self.dangerous_misses[:20],
            "false_alarms": len(self.false_alarms),
            "schema_failures": self.schema_failures,
            "overridden_by_post_validation": self.overridden,
            "latency_ms": {
                "p50": lat[len(lat) // 2] if lat else None,
                "p95": lat[int(len(lat) * 0.95)] if lat else None,
            },
            "cost_usd": round(self.cost_usd, 4),
            "calibration": {
                bucket: {
                    "n": s["n"],
                    "actual_accuracy": _pct(s["correct"], s["n"]),
                }
                for bucket, s in sorted(self.calibration.items())
            },
            "explanation_coverage": {
                "confidence_rationale": _pct(self.explained, self.total),
                "dataflow_reconstructed": _pct(self.with_dataflow, self.total),
                "vulnerable_symbol_named": _pct(self.with_symbol, self.total),
                "unknowns_with_blocking_question": _pct(self.unknowns_with_blocking_question, self.unknown_count),
            },
            "by_cwe": {
                cwe: {
                    "n": s["n"],
                    "agreement_all": _pct(s["agree"], s["n"]),
                    "agreement_decided": _pct(s["agree_decided"], s["decided"]),
                }
                for cwe, s in sorted(self.by_cwe.items(), key=lambda kv: -kv[1]["n"])
            },
        }


def _pct(num: int, den: int) -> float | None:
    return round(100 * num / den, 1) if den else None


def _bucket(confidence: float) -> str:
    """The three measured bands, matching calibration.Calibration.band.

    Four narrow buckets over a self-reported number produced one occupied row —
    every decided verdict sat in 0.95-1.00 — which is a calibration table that
    cannot show miscalibration. These bands are computed from evidence, so a
    reader can ask the useful question: how often is `high` actually right?
    """
    if confidence >= 0.75:
        return "high"
    return "medium" if confidence >= 0.5 else "low"


def score(records: Iterable[TriageRecord], labels: dict[str, str], provider: str, model: str) -> Scorecard:
    """`labels` maps finding_id -> one of confirmed/false_positive/unknown."""
    card = Scorecard(provider=provider, model=model)

    for r in records:
        truth = labels.get(r.finding_id)
        if truth is None:
            continue
        predicted = r.verdict.verdict
        cwe = r.cwe or "unclassified"
        bucket = card.by_cwe[cwe]

        card.total += 1
        bucket["n"] += 1
        if r.error:
            card.schema_failures += 1
        if r.overrides:
            card.overridden += 1
        if r.latency_ms:
            card.latencies_ms.append(r.latency_ms)
        card.cost_usd += r.cost_usd or 0.0

        correct = predicted.value == truth
        if correct:
            card.agree_all += 1
            bucket["agree"] += 1

        if r.verdict.confidence_rationale.strip():
            card.explained += 1
        if r.verdict.dataflow:
            card.with_dataflow += 1
        if r.verdict.vulnerable_symbol:
            card.with_symbol += 1

        if predicted is not VerdictLabel.unknown:
            cal = card.calibration[_bucket(r.verdict.confidence)]
            cal["n"] += 1
            cal["correct"] += int(correct)

        if predicted is VerdictLabel.unknown:
            card.unknown_count += 1
            if r.verdict.blocking_question:
                card.unknowns_with_blocking_question += 1
        else:
            card.decided += 1
            bucket["decided"] += 1
            if predicted.value == truth:
                card.agree_decided += 1
                bucket["agree_decided"] += 1
            elif truth == "confirmed" and predicted is VerdictLabel.false_positive:
                card.dangerous_misses.append(r.finding_id)
            elif truth == "false_positive" and predicted is VerdictLabel.confirmed:
                card.false_alarms.append(r.finding_id)

    return card


def compare(cards: list[Scorecard]) -> dict:
    """Side-by-side view; ranks by decided-accuracy but surfaces the risk column."""
    ranked = sorted(cards, key=lambda c: (-(c.as_dict()["agreement_decided"] or 0), len(c.dangerous_misses)))
    return {
        "ranking": [
            {
                "provider": c.provider,
                "model": c.model,
                "agreement_decided": c.as_dict()["agreement_decided"],
                "abstention_rate": c.as_dict()["abstention_rate"],
                "dangerous_misses": len(c.dangerous_misses),
                "cost_usd": round(c.cost_usd, 4),
                "p95_ms": c.as_dict()["latency_ms"]["p95"],
            }
            for c in ranked
        ],
        "detail": {c.provider: c.as_dict() for c in cards},
        "note": (
            "Rank by agreement_decided, but never promote a provider with a non-zero "
            "dangerous_misses count without reviewing each missed finding by hand."
        ),
    }
