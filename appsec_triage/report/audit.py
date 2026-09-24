"""JSONL audit trail — one line per decision, append-only, replayable."""

from __future__ import annotations

import json
import platform
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Self

if TYPE_CHECKING:
    from ..models import TriageRecord
    from ..pipeline import TriageRun


def write_jsonl(run: TriageRun, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(UTC).isoformat()
    with path.open("w", encoding="utf-8") as fh:
        for record in run.records:
            row = record.model_dump(mode="json")
            row["decided_at"] = stamp
            row["prompt_pack"] = run.prompt_pack
            row["host"] = platform.node()
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


_PROVENANCE_KEYS = ("decided_at", "prompt_pack", "host")


def _from_row(row: dict) -> TriageRecord:
    """One audit line back into a record, provenance stripped."""
    from ..models import TriageRecord

    for key in _PROVENANCE_KEYS:
        row.pop(key, None)
    return TriageRecord.model_validate(row)


def read_jsonl(path: Path) -> list[TriageRecord]:
    """Load an audit log back into records."""
    return [
        _from_row(json.loads(line))
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_summary(run: TriageRun, path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = run.counts()
    by_cwe: dict[str, dict[str, int]] = {}
    for r in run.records:
        bucket = by_cwe.setdefault(r.cwe or "unclassified", {"confirmed": 0, "false_positive": 0, "unknown": 0})
        bucket[r.verdict.verdict.value] += 1

    latencies = sorted(r.latency_ms for r in run.records if r.latency_ms)
    summary = {
        "generated_at": datetime.now(UTC).isoformat(),
        **(run.coverage.as_dict() if run.coverage is not None else {"coverage_complete": None}),
        "provider": run.provider,
        "model": run.model,
        "prompt_pack": run.prompt_pack,
        "total": len(run.records),
        "triaged_by_model": run.triaged_count,
        "scope_excluded": run.scope_excluded,
        "reuse": run.reuse,
        "reused_verdicts": sum(1 for r in run.records if r.reused),
        "verdicts": counts,
        "by_cwe": by_cwe,
        "overridden_by_post_validation": sum(1 for r in run.records if r.overrides),
        "errors": sum(1 for r in run.records if r.error),
        "requires_human_review": sum(1 for r in run.records if r.verdict.requires_human_review),
        "auto_closed": counts["false_positive"],
        "noise_reduction_pct": round(100 * counts["false_positive"] / len(run.records), 1) if run.records else 0.0,
        "decided_by": {
            k: sum(1 for r in run.records if r.decided_by == k)
            for k in ("scope", "heuristics", "policy", "llm", "post_validation", "challenged", "error")
        },
        "decided_without_person": sum(1 for r in run.records if not r.verdict.requires_human_review),
        "decided_without_person_pct": (
            round(100 * sum(1 for r in run.records if not r.verdict.requires_human_review) / len(run.records), 1)
            if run.records else 0.0),
        "dependency_priority": {
            p: sum(1 for r in run.records if r.sca is not None and r.sca.priority == p)
            for p in ("critical", "high", "medium", "low", "none")
        },
        "dependency_shipping": {
            k: sum(1 for r in run.records if r.sca is not None and r.sca.shipped == k)
            for k in ("runtime", "image_only", "build_only", "unknown")
        },
        "stage_seconds": _stage_seconds(run.records),
        "confidence_spread": _confidence_spread(run.records),
        "latency_ms": {
            "p50": latencies[len(latencies) // 2] if latencies else None,
            "p95": latencies[int(len(latencies) * 0.95)] if latencies else None,
            "max": latencies[-1] if latencies else None,
        },
        "total_cost_usd": run.total_cost_usd,
        "verdict_cost_usd": run.verdict_cost_usd,
        "model_calls": run.model_calls,
    }
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


class Journal:
    """Append-only record of finished verdicts, written as the run proceeds."""

    def __init__(self, path: Path, prompt_pack: str) -> None:
        self.path = Path(path)
        self._prompt_pack = prompt_pack
        self._fh = None

    def __enter__(self) -> Self:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = self.path.open("a", encoding="utf-8")
        return self

    def __exit__(self, *exc) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None

    def append(self, record) -> None:
        if not self._fh:
            return
        row = record.model_dump(mode="json")
        row["decided_at"] = datetime.now(UTC).isoformat()
        row["prompt_pack"] = self._prompt_pack
        row["host"] = platform.node()
        self._fh.write(json.dumps(row, ensure_ascii=False) + "\n")
        self._fh.flush()

    def done(self) -> None:
        """Called once the durable audit log exists; the journal is then noise."""
        self.__exit__()
        self.path.unlink(missing_ok=True)

    @classmethod
    def recover(cls, path: Path) -> list:
        """Verdicts from an interrupted run."""
        path = Path(path)
        if not path.is_file():
            return []
        records = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                records.append(_from_row(json.loads(line)))
            except (json.JSONDecodeError, ValueError):
                continue
        return records


def _stage_seconds(records) -> dict[str, dict[str, float]]:
    """Median and total seconds per pipeline stage: where the run's time went."""
    stages: dict[str, list[float]] = {}
    for record in records:
        for stage, seconds in (getattr(record, "timings", None) or {}).items():
            stages.setdefault(stage, []).append(float(seconds))
    out = {}
    for stage, values in stages.items():
        values.sort()
        out[stage] = {"median": values[len(values) // 2], "total": round(sum(values), 1), "n": len(values)}
    return out


def _confidence_spread(records) -> dict[str, float | None]:
    """How much the calibrated confidence varies across model verdicts.

    Near zero means the number says nothing: forty verdicts at exactly 0.80 is a
    constant, not a measurement, and the auto-apply threshold then never moves.
    """
    import statistics

    values = [r.verdict.confidence for r in records if r.decided_by in ("llm", "post_validation", "challenged")]
    if len(values) < 5:
        return {"n": len(values), "stdev": None, "distinct": len(set(values))}
    return {"n": len(values), "stdev": round(statistics.pstdev(values), 3), "distinct": len(set(values))}
