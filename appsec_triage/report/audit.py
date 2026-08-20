"""JSONL audit trail — one line per decision, append-only, replayable.

Every line carries enough provenance to answer "why did this get closed in
March" six months later: provider, model, prompt id + version, the pre-override
verdict, and which post-validation rules fired.
"""

from __future__ import annotations

import json
import platform
from datetime import datetime, timezone
from pathlib import Path

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..pipeline import TriageRun


def write_jsonl(run: "TriageRun", path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).isoformat()
    with path.open("w", encoding="utf-8") as fh:
        for record in run.records:
            row = record.model_dump(mode="json")
            row["decided_at"] = stamp
            row["prompt_pack"] = run.prompt_pack
            row["host"] = platform.node()
            fh.write(json.dumps(row, ensure_ascii=False) + "\n")
    return path


_PROVENANCE_KEYS = ("decided_at", "prompt_pack", "host")


def _from_row(row: dict) -> "TriageRecord":
    """One audit line back into a record, provenance stripped."""
    from ..models import TriageRecord

    for key in _PROVENANCE_KEYS:
        row.pop(key, None)
    return TriageRecord.model_validate(row)


def read_jsonl(path: Path) -> list["TriageRecord"]:
    """Load an audit log back into records. Inverse of `write_jsonl`."""
    return [
        _from_row(json.loads(line))
        for line in Path(path).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def write_summary(run: "TriageRun", path: Path) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    counts = run.counts()
    by_cwe: dict[str, dict[str, int]] = {}
    for r in run.records:
        bucket = by_cwe.setdefault(r.cwe or "unclassified", {"confirmed": 0, "false_positive": 0, "unknown": 0})
        bucket[r.verdict.verdict.value] += 1

    latencies = sorted(r.latency_ms for r in run.records if r.latency_ms)
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
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
            for k in ("scope", "heuristics", "llm", "post_validation", "error")
        },
        "latency_ms": {
            "p50": latencies[len(latencies) // 2] if latencies else None,
            "p95": latencies[int(len(latencies) * 0.95)] if latencies else None,
            "max": latencies[-1] if latencies else None,
        },
        # Both, because they answer different questions: what the run cost, and
        # how much of that a per-finding record can account for.
        "total_cost_usd": run.total_cost_usd,
        "verdict_cost_usd": run.verdict_cost_usd,
        "model_calls": run.model_calls,
    }
    path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


class Journal:
    """Append-only record of finished verdicts, written as the run proceeds.

    Everything used to be written after the last finding returned, so a crash at
    183 of 296 destroyed 183 completed verdicts along with the API spend and the
    wall-clock time that produced them. The model calls are the expensive part of
    this pipeline and they are not reproducible for free.

    The journal is also the resume point: a re-run reads it, skips the findings
    already decided, and pays only for what is left. It is deleted once the real
    audit log is written, so its presence means "a run did not finish".
    """

    def __init__(self, path: Path, prompt_pack: str) -> None:
        self.path = Path(path)
        self._prompt_pack = prompt_pack
        self._fh = None

    def __enter__(self) -> "Journal":
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
        row["decided_at"] = datetime.now(timezone.utc).isoformat()
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
        """Verdicts from an interrupted run. A corrupt tail is dropped, not fatal.

        The last line of a killed process is routinely half-written. Refusing to
        read the file for that would throw away everything the run did survive.
        """
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
