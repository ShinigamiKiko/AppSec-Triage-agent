"""Cross-project measurement: what the reviewer is actually left holding.

There is no labelled ground truth for these repositories, so this deliberately
does not print an "accuracy". It prints the things that *can* be measured
without labels and that the pipeline's stated goals are phrased in:

* how much of the scanner's output still reaches a human (the <=30% target)
* how often the model abstains, and whether it said what would settle it
* whether the measured certainty actually spreads across bands, or has
  collapsed into one — the failure that made the old self-reported number
  useless
* whether reachability was answered at all, which is the PHP gap

Read it as instrumentation for tuning, not as a score.

    python3 tools/measure.py out/rabota/*/verdicts-*.jsonl
"""

from __future__ import annotations

import json
import sys
from collections import Counter
from pathlib import Path


def _findings_for(path: Path) -> dict:
    """The scan reports behind these verdicts, when they can be located.

    Severity and file paths feed both the cluster key and the score, so a queue
    built without them collapses fewer duplicates and ranks them differently —
    it is a different queue, not a cheaper one.
    """
    from appsec_triage import ingest

    for candidate in (path.parent / "scans", path.parent):
        if any(candidate.glob("*.sarif.json")):
            try:
                return {f.finding_id: f for f in ingest.load(candidate)}
            except Exception:
                break
    raise LookupError(
        f"scan reports not found next to {path}; pass them explicitly or run "
        "`appsec-triage queue <verdicts> -f <scans>`"
    )


def _budget() -> float:
    from appsec_triage.config import load_pipeline_config

    return load_pipeline_config().queue.review_budget_pct


def _queue_size(path: Path):
    """What the reviewer actually opens: clustered, scored, budget-capped."""
    try:
        from appsec_triage.config import load_pipeline_config
        from appsec_triage import prioritize
        from appsec_triage.report import audit

        cfg = load_pipeline_config()
        queue = prioritize.build(audit.read_jsonl(path), cfg.queue, _findings_for(path))
        return len(queue.to_review), queue.summary()["manual_share_pct"]
    except Exception as exc:
        print(f"  (queue unavailable: {exc})")
        return None


def summarise(path: Path) -> None:
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not records:
        print(f"{path}: empty")
        return

    verdicts = Counter(r["verdict"]["verdict"] for r in records)
    bands = Counter(r["verdict"].get("confidence_band") or "not-calibrated" for r in records)
    priorities = Counter(r.get("priority") or "not-prioritized" for r in records)
    decided_by = Counter(r.get("decided_by") for r in records)
    review = sum(1 for r in records if r["verdict"].get("requires_human_review"))
    scoped_out = decided_by.get("scope", 0)
    triaged = len(records) - scoped_out

    unknowns = [r for r in records if r["verdict"]["verdict"] == "unknown"]
    answerable = sum(
        1 for r in unknowns if r["verdict"].get("blocking_question") or r["verdict"].get("missing_information")
    )
    prompt_tok = sum(r.get("prompt_tokens") or 0 for r in records)
    completion_tok = sum(r.get("completion_tokens") or 0 for r in records)
    cost = sum(r.get("cost_usd") or 0.0 for r in records)
    called = sum(1 for r in records if r.get("prompt_tokens"))

    reachable = sum(1 for r in records if r.get("reachability"))
    errors = sum(1 for r in records if r.get("error"))
    queue = _queue_size(path)

    print(f"\n=== {path}")
    print(f"  findings            {len(records)}  (scope-excluded {scoped_out}, triaged {triaged})")
    print(f"  verdicts            {dict(verdicts)}")
    print(f"  decided by          {dict(decided_by)}")
    print(f"  flagged for review  {review} ({100 * review / len(records):.0f}% of raw findings)")
    if queue is not None:
        print(f"  REVIEW QUEUE        {queue[0]} item(s) = {queue[1]}% manual (budget {_budget()}%)")
    print(f"  unknowns explained  {answerable}/{len(unknowns)}")
    print(f"  reachability known  {reachable}/{len(records)}")
    print(f"  certainty bands     {dict(bands)}")
    print(f"  priorities          {dict(priorities)}")
    print(
        f"  tokens              {prompt_tok + completion_tok:,} "
        f"(in {prompt_tok:,} / out {completion_tok:,}) over {called} model call(s)"
    )
    if prompt_tok:
        print(f"  per finding         {(prompt_tok + completion_tok) // max(1, len(records)):,} tokens")
    if cost:
        print(f"  cost                ${cost:.4f}")
    if errors:
        print(f"  errors              {errors}")


if __name__ == "__main__":
    args = sys.argv[1:]
    if not args:
        args = [str(p) for p in sorted(Path("out").rglob("verdicts*.jsonl"))]
    for arg in args:
        summarise(Path(arg))
