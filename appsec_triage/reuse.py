"""Reuse verdicts from a previous run instead of paying for them again.

A full pass over a real project is an hour of GPU. Between two runs most
findings are byte-identical and were already settled — re-judging them buys
nothing and makes the tool unusable in CI, where the answer has to arrive before
anyone loses interest.

The unit of identity is a **fingerprint** over the things that decide a verdict:
rule, CWE, path, and the code itself. Line numbers are excluded on purpose — a
finding that merely shifted down because someone added an import is the same
finding. The snippet is included for the opposite reason: if the code changed,
the old verdict is about code that no longer exists, and reusing it would be
worse than useless.

What gets re-judged is a policy choice, so it is explicit rather than clever.
The default answers the question people actually ask: *redo the ones that were
unresolved or unreliable, keep the ones that were cleanly settled.*
"""

from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from .models import Finding, TriageRecord
from .report import audit

log = logging.getLogger(__name__)

_WS = re.compile(r"\s+")

REDO_CLASSES = ("unknown", "error", "overridden", "confirmed", "false_positive", "all", "none")

DEFAULT_REDO = ("unknown", "error", "overridden")


def fingerprint(finding: Finding) -> str:
    """Stable across line shifts, sensitive to the code actually changing."""
    snippet = _WS.sub(" ", (finding.code_context.snippet or "")).strip()
    material = "␟".join(
        [
            finding.rule_id or "",
            finding.cwe or "",
            finding.code_context.file_path.replace("\\", "/"),
            snippet,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


def _needs_redo(record: TriageRecord, redo: tuple[str, ...]) -> bool:
    if "all" in redo:
        return True
    verdict = record.verdict.verdict.value
    if verdict in redo:
        return True
    if "error" in redo and record.error:
        return True
    return bool("overridden" in redo and record.overrides)


@dataclass(slots=True)
class ReusePlan:
    fresh: list[Finding] = field(default_factory=list)
    reused: list[TriageRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)
    stale_provenance: dict[str, int] = field(default_factory=dict)

    def summary(self) -> dict:
        return {
            "reused": len(self.reused),
            "re_triaged": len(self.fresh),
            "reasons": self.counts,
            "reused_from_older_inputs": self.stale_provenance,
        }


def plan(
    findings: list[Finding],
    previous_path: Path,
    redo: tuple[str, ...] = DEFAULT_REDO,
    current_model: str | None = None,
    current_prompt_pack: str | None = None,
) -> ReusePlan:
    """Split findings into 'reuse the old verdict' and 'triage again'."""
    result = ReusePlan()
    if "none" in redo:
        redo = ()

    try:
        previous = audit.read_jsonl(Path(previous_path))
    except (OSError, ValueError) as exc:
        log.warning("cannot read previous verdicts at %s: %s — triaging everything", previous_path, exc)
        result.fresh = list(findings)
        result.counts["previous_run_unreadable"] = len(findings)
        return result

    by_fingerprint: dict[str, TriageRecord] = {}
    without = 0
    for record in previous:
        if record.fingerprint:
            by_fingerprint.setdefault(record.fingerprint, record)
        else:
            without += 1
    if without:
        log.warning("%d previous verdict(s) have no fingerprint and cannot be reused", without)

    for finding in findings:
        record = by_fingerprint.get(fingerprint(finding))
        if record is None:
            result.fresh.append(finding)
            result.counts["new_or_changed"] = result.counts.get("new_or_changed", 0) + 1
            continue
        if _needs_redo(record, redo):
            result.fresh.append(finding)
            key = f"redo:{record.verdict.verdict.value}" + (":overridden" if record.overrides else "")
            result.counts[key] = result.counts.get(key, 0) + 1
            continue

        result.reused.append(record.model_copy(update={"reused": True}))
        result.counts["reused"] = result.counts.get("reused", 0) + 1
        if current_model and record.model and record.model != current_model:
            result.stale_provenance["model"] = result.stale_provenance.get("model", 0) + 1

    return result


def parse_redo(value: str | None) -> tuple[str, ...]:
    if not value:
        return DEFAULT_REDO
    picked = tuple(v.strip().lower() for v in value.split(",") if v.strip())
    unknown = [v for v in picked if v not in REDO_CLASSES]
    if unknown:
        raise ValueError(f"unknown --redo class {unknown}; choose from {list(REDO_CLASSES)}")
    return picked
