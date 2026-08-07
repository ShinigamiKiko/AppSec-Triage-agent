"""Second pass: try to break the verdict.

Repeating the same question does not help. Measured on this setup the model's
errors are systematic, not random — it believed "quoting a variable inside SQL
is parameterisation" every single time it saw one. Three independent votes would
have produced three identical mistakes at three times the cost. Majority voting
fixes noise; this model's problem is bias.

So the second pass asks a *different* question: not "is this a vulnerability"
but "what is wrong with this verdict". That reframing is what breaks the shared
prior, and it aims at the measured weak spot — on real code the model's
`confirmed` label was wrong five times out of five, and each of those would have
struggled against one honest attempt at refutation.

The merge rule is the same invariant as everywhere else in this pipeline:
**a challenge can only move a verdict toward `unknown`.** A successful refutation
does not flip `confirmed` into `false_positive` — that would let a second guess
overwrite a first one. It sends the finding to a human, which is what a genuine
disagreement between two passes means.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from .config import VerificationConfig
from .consequence import weight as consequence_weight
from .llm.base import LLMClient, LLMError
from .models import EvidencePackage, EvidenceQuote, TriageRecord, Verdict, VerdictLabel
from .prompts import registry
from .validate.postvalidation import quote_is_grounded
from .validate.schema import SchemaError, _salvage

log = logging.getLogger(__name__)

CHALLENGE_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": ["strongest_counterargument", "counter_evidence", "verdict_survives", "why"],
    "properties": {
        "strongest_counterargument": {
            "type": "string",
            "description": "The best case against the verdict that the evidence actually supports.",
        },
        "counter_evidence": {
            "type": "array",
            "description": "Lines supporting the counterargument. Verbatim, and checked.",
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["quote", "why"],
                "properties": {
                    "quote": {"type": "string", "description": "VERBATIM from the input. Copy, do not describe."},
                    "why": {"type": "string", "description": "What this line shows."},
                },
            },
        },
        "verdict_survives": {
            "type": "boolean",
            "description": "True when the counterargument fails and the original verdict still holds.",
        },
        "why": {"type": "string", "description": "One or two sentences on why it survives, or why it does not."},
    },
}


@dataclass(slots=True)
class ChallengeResult:
    survives: bool
    counterargument: str = ""
    why: str = ""
    grounded_quotes: list[EvidenceQuote] = field(default_factory=list)
    ungrounded: int = 0
    latency_ms: int = 0
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    error: str | None = None


def should_challenge(record: TriageRecord, cfg: VerificationConfig) -> bool:
    """Second passes cost as much as first ones, so spend them where they pay.

    A universal second pass doubles a run — an hour becomes two on 165 findings.
    The default targets the measured weakness (`confirmed` precision) plus the
    cases where the checks already saw something odd.
    """
    if not cfg.enabled or record.decided_by in ("scope", "heuristics", "error"):
        return False
    if record.verdict.verdict.value in cfg.challenge_verdicts:
        return True
    if cfg.challenge_on_override and record.overrides:
        return True
    if cfg.challenge_cwes and (record.cwe or "").upper() in {c.upper() for c in cfg.challenge_cwes}:
        return True
    if (
        cfg.challenge_closures_above_consequence
        and record.verdict.verdict in (VerdictLabel.false_positive, VerdictLabel.external_fp)
        and consequence_weight(record.cwe) >= cfg.challenge_closures_above_consequence
    ):
        return True
    return False


def _render_prompt(
    pkg: EvidencePackage,
    verdict: Verdict,
    rendered_input: str,
    pack: str = "default",
    stack_section: str = "",
) -> tuple[str, str]:
    """The challenger gets the *same* knowledge as the pass it audits.

    Measured the hard way. Built on `base` alone the challenger lacked the CWE
    specialization and the shared fragments, and proceeded to overturn eleven
    correct command-injection verdicts on the grounds that "a blacklist filter
    removes dangerous shell metacharacters" — precisely the argument the
    sanitiser fragment declares invalid. A reviewer who knows less than the
    author does not review; it second-guesses.
    """
    system, _ = registry.render_system(pkg.cwe, pack, stack_section)
    challenge = registry.load_pack(pack)["_challenge"]
    system = f"{system}\n\n---\n\n{challenge.body}"

    evidence = "\n".join(f"  - {e.quote!r} ({e.why})" for e in verdict.evidence) or "  (none cited)"
    proposed = (
        "=== VERDICT UNDER REVIEW ===\n"
        f"verdict: {verdict.verdict.value}\n"
        f"evidence_class: {verdict.evidence_class.value}\n"
        f"confidence: {verdict.confidence}\n"
        f"reason: {verdict.reason}\n"
        f"cited evidence:\n{evidence}\n"
    )
    return system, f"{rendered_input}\n\n{proposed}"


def challenge(
    client: LLMClient,
    pkg: EvidencePackage,
    verdict: Verdict,
    rendered_input: str,
    cfg: VerificationConfig,
    quote_threshold: float,
    pack: str = "default",
    stack_section: str = "",
) -> ChallengeResult:
    import json

    system, user = _render_prompt(pkg, verdict, rendered_input, pack, stack_section)
    try:
        resp = client.complete(system, user, json_schema=CHALLENGE_SCHEMA)
    except LLMError as exc:
        log.warning("challenge failed for %s: %s", pkg.finding_id, exc)
        return ChallengeResult(survives=True, error=str(exc))

    try:
        data = json.loads(resp.text.strip())
    except json.JSONDecodeError:
        try:
            data = json.loads(_salvage(resp.text))
        except (SchemaError, json.JSONDecodeError) as exc:
            return ChallengeResult(survives=True, error=f"unparseable challenge: {exc}")

    haystack = pkg.quotable_text()
    quotes: list[EvidenceQuote] = []
    ungrounded = 0
    for item in data.get("counter_evidence") or []:
        if isinstance(item, str):
            item = {"quote": item, "why": ""}
        if not isinstance(item, dict) or not item.get("quote"):
            continue
        if quote_is_grounded(str(item["quote"]), haystack, quote_threshold):
            quotes.append(EvidenceQuote(quote=str(item["quote"]), why=str(item.get("why", ""))))
        else:
            ungrounded += 1

    survives = bool(data.get("verdict_survives", True))
    if not survives and not quotes:
        survives = True
        log.info("challenge for %s rejected the verdict but cited nothing verifiable", pkg.finding_id)

    return ChallengeResult(
        survives=survives,
        counterargument=str(data.get("strongest_counterargument", ""))[:1000],
        why=str(data.get("why", ""))[:500],
        grounded_quotes=quotes,
        ungrounded=ungrounded,
        latency_ms=resp.latency_ms,
        prompt_tokens=resp.prompt_tokens,
        completion_tokens=resp.completion_tokens,
    )


def apply(
    verdict: Verdict, result: ChallengeResult, mode: str = "advisory"
) -> tuple[Verdict, list[str], str | None]:
    """Merge the second pass into the first.

    Advisory is the default because it was measured: letting the challenge
    override took correct verdicts from 20 to 17 on a labelled corpus, while
    dangerous misses stayed at zero in both modes. The objection has value —
    just not as a decision. It goes to the reviewer, who has the context the
    challenger lacked.
    """
    if result.error:
        return verdict, [f"challenge_skipped: {result.error[:120]}"], None
    if result.survives:
        return verdict, [], None

    note = result.counterargument.strip() or result.why.strip()
    if result.grounded_quotes:
        note += f"  [cites: {result.grounded_quotes[0].quote[:80]!r}]"

    if mode == "advisory":
        return (
            verdict,
            [f"challenged_advisory: a second pass objected — {note[:180]}"],
            note,
        )

    quoted = result.grounded_quotes[0].quote[:80] if result.grounded_quotes else ""
    override = (
        f"challenged: a second pass refuted the `{verdict.verdict.value}` verdict "
        f"({result.counterargument[:140]!r}"
        + (f", citing {quoted!r}" if quoted else "")
        + ")"
    )
    updated = verdict.model_copy(
        update={
            "verdict": VerdictLabel.unknown,
            "requires_human_review": True,
            "missing_information": [*verdict.missing_information, "two passes disagreed on this finding"],
            "blocking_question": verdict.blocking_question
            or (
                "Two independent passes reached opposite conclusions. The counterargument was: "
                f"{result.counterargument[:200]} — decide which reading the code supports."
            ),
            "evidence": [*verdict.evidence, *result.grounded_quotes],
        }
    )
    return updated, [override], note
