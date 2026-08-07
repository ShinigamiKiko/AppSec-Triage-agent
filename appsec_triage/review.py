"""Turning an undecided finding into a short, answerable review task.

A verdict is not always the most useful output. When the pipeline cannot settle
a finding, the expensive part for a human is not the judgement — it is the
legwork: tracing the value, finding the route, working out whether the endpoint
is even exposed. All of that we have already done.

So an undecided finding ships as: what we established, the specific question
whose answer decides it, exactly where to look, and what each answer implies.
The reviewer supplies one fact instead of reconstructing a trace.

Questions are derived from resolved facts, not invented. Every one names a real
location, because "check whether the input is sanitised" sends someone hunting,
while "line 158 concatenates `name`; is `sql_lab` behind auth?" does not.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .consequence import weight as consequence_weight
from .models import TriageRecord, VerdictLabel


@dataclass(slots=True)
class Question:
    """One thing only a human can answer, with the place to answer it from."""

    text: str
    look_at: list[str] = field(default_factory=list)
    if_yes: str = ""
    if_no: str = ""

    def as_dict(self) -> dict:
        return {"question": self.text, "look_at": self.look_at, "if_yes": self.if_yes, "if_no": self.if_no}


@dataclass(slots=True)
class ReviewBrief:
    established: list[str] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    minutes_saved_note: str = ""

    @property
    def actionable(self) -> bool:
        return bool(self.questions)

    def as_dict(self) -> dict:
        return {
            "established": self.established,
            "questions": [q.as_dict() for q in self.questions],
        }


_ROUTE = re.compile(
    r"""(?:path|re_path|url)\s*\(\s*["']([^"']*)["']"""
    r"""|@app\.route\s*\(\s*["']([^"']*)["']"""
    r"""|Route::\w+\s*\(\s*["']([^"']*)["']"""
    r"""|@(?:Get|Post|Put|Delete|Request)Mapping\s*\(\s*["']?([^"')]*)""",
    re.I,
)


def _route_name(line: str) -> str | None:
    m = _ROUTE.search(line or "")
    if not m:
        return None
    return next((g for g in m.groups() if g), None)


def _is_secret_family(cwe: str | None) -> bool:
    from .context.heuristics import SECRET_FAMILY_CWES

    return bool(cwe) and cwe.upper() in SECRET_FAMILY_CWES


def build(record: TriageRecord) -> ReviewBrief:
    """What the reviewer should be told, and asked."""
    brief = ReviewBrief()
    verdict = record.verdict

    if verdict.verdict is VerdictLabel.external_fp:
        return brief

    if verdict.dataflow:
        grounded = [s for s in verdict.dataflow if s.grounded]
        if grounded:
            ends = f"{grounded[0].location or '?'} → {grounded[-1].location or '?'}"
            brief.established.append(f"Traced path, {len(grounded)} step(s): {ends}")
    if verdict.vulnerable_symbol:
        sym = verdict.vulnerable_symbol
        brief.established.append(f"At fault: `{sym.name}`" + (f" ({sym.location})" if sym.location else ""))

    route_lines: list[str] = []
    for line in record.symbol_context:
        if line.startswith("called from:"):
            route_lines.append(line[len("called from:") :].strip())
        elif line.startswith("definition of"):
            brief.established.append(line)
    if record.reachability:
        brief.established.append(f"Reachability: {record.reachability}")

    heavy = consequence_weight(record.cwe) >= 22

    if record.kind == "dependency" and not record.verdict.verdict.is_closed:
        brief.questions.append(
            Question(
                text=(
                    "Can this be upgraded now? The remediation is named in the verdict — "
                    "what is left is whether the bump breaks anything here."
                ),
                look_at=[record.file_path, "the changelog between the installed and fixed versions"],
                if_yes="Upgrade and close.",
                if_no=(
                    "Record why, and what compensates in the meantime — this stays open as accepted "
                    "risk, not as an untriaged finding."
                ),
            )
        )
        return brief

    for caller in route_lines[:2]:
        route = _route_name(caller)
        if route is None:
            continue
        brief.questions.append(
            Question(
                text=(
                    f"Route `{route}` reaches this code. Is it exposed outside the perimeter, "
                    "or is it internal-only / behind authentication?"
                ),
                look_at=[caller, "the firewall or access-control rules covering this route"],
                if_yes=f"Exposed → treat as {'confirmed' if heavy else 'a real finding'}.",
                if_no="Internal-only → severity drops; still worth fixing, not urgent.",
            )
        )
        break

    if _is_secret_family(record.cwe) and not record.verdict.verdict.is_closed:
        brief.questions.append(
            Question(
                text=(
                    "Is this a live credential, and is this file published — committed to the "
                    "repository, baked into an image, or shipped to a server?"
                ),
                look_at=[
                    f"{record.file_path}" + (f":{record.start_line}" if record.start_line else ""),
                    "`git log` for this file, and .gitignore",
                    "whether a real value overrides it at deploy time",
                ],
                if_yes="Live and published → rotate the secret first, then remove it from the file.",
                if_no=(
                    "A placeholder or a local-only default → false positive; record which of the two, "
                    "because they age differently."
                ),
            )
        )
        return brief

    if (
        not verdict.dataflow
        and record.kind == "weakness"
        and not record.verdict.verdict.is_closed
    ):
        target = verdict.vulnerable_symbol.name if verdict.vulnerable_symbol else "the flagged value"
        brief.questions.append(
            Question(
                text=f"Does any request-controlled value reach `{target}`?",
                look_at=[
                    f"{record.file_path}" + (f":{record.start_line}" if record.start_line else ""),
                    "the callers of the enclosing function",
                ],
                if_yes="Attacker-controlled → confirmed.",
                if_no="Only internal or constant values → false positive; note why.",
            )
        )

    if record.reachability and "none of them an entry point" in record.reachability:
        brief.questions.append(
            Question(
                text=(
                    "Callers were found, but none registers a route within one hop. "
                    "Is this reached from a controller further up, or is it internal plumbing?"
                ),
                look_at=[c for c in route_lines[:3]],
                if_yes="Reachable → the finding stands.",
                if_no="Internal helper with trusted callers only → deprioritise.",
            )
        )

    if record.reachability and "tests or fixtures" in record.reachability:
        brief.questions.append(
            Question(
                text=(
                    "Every caller found is a test or fixture. Is there a production caller the "
                    "indexer missed — dynamic dispatch, DI wiring, annotation routing?"
                ),
                look_at=[record.file_path, "DI configuration and route annotations"],
                if_yes="Production caller exists → the finding stands.",
                if_no="Test-only code → close it, and say so in the ticket.",
            )
        )

    if record.challenge_note:
        brief.questions.append(
            Question(
                text=f"A second pass argued against this verdict: {record.challenge_note[:220]}. Is that right?",
                look_at=[f"{record.file_path}" + (f":{record.start_line}" if record.start_line else "")],
                if_yes="The objection holds → change the verdict and say why.",
                if_no="The objection fails → the original verdict stands; note the reasoning for next time.",
            )
        )

    if verdict.blocking_question and verdict.verdict is VerdictLabel.unknown:
        already = {q.text[:40] for q in brief.questions}
        if verdict.blocking_question[:40] not in already:
            brief.questions.append(
                Question(
                    text=verdict.blocking_question,
                    look_at=[f"{record.file_path}" + (f":{record.start_line}" if record.start_line else "")],
                )
            )

    for gap in verdict.missing_information[:2]:
        if len(brief.questions) >= 4:
            break
        brief.questions.append(Question(text=f"Missing: {gap}", look_at=[record.file_path]))

    if brief.established and brief.questions:
        brief.minutes_saved_note = (
            "The trace and the call sites above were resolved automatically — "
            "answer the question rather than re-deriving them."
        )
    return brief
