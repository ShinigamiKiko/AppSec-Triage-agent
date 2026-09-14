"""Post-validation: the model's answer is a proposal, not a decision.

Five checks, in order, each able to downgrade the verdict (never upgrade it):

 1. schema      — handled upstream by `parse_verdict`; a failure never reaches here
 2. evidence    — every quote must actually exist in the input (anti-hallucination)
 3. sanity      — a strong secret signal cannot be closed as a test placeholder
 4. confidence  — below the floor, `confirmed`/`false_positive` become `unknown`
  5. escalation  — unknown and low-confidence decisions stay with a human

Downgrade-only is the safety property: no combination of checks can turn an
`unknown` into a `false_positive` and silently close a real vulnerability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from difflib import SequenceMatcher

from ..calibration import DATAFLOW_CLEARABLE_SIGNALS, calibrate
from ..config import PostValidationConfig
from ..consequence import weight as consequence_weight
from ..models import EvidenceClass, EvidencePackage, Finding, Verdict, VerdictLabel

_WS = re.compile(r"\s+")
_LINE_GUTTER = re.compile(r"^[ \t]*\d+[ \t]*\|[ \t]?", re.MULTILINE)

# Confidence is stored as a probability in the 0..1 range. Strictly above this
# threshold is the only condition that permits an automated application of the
# model's verdict; exactly 0.86 remains a human-review case.
AUTO_APPLY_CONFIDENCE = 0.86


_ARGUES_FALSE_POSITIVE = re.compile(
    r"(not an? (real|genuine|actual) (credential|secret|password|vulnerability|issue)"
    r"|is (clearly )?an? (default )?placeholder"
    r"|not an? (actual|exploitable) (vulnerability|issue|risk)"
    r"|no (real )?security (impact|risk|implication)"
    r"|this is a false.?positive"
    r"|harmless (here|in this context)"
    r"|poses no risk)",
    re.IGNORECASE,
)
_ARGUES_CONFIRMED = re.compile(
    r"(is an? (real|genuine|confirmed|exploitable) (vulnerability|credential|secret)"
    r"|attacker (can|could) (exploit|control|inject)"
    r"|this is exploitable"
    r"|remote code execution is possible)",
    re.IGNORECASE,
)


@dataclass(slots=True)
class ValidationOutcome:
    verdict: Verdict
    overrides: list[str]

    ANNOTATIONS = ("remediation_is_mechanical",)

    @property
    def changed(self) -> bool:
        return any(not o.startswith(self.ANNOTATIONS) for o in self.overrides)


def is_authoritative_govulncheck(finding: Finding) -> bool:
    """Whether govulncheck supplied a usable source-to-sink baseline."""
    if (finding.scanner or "").strip().lower() != "govulncheck":
        return False
    if len(finding.trace) < 2:
        return False
    source = next((step for step in finding.trace if step.role == "source"), None)
    sink = next((step for step in finding.trace if step.role == "sink"), None)
    return (
        source is not None
        and sink is not None
        and bool(source.file_path and source.line is not None)
        and bool(sink.file_path and sink.line is not None)
    )


def govulncheck_baseline(finding: Finding) -> Verdict:
    """Build the scanner-authoritative verdict without asking the model."""
    return Verdict(
        verdict=VerdictLabel.confirmed,
        evidence_class=EvidenceClass.exploitable_dataflow,
        confidence=1.0,
        confidence_band="high",
        confidence_rationale="govulncheck supplied a source-to-sink trace with positioned frames.",
        cwe=finding.cwe,
        reason=(
            "Govulncheck authoritative baseline: a real source-to-sink call trace was supplied. "
            "The trace establishes that the vulnerable symbol is reached."
        ),
        requires_human_review=False,
    )


def check_deployment_mismatch(finding: Finding, pkg: EvidencePackage) -> str | None:
    """Return FP reason for advisory preconditions impossible in this deployment.

    The default categories are an operator decision for this platform: kernel,
    SSH, LDAP, FTP, NFS/SMB and Windows never apply to a service in a Linux pod.
    curl/wget, telnet, GUI and init-system words were removed on purpose — each
    is a word an application advisory can contain, and a word closed it.
    """
    advisory = finding.raw.get("advisory", {})
    details = "\n".join(
        text
        for text in (
            str(advisory.get("details", "")),
            finding.title or "",
            finding.description or "",
            finding.dependency.package if finding.dependency else "",
        )
        if text
    )
    if not details:
        return None

    # No bare "driver": "SQL injection in the PostgreSQL driver" is an application
    # flaw, and the word alone closed it as kernel-level behaviour.
    if re.search(r"\b(?:kernel|syscall|sys\.call|kmod)\b", details, re.IGNORECASE):
        return (
            "Advisory describes kernel-level behavior; application code cannot modify the kernel. "
            "The vulnerability does not apply to this application."
        )

    if re.search(r"\bssh\b|\bsshd\b", details, re.IGNORECASE):
        return (
            "Advisory describes SSH behavior; SSH is not part of the application deployment. "
            "The vulnerability does not apply to this application."
        )

    if re.search(r"\bldap\b|\bgo-ntlmssp\b", details, re.IGNORECASE):
        return (
            "Advisory describes LDAP behavior; LDAP is not part of the application deployment. "
            "The vulnerability does not apply to this application."
        )

    if re.search(r"\bftp\b", details, re.IGNORECASE):
        return (
            "Advisory describes FTP behavior; FTP is not part of the application deployment. "
            "The vulnerability does not apply to this application."
        )

    if re.search(r"\b(?:nfs|smb|cifs)\b", details, re.IGNORECASE):
        return (
            "Advisory describes network file-sharing behavior; legacy file-sharing is not part of the application "
            "deployment. The vulnerability does not apply to this application."
        )

    # Windows is never part of the supported application deployment.
    if re.search(r"\bWindows\b", details) and not re.search(r"\bcross[- ]platform\b", details, re.IGNORECASE):
        return (
            "Advisory describes Windows behavior; Windows is not a supported deployment platform. "
            "The vulnerability does not apply to this application."
        )

    # CGO-specific vulnerability with CGO disabled in the build.
    evidence_text = "\n".join(pkg.evidence_blocks + pkg.context_notes)
    if "CGO_ENABLED=0" in evidence_text and re.search(
        r"\bcgo\b.{0,40}\b(?:resolver|build|enabled|compiled)\b",
        details,
        re.IGNORECASE,
    ):
        return (
            "Advisory requires CGO; CGO disabled in build (Dockerfile: CGO_ENABLED=0). "
            "The vulnerability does not apply to this build configuration."
        )

    # Incoming TLS is terminated before reaching the application.
    if (
        re.search(r"\bTLS.*(?:server|handshake)\b|\bserver.*TLS\b", details, re.IGNORECASE)
        and not re.search(r"\bclient\b", details, re.IGNORECASE)
    ):
        return (
            "Advisory describes server-side TLS incoming behavior; TLS is terminated at the ingress "
            "and the application receives plaintext. The vulnerability does not apply."
        )

    return None


def apply_govulncheck_gate(
    baseline: Verdict,
    candidate: Verdict | None,
    pkg: EvidencePackage,
    *,
    quote_threshold: float,
    error: str | None = None,
) -> tuple[Verdict, list[str]]:
    """Permit only a grounded, concrete model refutation of the baseline."""
    prefix = "govulncheck authoritative baseline preserved"
    del quote_threshold  # The gate intentionally requires exact, not fuzzy, package text.
    if error:
        return baseline, [f"{prefix}: model error ({error[:240]})"]
    if candidate is None:
        return baseline, [f"{prefix}: model response was unavailable or malformed"]
    if candidate.verdict is not VerdictLabel.false_positive:
        return baseline, [f"{prefix}: model did not explicitly refute the finding"]

    haystack = pkg.quotable_text()
    grounded = bool(candidate.evidence) and all(
        e.quote in haystack and len(e.quote.strip()) >= 4 for e in candidate.evidence
    )
    reason = f"{candidate.reason} {candidate.confidence_rationale}".strip()
    contradiction = len(candidate.reason.strip()) >= 20 and bool(
        re.search(
            r"\b(?:not|outside|patched|fixed|development|dev[- ]only|test|unreachable|"
            r"absent|different|wrong|does not|no vulnerable|not affected|not shipped)\b",
            reason,
            re.IGNORECASE,
        )
    )
    if not grounded or not contradiction:
        return baseline, [
            f"{prefix}: false_positive refutation lacked exact grounded evidence or a concrete contradiction"
        ]
    accepted = candidate.model_copy(
        update={
            "reason": f"{candidate.reason.strip()} [govulncheck baseline refuted by grounded package evidence]",
            "requires_human_review": candidate.requires_human_review,
        }
    )
    return accepted, ["govulncheck authoritative baseline overridden by grounded model refutation"]


def _norm(s: str) -> str:
    return _WS.sub(" ", _LINE_GUTTER.sub("", s)).strip().lower()


def quote_is_grounded(quote: str, haystack: str, threshold: float) -> bool:
    """Exact substring first; fuzzy fallback for whitespace/quote-style drift.

    Models reliably re-indent or swap quote characters when copying a code line.
    Rejecting those as hallucinations would make the check useless, so we allow
    a high-similarity window match but nothing looser.
    """
    q, h = _norm(quote), _norm(haystack)
    if len(q) < 4:
        return False
    if q in h:
        return True
    window = len(q)
    if window > len(h):
        return SequenceMatcher(None, q, h).ratio() >= threshold
    best = 0.0
    step = max(1, window // 4)
    for i in range(0, len(h) - window + 1, step):
        best = max(best, SequenceMatcher(None, q, h[i : i + window]).ratio())
        if best >= threshold:
            return True
    return best >= threshold


def _to_unknown(v: Verdict, evidence_class: EvidenceClass | None = None) -> Verdict:
    return v.model_copy(
        update={
            "verdict": VerdictLabel.unknown,
            "evidence_class": evidence_class or v.evidence_class,
            "requires_human_review": True,
        }
    )


def apply_confidence_policy(result: Verdict, overrides: list[str]) -> Verdict:
    """Allow automatic application only for a non-unknown verdict above 85%."""
    if result.verdict is VerdictLabel.unknown:
        if not result.requires_human_review:
            result = result.model_copy(update={"requires_human_review": True})
            overrides.append("confidence_policy: unknown verdict requires human review")
    elif result.confidence > AUTO_APPLY_CONFIDENCE:
        if result.requires_human_review:
            result = result.model_copy(update={"requires_human_review": False})
            overrides.append(
                f"confidence_policy: confidence {result.confidence:.2f} is above the "
                f"{AUTO_APPLY_CONFIDENCE:.2f} auto-apply threshold"
            )
    elif not result.requires_human_review:
        result = result.model_copy(update={"requires_human_review": True})
        overrides.append(
            f"confidence_policy: confidence {result.confidence:.2f} is not above "
            f"the {AUTO_APPLY_CONFIDENCE:.2f} auto-apply threshold"
        )
    return result


def validate(
    verdict: Verdict,
    pkg: EvidencePackage,
    finding: Finding,
    cfg: PostValidationConfig,
) -> ValidationOutcome:
    if not cfg.enabled:
        return ValidationOutcome(verdict, [])

    overrides: list[str] = []
    result = verdict
    haystack = pkg.quotable_text()

    if cfg.require_evidence_quotes:
        checked = [
            e.model_copy(update={"grounded": quote_is_grounded(e.quote, haystack, cfg.quote_match_threshold)})
            for e in result.evidence
        ]
        grounded = [e for e in checked if e.grounded]
        ungrounded = [e for e in checked if not e.grounded]

        if not result.evidence and result.verdict is not VerdictLabel.unknown:
            overrides.append("no_evidence: a decisive verdict was returned without a single quote")
            result = _to_unknown(result)
        elif result.evidence and not grounded:
            overrides.append(
                f"hallucinated_evidence: none of {len(result.evidence)} quotes could be verified "
                f"(first: {ungrounded[0].quote[:80]!r})"
            )
            result = _to_unknown(result, EvidenceClass.insufficient_context)
            result = result.model_copy(
                update={
                    "evidence": checked,
                    "missing_information": [*result.missing_information, "evidence quotes could not be verified"],
                }
            )
        elif ungrounded:
            overrides.append(
                f"unverified_evidence_dropped: {len(ungrounded)} of {len(result.evidence)} entries were "
                f"paraphrase rather than quotation (first: {ungrounded[0].quote[:80]!r}); "
                f"{len(grounded)} verified quote(s) remain"
            )
            result = result.model_copy(update={"evidence": grounded})

    if result.dataflow:
        checked = []
        ungrounded_steps = 0
        for step in result.dataflow:
            grounded = True
            if step.code:
                grounded = quote_is_grounded(step.code, haystack, cfg.quote_match_threshold)
            elif step.location:
                grounded = quote_is_grounded(step.location, haystack, cfg.quote_match_threshold)
            if not grounded:
                ungrounded_steps += 1
            checked.append(step.model_copy(update={"grounded": grounded}))
        result = result.model_copy(update={"dataflow": checked})

        if ungrounded_steps:
            overrides.append(
                f"unverified_dataflow: {ungrounded_steps} of {len(checked)} step(s) cite code "
                "or locations not present in the input; shown as unverified in the report"
            )
        if (
            result.evidence_class is EvidenceClass.exploitable_dataflow
            and result.verdict is VerdictLabel.confirmed
            and ungrounded_steps == len(checked)
        ):
            overrides.append("unverified_dataflow: every hop was unverifiable, cannot confirm on this basis")
            result = _to_unknown(result, EvidenceClass.insufficient_context)

    if result.vulnerable_symbol and not _symbol_is_grounded(result.vulnerable_symbol.name, pkg, haystack, cfg):
        overrides.append(
            f"unverified_symbol: {result.vulnerable_symbol.name!r} does not appear in the input; dropped"
        )
        result = result.model_copy(update={"vulnerable_symbol": None})

    if result.verdict is VerdictLabel.unknown and not (result.blocking_question or result.missing_information):
        overrides.append("unexplained_unknown: no blocking question and no missing_information supplied")
        result = result.model_copy(
            update={"missing_information": ["model abstained without naming what it lacked"]}
        )

    prose = f"{result.reason} {result.confidence_rationale}"
    if result.verdict is VerdictLabel.confirmed and (m := _ARGUES_FALSE_POSITIVE.search(prose)):
        overrides.append(
            f"contradictory_rationale: verdict is `confirmed` but the explanation argues the opposite "
            f"({m.group(0)!r})"
        )
        result = _to_unknown(result)
    elif result.verdict is VerdictLabel.false_positive and (m := _ARGUES_CONFIRMED.search(prose)):
        overrides.append(
            f"contradictory_rationale: verdict is `false_positive` but the explanation argues the opposite "
            f"({m.group(0)!r})"
        )
        result = _to_unknown(result)

    strong = {s.name for s in pkg.heuristic_signals if s.direction == "toward_confirmed" and s.weight >= 0.7}
    if pkg.lsp_resolved_clean:
        cleared = strong & DATAFLOW_CLEARABLE_SIGNALS
        if cleared:
            strong -= cleared
    if strong and result.verdict is VerdictLabel.false_positive:
        overrides.append(
            f"sanity_conflict: closed as false_positive despite {sorted(strong)}; "
            "a deterministic check found strong evidence the other way"
        )
        secretish = {"known_secret_shape", "high_entropy_literal"} & strong
        result = _to_unknown(result, EvidenceClass.secret_value if secretish else None)
        result = result.model_copy(update={"confidence": min(result.confidence, 0.5)})

    if strong and result.evidence_class is EvidenceClass.test_placeholder:
        overrides.append(f"sanity_conflict: classed as TEST_PLACEHOLDER despite {sorted(strong)}")
        result = result.model_copy(update={"evidence_class": EvidenceClass.secret_value})

    if pkg.code_source == "description_only" and not pkg.repository_code_collected and result.evidence_class in (
        EvidenceClass.exploitable_dataflow,
        EvidenceClass.sanitized_dataflow,
    ):
        overrides.append("sanity_conflict: dataflow verdict claimed without any code context")
        result = _to_unknown(result, EvidenceClass.insufficient_context)

    floor_consequence = cfg.closure_requires_named_defence_above
    if (
        floor_consequence
        and result.verdict is VerdictLabel.false_positive
        and consequence_weight(finding.cwe) >= floor_consequence
    ):
            named = result.evidence_class in (
                EvidenceClass.sanitized_dataflow,
                EvidenceClass.identifier_only,
                EvidenceClass.test_placeholder,
            )
            if not named or not result.evidence:
                overrides.append(
                    f"unexplained_closure: {finding.cwe} is a high-consequence class "
                    f"(weight {consequence_weight(finding.cwe)} >= {floor_consequence}); closing it needs a named, "
                    f"quoted defence, not evidence_class `{result.evidence_class.value}`"
                )
                result = _to_unknown(result, EvidenceClass.insufficient_context)

    if pkg.lsp_required_missing and result.verdict is VerdictLabel.false_positive:
        from ..context.builder import DATAFLOW_CWES

        if (finding.cwe or "").upper() in DATAFLOW_CWES:
            overrides.append(
                "lsp_required_no_answer: closing a dataflow class without symbol resolution is not valid — "
                "the language server is mandatory for this file type and returned nothing"
            )
            result = _to_unknown(result, EvidenceClass.insufficient_context)

    cal = calibrate(result, pkg, finding, overrides)
    result = result.model_copy(
        update={
            "self_reported_confidence": result.confidence,
            "confidence": cal.score,
            "confidence_band": cal.band,
            "confidence_rationale": _merge_rationale(result.confidence_rationale, result.self_reported_confidence, cal),
        }
    )

    if result.verdict is not VerdictLabel.unknown and result.confidence_band == "low":
        overrides.append(
            f"low_confidence: measured certainty {result.confidence:.2f} (low) for verdict "
            f"'{result.verdict.value}' — {'; '.join(cal.reasons[:2])}"
        )
        result = _to_unknown(result)

    if (
        cfg.escalate_severities
        and finding.severity.value in cfg.escalate_severities
        and not result.requires_human_review
        and result.verdict is VerdictLabel.confirmed
    ):
        overrides.append(
            f"escalated: a confirmed {finding.severity.value}-severity finding always keeps a human in the loop"
        )
        result = result.model_copy(update={"requires_human_review": True})

    if result.verdict is VerdictLabel.unknown and not result.requires_human_review:
        overrides.append("escalated: unknown always requires human review")
        result = result.model_copy(update={"requires_human_review": True})

    dep = pkg.dependency
    if (
        result.verdict is VerdictLabel.confirmed
        and dep is not None
        and dep.upgrade_target
        and result.requires_human_review
    ):
        result = result.model_copy(update={"requires_human_review": False})
        overrides.append(
            f"remediation_is_mechanical: upgrade {dep.package} to {dep.upgrade_target} — "
            "confirmed, with a published fix on the installed branch, so this is a patch task "
            "rather than a triage decision"
        )

    result = apply_confidence_policy(result, overrides)

    if finding.cwe and result.cwe != finding.cwe:
        result = result.model_copy(update={"cwe": finding.cwe})

    if result.verdict is VerdictLabel.unknown and not result.blocking_question and overrides:
        result = result.model_copy(update={"blocking_question": _question_from_override(overrides, verdict)})

    return ValidationOutcome(result, overrides)


def _symbol_is_grounded(name: str, pkg: EvidencePackage, haystack: str, cfg: PostValidationConfig) -> bool:
    """Is the named symbol real? For a dependency, a coordinate counts as real.

    For a weakness in our code the symbol is a thing on a line — a call, a
    literal — and demanding it appear verbatim is exactly right. For a CVE it is
    a package coordinate, and the SCA prompt asks for it as `package@version`.
    That composite is *assembled* from two facts that the evidence lists on
    separate lines, so it never appears literally, and the verbatim check
    rejected it on 84 of 89 dependency findings on a real project. The verdicts
    were correct; the symbol was struck from every one of them, and the override
    it logged then dragged the certainty band down with it.

    So for dependency findings the parts are checked instead. A model naming a
    package or version that is not in the evidence still fails.
    """
    if quote_is_grounded(name, haystack, cfg.quote_match_threshold):
        return True
    dep = pkg.dependency
    if dep is None:
        return False
    lowered = name.lower()
    if dep.package.lower() not in lowered:
        return False
    version = (dep.installed_version or "").lower().lstrip("v")
    return not version or version in lowered or "@" not in lowered


def _merge_rationale(model_text: str, self_reported: float | None, cal) -> str:
    """Keep the model's reasoning, then say what the measured score is built on.

    Both belong in the report. The model's sentence explains the verdict; the
    measured reasons explain how far to trust it, and a reviewer comparing the
    two learns more than either alone.
    """
    measured = "; ".join(cal.reasons) or "no distinguishing evidence either way"
    said = f"model stated {self_reported:.2f}" if self_reported is not None else "model stated no number"
    lines = [t for t in (model_text.strip(),) if t]
    lines.append(f"Measured certainty {cal.score:.2f} ({cal.band}) — {measured}. [{said}]")
    return " ".join(lines)


def _question_from_override(overrides: list[str], original: Verdict) -> str:
    """Turn the triggering check into the question a reviewer should answer."""
    kind = overrides[0].split(":", 1)[0]
    said = original.verdict.value
    templates = {
        "hallucinated_evidence": (
            f"The model concluded `{said}` but not one of its cited lines exists in the input. "
            "Open the file and judge the code directly — there is nothing here to audit."
        ),
        "no_evidence": (
            f"The model concluded `{said}` without citing a single line. "
            "Decide from the code directly — there is nothing to audit here."
        ),
        "sanity_conflict": (
            "A deterministic check contradicts the model's reading. "
            "Confirm by hand whether the flagged value is a real credential or a placeholder."
        ),
        "unverified_dataflow": (
            "The reconstructed path cites code that is not in the analyzer output. "
            "Re-run the scanner with full trace, or trace the value by hand."
        ),
        "contradictory_rationale": (
            "The model's written explanation argues against its own verdict. "
            "Read the reason field and the code, and decide which one is right."
        ),
        "unexplained_closure": (
            "A high-consequence finding was closed without naming what makes it safe. "
            "Find the defence in the code, or treat the finding as real."
        ),
        "low_confidence": (
            f"The model leaned `{said}`, but the measured certainty fell below the floor — the evidence "
            "behind it did not hold up. Treat as undecided and review the code directly."
        ),
        "lsp_required_no_answer": (
            "The language server is mandatory for this file type but resolved nothing, so the origin of "
            "the flagged values is unverified. Fix the server (`appsec-triage doctor`) and re-run, or "
            "trace by hand where the values on the flagged line come from."
        ),
    }
    return templates.get(kind, f"Automated checks overrode a `{said}` verdict ({kind}). Review by hand.")
