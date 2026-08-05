"""Second-pass challenge: advisory vs authoritative, grounding of refutations."""

from __future__ import annotations

import json

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _record, _verdict_json

from appsec_triage.llm.base import LLMError
from appsec_triage.models import VerdictLabel
from appsec_triage.pipeline import TriagePipeline


def _challenge_json(survives: bool, quotes=(), arg="the value is validated upstream") -> str:
    return json.dumps(
        {
            "strongest_counterargument": arg,
            "counter_evidence": [{"quote": q, "why": "shows the guard"} for q in quotes],
            "verdict_survives": survives,
            "why": "because" if survives else "the guard invalidates the claim",
        }
    )


def _verify_cfg(**over):
    from appsec_triage.config import VerificationConfig

    cfg = _cfg()
    cfg.verification = VerificationConfig(enabled=True, **over)
    return cfg


def test_advisory_challenge_records_the_objection_without_touching_the_verdict():
    """The default, and it was measured rather than assumed.

    Letting the challenge override took correct verdicts from 20 to 17 on a
    labelled corpus while dangerous misses stayed at zero in both modes. The
    objection is worth reading and is not worth obeying — so it goes to the
    reviewer as a question.
    """
    snippet = "if( is_numeric( $octet[0] ) ) {\n  $cmd = shell_exec( 'ping ' . $target );"
    finding = _finding(snippet, cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec( 'ping ' . $target );", "why": "sink"}],
            reason="user input reaches shell_exec",
        ),
        _challenge_json(False, quotes=["if( is_numeric( $octet[0] ) ) {"]),
    )
    record = TriagePipeline(client, _PROVIDER, _verify_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed, "advisory must not change the verdict"
    assert record.challenge_note, "the objection is kept"
    assert any("challenged_advisory" in o for o in record.overrides)

    from appsec_triage import review

    brief = review.build(record)
    assert any("second pass argued" in q.text for q in brief.questions)


def test_authoritative_challenge_downgrades_to_unknown_not_the_opposite():
    """A second guess must not overwrite the first — disagreement means a human decides."""
    snippet = "if( is_numeric( $octet[0] ) ) {\n  $cmd = shell_exec( 'ping ' . $target );"
    finding = _finding(snippet, cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec( 'ping ' . $target );", "why": "sink"}],
            reason="user input reaches shell_exec",
        ),
        _challenge_json(False, quotes=["if( is_numeric( $octet[0] ) ) {"]),
    )
    record = TriagePipeline(client, _PROVIDER, _verify_cfg(mode="authoritative")).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.decided_by == "challenged"
    assert any("challenged" in o for o in record.overrides)
    assert record.verdict.blocking_question


def test_a_surviving_verdict_is_left_alone():
    finding = _finding("$cmd = shell_exec( 'ping ' . $target );", cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec( 'ping ' . $target );", "why": "sink"}],
        ),
        _challenge_json(True),
    )
    record = TriagePipeline(client, _PROVIDER, _verify_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed
    assert record.overrides == []


def test_an_ungrounded_refutation_cannot_destroy_a_verdict():
    """Same rule as the first pass: an unverifiable claim decides nothing."""
    finding = _finding("$cmd = shell_exec( 'ping ' . $target );", cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec( 'ping ' . $target );", "why": "sink"}],
        ),
        _challenge_json(False, quotes=["there is validation somewhere in the controller"]),
    )
    record = TriagePipeline(client, _PROVIDER, _verify_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed, "an invented guard proves nothing"


def test_a_failed_challenge_never_changes_the_verdict():
    finding = _finding("$cmd = shell_exec( 'ping ' . $target );", cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "$cmd = shell_exec( 'ping ' . $target );", "why": "sink"}],
        ),
        LLMError("connection refused"),
    )
    record = TriagePipeline(client, _PROVIDER, _verify_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed
    assert any("challenge_skipped" in o for o in record.overrides)


def test_second_pass_is_spent_only_where_configured():
    """A universal second pass doubles the run; the default targets `confirmed`."""
    from appsec_triage import verify
    from appsec_triage.config import VerificationConfig

    cfg = VerificationConfig(enabled=True)
    confirmed = _record("confirmed", "CWE-89", "a.php")
    closed = _record("false_positive", "CWE-89", "b.php")
    flagged = _record("false_positive", "CWE-89", "c.php", overrides=["sanity_conflict: x"])

    assert verify.should_challenge(confirmed, cfg)
    assert not verify.should_challenge(closed, cfg)
    assert not verify.should_challenge(flagged, cfg)
    assert verify.should_challenge(flagged, VerificationConfig(enabled=True, challenge_on_override=True))


# --- reuse: do not pay twice for a settled finding -----------------------------
