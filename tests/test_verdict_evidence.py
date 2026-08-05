"""Verdict-safety gates: hallucinated evidence, grounding, schema parsing, prompt routing."""

from __future__ import annotations

import json

import pytest
from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.llm.base import LLMError
from appsec_triage.models import CodeContext, Finding, Severity, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.prompts import registry
from appsec_triage.validate.schema import SchemaError, parse_verdict

# --- property 1: hallucinated evidence ----------------------------------------


def test_hallucinated_quote_is_downgraded_to_unknown():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(
        _verdict_json(evidence=['String password = "hunter2_never_appeared_anywhere";'], confidence=0.99)
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.decided_by == "post_validation"
    assert any("hallucinated_evidence" in o for o in record.overrides)
    assert record.original_verdict.verdict is VerdictLabel.false_positive


def test_grounded_quote_survives_whitespace_drift():
    snippet = 'private static final String TOKEN = "${SERVICE_TOKEN}";'
    finding = _finding(snippet)
    # Model re-indented the line, as they routinely do.
    client = FakeClient(_verdict_json(evidence=['private  static final String TOKEN = "${SERVICE_TOKEN}";']))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


def test_decisive_verdict_without_any_evidence_is_rejected():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=[], confidence=0.99))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("no_evidence" in o for o in record.overrides)


# --- property 2: sanity conflicts ---------------------------------------------


def test_real_aws_key_in_a_test_file_cannot_be_closed():
    finding = _finding('String key = "AKIAIOSFODNN7EXAMPLE";', path="src/test/java/AppTest.java")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence=['String key = "AKIAIOSFODNN7EXAMPLE";'],
            reason="it is in a test file",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.verdict.requires_human_review
    assert any("sanity_conflict" in o for o in record.overrides)


def test_dataflow_verdict_without_code_context_is_rejected():
    finding = Finding(
        finding_id="t-2",
        scanner="test",
        cwe="CWE-89",
        description="SQL injection reported by the analyzer.",
        code_context=CodeContext(file_path="src/Repo.java", snippet=None),
    )
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="EXPLOITABLE_DATAFLOW",
            cwe="CWE-89",
            evidence=["SQL injection reported by the analyzer."],
            confidence=0.9,
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("dataflow verdict claimed without any code context" in o for o in record.overrides)


def test_the_models_own_number_no_longer_decides_anything():
    """Deliberate change of behaviour, driven by a real run.

    Every decided verdict came back at 0.95+, so a threshold on the model's
    self-reported number was a gate that never closed. It is now replaced by a
    measured score; the model's number is kept for the report only. Here the
    evidence is a real, verifiable quote, so a stated 0.4 does not downgrade it.
    """
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=['"${SERVICE_TOKEN}"'], confidence=0.4))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.verdict.self_reported_confidence == 0.4
    assert record.verdict.confidence != 0.4
    assert record.verdict.confidence_band in {"high", "medium"}


def test_a_verdict_with_no_surviving_evidence_lands_in_the_low_band():
    """The measured score is what the floor now reads.

    Nothing quoted survives grounding, so post-validation downgrades on the
    evidence check and calibration independently records why the number is low.
    """
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=["this value is only ever a placeholder"], confidence=0.99))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.verdict.confidence_band == "low"
    assert "grounding check" in record.verdict.confidence_rationale


def test_severity_alone_no_longer_forces_review():
    """Deliberate change of behaviour, driven by a real run.

    Severity used to force review on its own. On a project filtered to
    critical+high that put 126 of 126 findings in the human queue: an escalation
    rule that escalates everything is not a control. Severity now feeds the
    priority score instead (see prioritize.py).
    """
    finding = _finding('String token = "${SERVICE_TOKEN}";', severity=Severity.critical)
    client = FakeClient(_verdict_json(evidence=['"${SERVICE_TOKEN}"'], requires_human_review=False))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.verdict.requires_human_review is False
    assert record.overrides == []


def test_confirmed_high_severity_still_escalates():
    """The narrowed rule: a *confirmed* critical finding still keeps a human in."""
    finding = _finding('String key = "AKIAIOSFODNN7EXAMPLE";', severity=Severity.critical)
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="SECRET_VALUE",
            evidence=['String key = "AKIAIOSFODNN7EXAMPLE";'],
            reason="AWS access key committed to the repository.",
            requires_human_review=False,
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.requires_human_review
    assert any("escalated" in o for o in record.overrides)


# --- property 3: no finding is ever dropped -----------------------------------


def test_provider_failure_yields_an_unknown_record():
    finding = _finding('String token = "abc";')
    client = FakeClient(LLMError("connection refused"))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.decided_by == "error"
    assert "connection refused" in record.error


def test_batch_preserves_input_order_and_length():
    findings = [_finding(f'String t{i} = "${{VAR_{i}}}";') for i in range(6)]
    client = FakeClient(*[_verdict_json(evidence=[f'"${{VAR_{i}}}"']) for i in range(6)])
    run = TriagePipeline(client, _PROVIDER, _cfg()).run(findings)

    assert len(run.records) == 6
    assert [r.finding_id for r in run.records] == [f.finding_id for f in findings]


# --- schema parsing ------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        _verdict_json(),
        "```json\n" + _verdict_json() + "\n```",
        "Here is my analysis:\n" + _verdict_json() + "\nHope that helps!",
    ],
)
def test_parser_salvages_wrapped_json(raw):
    assert parse_verdict(raw).verdict is VerdictLabel.false_positive


def test_parser_normalizes_case_and_scalars():
    v = parse_verdict(
        json.dumps(
            {
                "verdict": "  Confirmed ",
                "evidence_class": "secret_value",
                "confidence": 0.9,
                "evidence": "a single string not a list",
                "reason": "x",
            }
        )
    )
    assert v.verdict is VerdictLabel.confirmed
    assert [e.quote for e in v.evidence] == ["a single string not a list"]
    assert v.requires_human_review is True  # defaulted safely


def test_parser_rejects_garbage():
    with pytest.raises(SchemaError):
        parse_verdict("the model apologises and returns prose")


# --- prompt routing ------------------------------------------------------------


def test_cwe_routes_to_the_narrow_prompt_not_base():
    system, prompt = registry.render_system("CWE-798")
    assert prompt.id == "cwe-798"
    assert "OAuth **Client ID**" in system
    assert "Absolute rules" in system  # base is prepended via `extends`


def test_unknown_cwe_falls_back_to_base():
    _, prompt = registry.render_system("CWE-9999")
    assert prompt.id == "base"


def test_fp_check_methodology_is_in_every_triage_prompt():
    """LSP/CodeQL context must be judged with the same evidence discipline for every CWE."""
    system, _ = registry.render_system("CWE-89")
    assert "fp-check discipline" in system
    assert "no callers listed is not proof of\n   unreachability" in system
    assert "unproven gate leads to `unknown`, not to\n`false_positive`" in system


# --- ingest --------------------------------------------------------------------
