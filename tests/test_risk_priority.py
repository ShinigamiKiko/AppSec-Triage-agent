from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage import prioritize, risk
from appsec_triage.models import (
    EvidenceClass,
    Priority,
    RiskContext,
    TriageRecord,
    Verdict,
    VerdictLabel,
)
from appsec_triage.pipeline import TriagePipeline


def _record(cwe: str, verdict: VerdictLabel = VerdictLabel.confirmed) -> TriageRecord:
    return TriageRecord(
        finding_id=f"{cwe}:{verdict.value}",
        cwe=cwe,
        file_path="src/App.php",
        verdict=Verdict(
            verdict=verdict,
            evidence_class=EvidenceClass.identifier_only,
            confidence=0.8,
            reason="test",
        ),
    )


def test_runtime_risk_context_parses_three_service_variables():
    context = risk.load(
        {
            "TRIAGE_INTERNET_EXPOSED": "true",
            "TRIAGE_AUTH_REQUIRED": "false",
            "TRIAGE_BUSINESS_CRITICAL": "unknown",
        }
    )

    assert context.internet_exposed is True
    assert context.auth_required is False
    assert context.business_critical is None
    assert context.platform == "kubernetes"
    assert context.egress_restricted is True
    assert context.shared_ingress is True
    assert context.ingress_type == "nginx"
    assert context.direct_backend_exposure is False


def test_missing_or_invalid_variables_are_unknown_not_safe_defaults():
    context = risk.load({"TRIAGE_INTERNET_EXPOSED": "public-ish"})

    assert context.internet_exposed is None
    assert context.auth_required is None
    assert context.business_critical is None
    assert "TRIAGE_INTERNET_EXPOSED" in context.warnings[0]


def test_priority_has_exactly_four_runtime_states():
    critical = prioritize.assign_priority(
        _record("CWE-78"),
        risk_context=RiskContext(
            internet_exposed=True,
            auth_required=False,
            business_critical=False,
        ),
    )
    high = prioritize.assign_priority(
        _record("CWE-703"),
        risk_context=RiskContext(
            internet_exposed=False,
            auth_required=True,
            business_critical=True,
        ),
    )
    medium = prioritize.assign_priority(
        _record("CWE-327"),
        risk_context=RiskContext(
            internet_exposed=False,
            auth_required=True,
            business_critical=False,
        ),
    )
    low = prioritize.assign_priority(
        _record("CWE-703", VerdictLabel.unknown),
        risk_context=RiskContext(
            internet_exposed=False,
            auth_required=True,
            business_critical=False,
        ),
    )

    assert critical.priority is Priority.critical
    assert high.priority is Priority.high
    assert high.priority_score < 55, "business critical must enforce the High floor"
    assert medium.priority is Priority.medium
    assert low.priority is Priority.low


def test_closed_verdicts_are_low_even_for_a_critical_public_service():
    context = RiskContext(internet_exposed=True, auth_required=False, business_critical=True)
    for verdict in (VerdictLabel.false_positive, VerdictLabel.external_fp):
        record = prioritize.assign_priority(_record("CWE-78", verdict), risk_context=context)
        assert record.priority is Priority.low


def test_kubernetes_egress_restriction_only_reduces_ssrf_priority():
    context = RiskContext(internet_exposed=True, auth_required=False, business_critical=False)
    ssrf = prioritize.assign_priority(_record("CWE-918"), risk_context=context)
    sqli = prioritize.assign_priority(_record("CWE-89"), risk_context=context)

    assert any("SSRF blast radius" in reason for reason in ssrf.priority_reasons)
    assert not any("SSRF blast radius" in reason for reason in sqli.priority_reasons)
    assert any("routing only" in reason for reason in sqli.priority_reasons)


def test_pipeline_reads_env_puts_context_in_prompt_and_persists_priority(monkeypatch):
    monkeypatch.setenv("TRIAGE_INTERNET_EXPOSED", "true")
    monkeypatch.setenv("TRIAGE_AUTH_REQUIRED", "false")
    monkeypatch.setenv("TRIAGE_BUSINESS_CRITICAL", "true")
    finding = _finding('MessageDigest.getInstance("MD5")', cwe="CWE-327")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="IDENTIFIER_ONLY",
            cwe="CWE-327",
            evidence=['MessageDigest.getInstance("MD5")'],
        )
    )

    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    prompt = client.calls[0][1]

    assert "internet exposed: true" in prompt
    assert "authentication required: false" in prompt
    assert "business critical: true" in prompt
    assert "restricted egress" in prompt
    assert "not a WAF or sanitizer" in prompt
    assert record.risk_context.internet_exposed is True
    assert record.priority is Priority.critical
    assert record.priority_score >= 75


def test_audit_summary_keeps_risk_snapshot_and_priority_counts(tmp_path):
    import json

    from appsec_triage.pipeline import TriageRun
    from appsec_triage.report import audit

    context = RiskContext(internet_exposed=True, auth_required=False, business_critical=True)
    record = prioritize.assign_priority(_record("CWE-78"), risk_context=context)
    run = TriageRun(
        records=[record],
        provider="fake",
        model="fake",
        prompt_pack="default",
        risk_context=context,
    )

    path = audit.write_summary(run, tmp_path / "summary.json")
    summary = json.loads(path.read_text(encoding="utf-8"))

    assert summary["risk_context"]["internet_exposed"] is True
    assert summary["risk_context"]["platform"] == "kubernetes"
    assert summary["priorities"] == {
        "Critical": 1,
        "High": 0,
        "Medium": 0,
        "Low": 0,
    }


def test_priority_can_be_recomputed_from_audit_without_original_finding():
    from appsec_triage.models import Severity

    context = RiskContext(internet_exposed=True, auth_required=False, business_critical=False)
    record = _record("CWE-79").model_copy(update={"scanner_severity": Severity.high})
    with_finding = _finding("echo $value;", cwe="CWE-79")
    with_finding.severity = Severity.high

    direct = prioritize.assign_priority(record, with_finding, context)
    from_audit = prioritize.assign_priority(record, None, context)

    assert from_audit.priority_score == direct.priority_score
    assert from_audit.priority is direct.priority
