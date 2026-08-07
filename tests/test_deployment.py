"""Where the app runs changes priority and exposure — and nothing else.

The value and the danger are the same fact. "Behind an ingress" genuinely
settles whether an image needs a HEALTHCHECK; it settles nothing at all about a
SQL injection, because the ingress passes the request through unchanged.
"""

from __future__ import annotations

import textwrap

from appsec_triage import deployment
from appsec_triage.models import CodeContext, Finding


def _write(tmp_path, body: str):
    path = tmp_path / "deployment.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return deployment.load(path)


BASE = """
    enabled: true
    description: Runs in Kubernetes behind an ingress.
    facts:
      liveness_probes_by_platform: true
      run_as_non_root_by_platform: false
    platform_handles:
      - rule: "DS-0026"
        requires: liveness_probes_by_platform
        why: the kubelet probes the pod
      - rule: "DS-0002"
        requires: run_as_non_root_by_platform
        why: podSecurityContext sets the user
    """


def test_a_platform_owned_check_closes_when_its_fact_is_declared(tmp_path):
    ctx = _write(tmp_path, BASE)
    entry = ctx.handled_by_platform("DS-0026")
    assert entry is not None and "kubelet" in entry.why


def test_an_entry_whose_fact_is_not_declared_is_inert(tmp_path):
    # The list describes what the platform does. A claim nobody confirmed does
    # not get to close a finding — otherwise it becomes a bucket of exceptions.
    assert _write(tmp_path, BASE).handled_by_platform("DS-0002") is None


def test_an_unlisted_rule_is_never_platform_handled(tmp_path):
    assert _write(tmp_path, BASE).handled_by_platform("DS-0001") is None


def test_nothing_is_claimed_when_the_file_is_absent(tmp_path):
    ctx = deployment.load(tmp_path / "missing.yaml")
    assert ctx.usable is False
    assert ctx.render() == ""
    assert ctx.handled_by_platform("DS-0026") is None


def test_a_disabled_context_makes_no_claims(tmp_path):
    ctx = _write(tmp_path, BASE.replace("enabled: true", "enabled: false"))
    assert ctx.usable is False
    assert ctx.handled_by_platform("DS-0026") is None


def test_the_rendered_section_forbids_closing_a_dataflow_finding(tmp_path):
    """The guardrail is in the prompt, not just in the docstring.

    Without it, "we are behind an ingress" is an invitation to close every
    injection in the codebase.
    """
    text = _write(tmp_path, BASE).render()
    assert "priority and exposure" in text
    assert "does **not** close an injection" in text
    assert "does **not** make a committed credential safe" in text
    # Only declared-true facts are stated; a false one must not be advertised.
    assert "liveness probes by platform" in text
    assert "run as non root" not in text


def test_a_broken_file_is_loud_and_claims_nothing(tmp_path, caplog):
    path = tmp_path / "deployment.yaml"
    path.write_text("enabled: true\nfacts: [this is not a mapping", encoding="utf-8")
    ctx = deployment.load(path)
    assert ctx.usable is False
    assert any("deployment context unavailable" in r.message for r in caplog.records)


def test_only_verified_non_bypassable_controls_match_the_finding(tmp_path):
    ctx = _write(
        tmp_path,
        BASE
        + """
    compensating_controls:
      - id: public-waf
        kind: waf
        covered_cwes: [CWE-89]
        covered_routes: ["*"]
        evidence: managed SQLi policy is enabled
        verified: true
        bypass_possible: false
      - id: plain-nginx
        kind: load_balancer
        covered_cwes: [CWE-89]
        covered_routes: ["*"]
        evidence: nginx forwards traffic
        verified: false
        bypass_possible: true
        """,
    )
    finding = Finding(
        finding_id="sqli",
        scanner="codeql",
        cwe="CWE-89",
        code_context=CodeContext(file_path="src/Controller.php", start_line=10, snippet="$db->query($q);"),
    )

    controls = ctx.matching_controls(finding)
    assert [control.control_id for control in controls] == ["public-waf"]


def test_route_scoped_control_requires_the_actual_route(tmp_path):
    ctx = _write(
        tmp_path,
        BASE
        + """
    compensating_controls:
      - id: api-waf
        kind: waf
        covered_cwes: [CWE-89]
        covered_routes: [/api/*]
        evidence: API WAF policy
        verified: true
        bypass_possible: false
        """,
    )
    finding = Finding(
        finding_id="sqli",
        scanner="codeql",
        cwe="CWE-89",
        code_context=CodeContext(file_path="src/Controller.php", start_line=10),
    )
    assert ctx.matching_controls(finding, "/admin/users") == []
    assert [c.control_id for c in ctx.matching_controls(finding, "/api/users")] == ["api-waf"]


def test_platform_owned_check_is_reported_as_ai_closed_external_fp(tmp_path):
    from _helpers import _PROVIDER, FakeClient

    from appsec_triage.config import PipelineConfig
    from appsec_triage.models import VerdictLabel
    from appsec_triage.pipeline import TriagePipeline

    path = tmp_path / "deployment.yaml"
    path.write_text(textwrap.dedent(BASE), encoding="utf-8")
    cfg = PipelineConfig(provider="fake", deployment_config=str(path))
    finding = Finding(
        finding_id="healthcheck",
        scanner="trivy",
        rule_id="DS-0026",
        cwe="CWE-693",
        code_context=CodeContext(file_path="Dockerfile", start_line=1, snippet="FROM app"),
        misconfiguration=True,
    )

    record = TriagePipeline(FakeClient(), _PROVIDER, cfg).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.external_fp
    assert record.verdict.requires_human_review is False
    assert record.verdict.external_control.control_id == "platform:DS-0026"
