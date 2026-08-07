"""Post-validation gates: dataflow/randomness/TLS/symbol checks and scope exclusion."""

from __future__ import annotations

import json

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.config import (
    HeuristicsConfig,
)
from appsec_triage.ingest import native
from appsec_triage.models import Severity, TraceStep, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.prompts import registry


def test_native_corpus_parses(tmp_path):
    corpus = tmp_path / "c.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "finding_id": "x-1",
                "cwe": "798",
                "path": "a/b.java",
                "code": 'String s = "x";',
                "risk": "blocker",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    findings = list(native.parse(corpus))
    assert findings[0].cwe == "CWE-798"
    assert findings[0].severity is Severity.critical  # 'blocker' alias
    assert findings[0].code_context.file_path == "a/b.java"


# --- regression: entropy signal must not leak outside the secret family --------


def test_sql_string_does_not_trigger_the_secret_entropy_signal():
    """A parameterized query is high-entropy text, not a credential.

    Before this was scoped, the entropy signal fired on the SQL literal and
    post-validation overrode a correct `false_positive` on CWE-89 into unknown.
    """
    from appsec_triage.context import heuristics

    finding = _finding(
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");',
        cwe="CWE-89",
    )
    result = heuristics.evaluate(finding, HeuristicsConfig())
    assert not any(s.name == "high_entropy_literal" for s in result.signals)

    secret = _finding('String s = "8Fq2xVn4LpZ7Tb1YrK0aHs9WdCe3MgJu";', cwe="CWE-798")
    assert any(s.name == "high_entropy_literal" for s in heuristics.evaluate(secret, HeuristicsConfig()).signals)


def test_correct_sqli_false_positive_is_not_overridden():
    finding = _finding(
        'PreparedStatement ps = conn.prepareStatement("SELECT * FROM customers WHERE id = ?");',
        cwe="CWE-89",
    )
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=['conn.prepareStatement("SELECT * FROM customers WHERE id = ?")'],
            confidence=0.95,
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


# --- regression: CWE-330 consumer detection ------------------------------------


def test_weak_random_for_a_session_id_cannot_be_closed():
    """The single dangerous miss from the first real benchmark run.

    `new Random()` feeding a session identifier was closed as a false positive
    because the snippet shows the generator, not the threat. The consumer's name
    is the evidence, so it becomes a toward_confirmed signal and post-validation
    blocks the closure.
    """
    from appsec_triage.context import heuristics

    finding = _finding("String sessionId = Long.toHexString(new Random().nextLong());", cwe="CWE-330")
    assert any(s.name == "security_context_hint" for s in heuristics.evaluate(finding, HeuristicsConfig()).signals)

    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            cwe="CWE-330",
            evidence=["String sessionId = Long.toHexString(new Random().nextLong());"],
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("sanity_conflict" in o for o in record.overrides)


def test_weak_random_for_retry_jitter_stays_closed():
    finding = _finding("long jitterMs = ThreadLocalRandom.current().nextLong(0, 250);", cwe="CWE-330")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            cwe="CWE-330",
            evidence=["long jitterMs = ThreadLocalRandom.current().nextLong(0, 250);"],
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


# --- explanation fields: grounding and completeness ----------------------------


def test_invented_dataflow_hop_is_marked_unverified():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(
        _verdict_json(
            evidence=['"${SERVICE_TOKEN}"'],
            dataflow=[
                {
                    "order": 1,
                    "role": "source",
                    "location": "src/main/App.java",
                    "code": 'String token = "${SERVICE_TOKEN}";',
                    "explanation": "real",
                    "tainted": True,
                },
                {
                    "order": 2,
                    "role": "sink",
                    "location": "src/other/Never.java",
                    "code": "sendToRemote(token);",
                    "explanation": "invented",
                    "tainted": True,
                },
            ],
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert [s.grounded for s in record.verdict.dataflow] == [True, False]
    assert any("unverified_dataflow" in o for o in record.overrides)


def test_confirmed_dataflow_built_entirely_on_invented_hops_is_rejected():
    finding = _finding("stmt.executeQuery(sql);", cwe="CWE-89")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="EXPLOITABLE_DATAFLOW",
            cwe="CWE-89",
            evidence=["stmt.executeQuery(sql);"],
            dataflow=[
                {
                    "order": 1,
                    "role": "source",
                    "location": "Ghost.java",
                    "code": 'req.getParameter("nope")',
                    "explanation": "x",
                    "tainted": True,
                },
            ],
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.unknown


def test_symbol_that_does_not_appear_in_the_input_is_dropped():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(
        _verdict_json(
            evidence=['"${SERVICE_TOKEN}"'],
            vulnerable_symbol={
                "name": "Runtime.getRuntime().exec",
                "kind": "sink",
                "location": None,
                "why": "invented",
            },
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.vulnerable_symbol is None
    assert any("unverified_symbol" in o for o in record.overrides)


def test_downgraded_unknown_gets_a_synthesized_blocking_question():
    """The model was confident, so it wrote no question — but the reviewer still needs one."""
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=["a line that was never in the input at all"], blocking_question=None))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.verdict.blocking_question
    assert "nothing here to audit" in record.verdict.blocking_question


# --- regression: the real miss found on httpie ---------------------------------


def test_disabled_tls_validation_cannot_be_closed_as_taint_reasoning():
    """The dangerous miss from the first real-project run.

    httpie's `requests.get(PACKAGE_INDEX_LINK, verify=False)` in production code
    was closed as a false positive because "the URL is a constant, not user
    input". Taint is the wrong question for transport security: a network
    attacker substitutes the response no matter who chose the URL.
    """
    from appsec_triage.context import heuristics

    finding = _finding(
        "response = requests.get(PACKAGE_INDEX_LINK, verify=False)",
        cwe="CWE-295",
        path="httpie/internal/update_warnings.py",
        severity=Severity.high,
    )
    signals = heuristics.evaluate(finding, HeuristicsConfig()).signals
    assert any(s.name == "tls_validation_disabled" for s in signals)

    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            cwe="CWE-295",
            evidence=["response = requests.get(PACKAGE_INDEX_LINK, verify=False)"],
            reason="the URL is a hardcoded constant, not user-controlled",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.verdict.requires_human_review
    assert any("tls_validation_disabled" in o for o in record.overrides)


def test_cwe_295_routes_to_the_crypto_prompt():
    """It fell through to `base` before, so the verify=False rule never loaded."""
    system, prompt = registry.render_system("CWE-295")
    assert prompt.id == "crypto"
    assert "transport security" in system.lower()


def test_signal_lines_the_model_copies_are_grounded():
    """Grounding compares against the rendered prompt, not a parallel rebuild.

    The two used to drift — signals rendered as `- name [direction]: detail` in
    the prompt but `name: detail` in the grounding text — so a model faithfully
    quoting a signal was accused of hallucinating.
    """
    from appsec_triage.context import builder, heuristics

    finding = _finding('String token = "${SERVICE_TOKEN}";')
    heur = heuristics.evaluate(finding, HeuristicsConfig())
    pkg = builder.build(finding, heur, _cfg())
    rendered = builder.render_for_prompt(pkg)

    signal_line = next(line for line in rendered.splitlines() if line.startswith("- template_expression"))
    from appsec_triage.validate.postvalidation import quote_is_grounded

    assert quote_is_grounded(signal_line, pkg.quotable_text(), 0.85)


def test_scope_excluded_findings_are_recorded_not_dropped():
    from appsec_triage.config import ScopeConfig

    cfg = _cfg()
    cfg.scope = ScopeConfig(exclude_rules=["B101 assert_used"])
    findings = [
        _finding("assert x == 1", cwe="CWE-703"),
        _finding('String t = "${VAR}";'),
    ]
    findings[0].rule_id = "B101 assert_used"
    client = FakeClient(_verdict_json(evidence=['"${VAR}"']))
    run = TriagePipeline(client, _PROVIDER, cfg).run(findings)

    assert len(run.records) == 2, "an excluded finding must still produce a record"
    assert run.triaged_count == 1
    assert run.scope_excluded == {"rule:B101 assert_used": 1}
    excluded = next(r for r in run.records if r.decided_by == "scope")
    assert "scope_excluded" in excluded.overrides[0]


class _ReachableSymbols:
    def enrich(self, finding):
        from appsec_triage.lsp.service import SymbolContext

        return SymbolContext(reachable_from_entrypoint=True, resolved=True)


def _external_cfg(tmp_path):
    deployment = tmp_path / "deployment.yaml"
    deployment.write_text(
        """enabled: true
description: Kubernetes behind a verified WAF.
compensating_controls:
  - id: public-waf
    kind: waf
    direction: inbound
    covered_cwes: [CWE-89]
    covered_routes: ["*"]
    evidence: WAF policy app-public blocks SQL injection
    verified: true
    bypass_possible: false
""",
        encoding="utf-8",
    )
    cfg = _cfg()
    cfg.deployment_config = str(deployment)
    return cfg


def _traced_sqli():
    finding = _finding("$db->query($q);", cwe="CWE-89", path="src/Controller.php")
    finding.scanner = "codeql"
    finding.trace = [
        TraceStep(file_path="src/Controller.php", line=1, message="request q", role="source"),
        TraceStep(file_path="src/Controller.php", line=1, message="$db->query($q)", role="sink"),
    ]
    return finding


def _external_verdict():
    return _verdict_json(
        verdict="external_fp",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-89",
        evidence=["WAF policy app-public blocks SQL injection"],
        external_control={
            "control_id": "public-waf",
            "why_effective": "it covers CWE-89 before this entrypoint",
        },
        requires_human_review=True,
    )


def test_verified_control_on_an_established_sast_path_is_ai_closed(tmp_path):
    record = TriagePipeline(
        FakeClient(_external_verdict()),
        _PROVIDER,
        _external_cfg(tmp_path),
        symbols=_ReachableSymbols(),
    ).triage_one(_traced_sqli())

    assert record.verdict.verdict is VerdictLabel.external_fp
    assert record.verdict.requires_human_review is False
    assert record.verdict.external_control.control_id == "public-waf"
    assert record.sast_reachability.status == "established"
    assert [control.control_id for control in record.external_controls] == ["public-waf"]


def test_external_control_without_a_source_to_sink_trace_is_unknown(tmp_path):
    finding = _traced_sqli()
    finding.trace = []
    record = TriagePipeline(
        FakeClient(_external_verdict()),
        _PROVIDER,
        _external_cfg(tmp_path),
        symbols=_ReachableSymbols(),
    ).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.verdict.requires_human_review
    assert any("external_control_path_unverified" in item for item in record.overrides)


def test_model_cannot_invent_an_external_control(tmp_path):
    verdict = json.loads(_external_verdict())
    verdict["external_control"]["control_id"] = "ordinary-nginx"
    record = TriagePipeline(
        FakeClient(json.dumps(verdict)),
        _PROVIDER,
        _external_cfg(tmp_path),
        symbols=_ReachableSymbols(),
    ).triage_one(_traced_sqli())

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("external_control_unverified" in item for item in record.overrides)


# --- source resolver: widen cropped scanner snippets ---------------------------
