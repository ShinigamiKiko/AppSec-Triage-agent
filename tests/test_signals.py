"""Consequence (reason-vs-verdict), deterministic heuristics, and the audit round-trip."""

from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.config import (
    HeuristicsConfig,
)
from appsec_triage.models import VerdictLabel
from appsec_triage.pipeline import TriagePipeline


def test_confirmed_verdict_whose_reason_argues_false_positive_is_escalated():
    """Found on a real project.

    The model wrote "the literal 'local' is clearly a default placeholder
    password, not a real credential" and returned `confirmed` with
    evidence_class SECRET_VALUE — formally self-consistent, so every structural
    check passed. The contradiction was only in the prose.
    """
    finding = _finding("BI_POSTGRES_PASSWORD=local", cwe="CWE-259", path="src/.env")
    # The check under test is about prose contradicting a label, which is not
    # specific to credentials. The deterministic policy would close this exact
    # line before the model saw it — correctly — so it is switched off here to
    # keep the interaction visible.
    cfg = _cfg()
    cfg.secrets_without_model = False
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="SECRET_VALUE",
            cwe="CWE-259",
            evidence=["BI_POSTGRES_PASSWORD=local"],
            reason="The literal 'local' is clearly a default placeholder password, not a real credential.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, cfg).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("contradictory_rationale" in o for o in record.overrides)
    assert "explanation" in record.verdict.blocking_question


def test_false_positive_whose_reason_argues_the_opposite_is_escalated():
    finding = _finding('$q = "SELECT * FROM t WHERE id=" . $_GET["id"];', cwe="CWE-89")
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            cwe="CWE-89",
            evidence=['$q = "SELECT * FROM t WHERE id=" . $_GET["id"];'],
            reason="An attacker can inject arbitrary SQL here, but the endpoint is probably internal.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("contradictory_rationale" in o for o in record.overrides)


def test_consistent_verdict_is_left_alone():
    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(
        _verdict_json(
            evidence=['String token = "${SERVICE_TOKEN}";'],
            reason="The value is a deploy-time template expression, so no credential is present in the repository.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


def test_committed_dotenv_gets_the_framework_convention_signal():
    from appsec_triage.context import heuristics

    committed = _finding("BI_POSTGRES_PASSWORD=local", cwe="CWE-259", path="src/.env")
    names = {s.name for s in heuristics.evaluate(committed, HeuristicsConfig()).signals}
    assert "framework_default_config" in names

    # `.env.local` is gitignored and genuinely holds secrets — no such excuse.
    local = _finding("BI_POSTGRES_PASSWORD=hunter2", cwe="CWE-259", path="src/.env.local")
    names = {s.name for s in heuristics.evaluate(local, HeuristicsConfig()).signals}
    assert "framework_default_config" not in names


# --- regression: false positives found on a real Symfony project ---------------


def test_symfony_env_placeholder_is_recognized_as_templating():
    """`%env(resolve:DB_PASSWORD)%` is resolved at container-compile time.

    The uppercase `%VAR%` pattern missed these because `%env(` is lowercase,
    leaving six textbook placeholders sitting in `unknown` on a real project.
    """
    from appsec_triage.context import heuristics

    for snippet in (
        "password: '%env(resolve:POSTGRES_PASSWORD)%'",
        "secret: '%env(APP_SECRET)%'",
        "dir: '%kernel.project_dir%'",
    ):
        finding = _finding(snippet, cwe="CWE-798", path="config/packages/doctrine.yaml")
        names = {s.name for s in heuristics.evaluate(finding, HeuristicsConfig()).signals}
        assert "template_expression" in names, snippet


def test_class_name_is_not_treated_as_a_high_entropy_secret():
    """The only `confirmed` on a real project was a Doctrine type mapping.

    A fully-qualified class name scores high on entropy, and the model confirmed
    it for exactly that reason.
    """
    from appsec_triage.context import heuristics

    finding = _finding(
        r"authentication_tokens_types: 'App\Doctrine\Type\AuthenticationTokensTypes'",
        cwe="CWE-798",
        path="config/packages/doctrine.yaml",
    )
    signals = {s.name for s in heuristics.evaluate(finding, HeuristicsConfig()).signals}
    assert "class_or_type_reference" in signals
    assert "high_entropy_literal" not in signals

    # A genuine high-entropy secret must still fire.
    real = _finding("internal.api.secret: '8Fq2xVn4LpZ7Tb1YrK0aHs9WdCe3MgJu'", cwe="CWE-798")
    signals = {s.name for s in heuristics.evaluate(real, HeuristicsConfig()).signals}
    assert "high_entropy_literal" in signals
    assert "class_or_type_reference" not in signals


def test_dynamic_include_rule_needs_a_trailing_word_boundary():
    """Regression on a Semgrep rule, verified by regex rather than by running it.

    Without the closing `\b` the rule matched `required`, `requirements` and
    `requiresSQLCommentHint`, producing 77 junk findings out of 296 on a real
    project — a quarter of the output, all of it ground through the model.
    """
    import re

    import yaml

    from appsec_triage.config import REPO_ROOT

    rules = yaml.safe_load((REPO_ROOT / "rules/semgrep/php.yaml").read_text(encoding="utf-8"))["rules"]
    rule = next(r for r in rules if r["id"] == "php-dynamic-include")
    pattern = re.compile(rule["pattern-regex"])

    for benign in (
        "candidateRequirements: $request->candidate->requirements,",
        "public function requiresSQLCommentHint(AbstractPlatform $platform): bool",
        "?array $required = null,",
        "required: $required,",
    ):
        assert not pattern.search(benign), f"false positive on: {benign}"

    for real in (
        "include $template;",
        "require_once $basePath . '/config.php';",
        "include_once($modulePath);",
    ):
        assert pattern.search(real), f"missed a real dynamic include: {real}"


def test_audit_log_round_trips(tmp_path):
    """The log must be readable by the code that wrote it.

    `write_jsonl` adds provenance (`decided_at`, `host`) that the record type
    forbids, so reading it straight back raised — an audit trail nobody can load
    is not an audit trail.
    """
    from appsec_triage.report import audit

    finding = _finding('String token = "${SERVICE_TOKEN}";')
    client = FakeClient(_verdict_json(evidence=['"${SERVICE_TOKEN}"']))
    run = TriagePipeline(client, _PROVIDER, _cfg()).run([finding])

    path = audit.write_jsonl(run, tmp_path / "verdicts.jsonl")
    loaded = audit.read_jsonl(path)

    assert len(loaded) == 1
    assert loaded[0].finding_id == run.records[0].finding_id
    assert loaded[0].verdict.verdict is run.records[0].verdict.verdict


# --- review queue --------------------------------------------------------------
