"""PHP semgrep rules and the SQL-interpolation / sanitizer signals."""

from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.config import (
    HeuristicsConfig,
)
from appsec_triage.models import VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.prompts import registry


def test_correct_command_injection_survives_when_the_quote_is_real():
    """The failure that cost every true positive on DVWA.

    With `evidence` as bare strings the model wrote conclusions into it — "user
    input is concatenated into a shell command" — which correctly failed
    grounding and downgraded three correctly-confirmed command injections to
    `unknown`. Splitting quote from explanation is the fix.
    """
    snippet = "$target = $_REQUEST[ 'ip' ];\n$cmd = shell_exec( 'ping  ' . $target );"
    finding = _finding(snippet, cwe="CWE-78", path="vulnerabilities/exec/source/low.php")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            evidence_class="EXPLOITABLE_DATAFLOW",
            cwe="CWE-78",
            evidence=[
                {
                    "quote": "$cmd = shell_exec( 'ping  ' . $target );",
                    "why": "user input is concatenated straight into the command string",
                },
                {"quote": "$target = $_REQUEST[ 'ip' ];", "why": "the value comes from the HTTP request"},
            ],
            reason="Request parameter reaches shell_exec with no sanitisation.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed, "a sound verdict must survive"
    assert all(e.grounded for e in record.verdict.evidence)
    assert not any("hallucinated" in o for o in record.overrides)


def test_conclusions_in_the_quote_field_are_still_rejected():
    """The anti-hallucination property must not be lost to the new shape."""
    finding = _finding("$cmd = shell_exec( 'ping  ' . $target );", cwe="CWE-78")
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-78",
            evidence=[{"quote": "user input is concatenated into a shell command", "why": ""}],
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("hallucinated_evidence" in o for o in record.overrides)


def test_php_rules_catch_the_canonical_sqli_and_xss_forms():
    """Both gaps were found by DVWA, and both are the *usual* PHP shape.

    PHP interpolates inside double quotes, so its commonest SQLi has no
    concatenation operator; and reflected XSS is usually built into a buffer
    that is echoed later, not echoed inline.
    """
    import re

    import yaml

    from appsec_triage.config import REPO_ROOT

    rules = {
        r["id"]: r for r in yaml.safe_load((REPO_ROOT / "rules/semgrep/php.yaml").read_text(encoding="utf-8"))["rules"]
    }

    def fires(rule_id: str, code: str) -> bool:
        rule = rules[rule_id]
        pats = (
            [p["pattern-regex"] for p in rule.get("pattern-either", [])]
            if "pattern-either" in rule
            else [rule["pattern-regex"]]
        )
        return any(re.search(p, code) for p in pats)

    assert fires("php-sql-concatenation", "$query = \"SELECT first_name FROM users WHERE user_id = '$id';\";")
    assert fires("php-sql-concatenation", '$q = "UPDATE users SET name = {$name} WHERE id = 1";')
    # Single quotes do not interpolate in PHP — this must not fire.
    assert not fires("php-sql-concatenation", "$query = 'SELECT first_name FROM users WHERE user_id = 1';")

    assert fires("php-echo-request-value", "$html .= '<pre>Hello ' . $_GET[ 'name' ] . '</pre>';")
    assert not fires("php-echo-request-value", "$html .= '<pre>Hello world</pre>';")


# --- regression: the seven SQLi misses measured on DVWA ------------------------


def test_interpolated_sql_fires_a_deterministic_signal():
    """The model believes quoting a variable inside SQL is parameterisation.

    Measured on DVWA: seven vulnerable queries closed as false positives on that
    reasoning. The prompt now says otherwise, but a signal is what survives the
    model repeating the belief — the same lesson as CWE-295.
    """
    from appsec_triage.context import heuristics

    vulnerable = [
        "$query = \"SELECT first_name FROM users WHERE user_id = '$id';\";",
        '$q = "SELECT * FROM t WHERE id = {$id}";',
        'query = f"SELECT * FROM users WHERE id = {user_id}"',
        "const q = `SELECT * FROM users WHERE id = ${id}`;",
        '$sql = "SELECT * FROM users WHERE id = " . $id;',
    ]
    for snippet in vulnerable:
        finding = _finding(snippet, cwe="CWE-89")
        names = {s.name for s in heuristics.evaluate(finding, HeuristicsConfig()).signals}
        assert "sql_value_interpolated" in names, snippet

    safe = [
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
        '$stmt = $conn->prepare("SELECT * FROM users WHERE id = :id");',
        "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
    ]
    for snippet in safe:
        finding = _finding(snippet, cwe="CWE-89")
        names = {s.name for s in heuristics.evaluate(finding, HeuristicsConfig()).signals}
        assert "sql_value_interpolated" not in names, snippet


def test_quoting_excuse_cannot_close_an_interpolated_query():
    """The exact failure: 'the variable is properly quoted, so it is safe'."""
    finding = _finding(
        "$query = \"SELECT first_name FROM users WHERE user_id = '$id';\";",
        cwe="CWE-89",
        path="vulnerabilities/sqli/source/low.php",
    )
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=[
                {
                    "quote": "$query = \"SELECT first_name FROM users WHERE user_id = '$id';\";",
                    "why": "the variable is enclosed in single quotes",
                }
            ],
            reason="The code uses proper SQL quoting around the $id variable, which prevents SQL injection.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown, "a deterministic signal must block this closure"
    assert any("sanity_conflict" in o for o in record.overrides)


def test_a_genuinely_parameterised_query_still_closes():
    """The guard must not make every SQL finding unclosable."""
    finding = _finding(
        "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
        cwe="CWE-89",
    )
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=[
                {
                    "quote": "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = ?');",
                    "why": "placeholder is bound, the value never enters the SQL text",
                }
            ],
            reason="Parameterised query with a bound placeholder.",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.overrides == []


def test_dataflow_findings_look_further_back_for_the_sanitiser(tmp_path):
    """DVWA's fixed command injection was confirmed because the guard was cropped.

    A symmetric +/-6 window around `shell_exec` cut the four `is_numeric()`
    octet checks out of view, and the model wrote "there is no sanitization" —
    accurate for what it had been shown.
    """
    from appsec_triage.config import PipelineConfig
    from appsec_triage.context import builder, heuristics
    from appsec_triage.context.source import SourceResolver

    src = tmp_path / "impossible.php"
    lines = ["<?php"]
    lines += [f"// filler {i}" for i in range(10)]
    lines.append("if( is_numeric( $octet[0] ) && is_numeric( $octet[1] ) ) {")
    lines += [f"    // filler {i}" for i in range(12)]
    lines.append("    $cmd = shell_exec( 'ping  ' . $target );")
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    sink_line = len(lines)

    resolver = SourceResolver([tmp_path])
    cfg = PipelineConfig()

    injection = _finding("$cmd = shell_exec( 'ping  ' . $target );", cwe="CWE-78", path="impossible.php")
    injection.code_context.start_line = sink_line
    injection.code_context.end_line = sink_line
    pkg = builder.build(injection, heuristics.evaluate(injection, HeuristicsConfig()), cfg, None, resolver)
    assert "is_numeric" in pkg.code_context, "the guard above the sink must be visible"

    # A credential is still judged on a narrow window — no need to drag in 30 lines.
    secret = _finding('$password = "hunter2";', cwe="CWE-798", path="impossible.php")
    secret.code_context.start_line = sink_line
    secret.code_context.end_line = sink_line
    pkg = builder.build(secret, heuristics.evaluate(secret, HeuristicsConfig()), cfg, None, resolver)
    assert "is_numeric" not in pkg.code_context


# --- shared prompt fragments ---------------------------------------------------


def test_sanitizer_knowledge_reaches_the_dataflow_classes():
    """Both false alarms left on DVWA were blocklist-vs-allowlist confusion.

    The knowledge belongs to no single CWE — injection, traversal and crypto all
    need it — so it lives in a shared fragment rather than being copied.
    """
    for cwe in ("CWE-78", "CWE-89", "CWE-79", "CWE-327", "CWE-295"):
        system, _ = registry.render_system(cwe)
        assert "Allowlist — effective" in system, cwe
        assert "Blocklist — not effective" in system, cwe


def test_shared_fragments_are_never_selected_as_a_prompt():
    """A fragment has no `applies_to`; picking one for a CWE would drop the base rules."""
    prompt = registry.resolve("CWE-89")
    assert prompt.id == "injection"
    assert not prompt.shared
    assert "_sanitizers" not in registry.coverage().values()


def test_secret_findings_stay_lean():
    """A credential verdict does not need the sanitiser essay; prompt length costs attention."""
    injection, _ = registry.render_system("CWE-89")
    secret, _ = registry.render_system("CWE-798")
    assert "Allowlist — effective" not in secret
    assert len(secret) < len(injection)


def test_self_check_step_is_present():
    system, _ = registry.render_system("CWE-89")
    assert "Does `reason` agree with `verdict`?" in system


# --- adversarial second pass ---------------------------------------------------
