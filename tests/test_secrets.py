"""A credential is judged from its value, deterministically and without a model.

Reachability does not enter into it: a key committed to a repository has leaked
whether or not any code path reaches it, and rotation is the remedy either way.
Every case below is a line taken from a real project.
"""

from __future__ import annotations

import pytest

from appsec_triage.secrets import classify, flagged_value


def verdict_for(line: str) -> str:
    return classify(flagged_value(line))[0]


@pytest.mark.parametrize(
    "line",
    [
        "ATS_SIGN_KEY=PBD2Y6XMfsn5KZinLGzE4IIi7FZmx4Hm",
        "HH_CLIENT_SECRET=S3UI6RTFAG32KH24QNBFGODFJOAJRCBJFVD3EG494H7VCLM3FEJAIPNNJR5PUM23",
        # A hardcoded HMAC key in PHP source. The model abstained on this one;
        # the shape does not leave room to abstain.
        "private const TOKEN_SECRET_KEY = 'c66P9yWptBX79edHcglIw7NFyse35be';",
    ],
)
def test_a_generated_key_is_reported(line):
    assert verdict_for(line) == "credential"


@pytest.mark.parametrize(
    "line",
    [
        "POSTGRES_PASSWORD=local",
        "S3_ACCESS_SECRET=minio123",
        "$password = 'changeme';",
        "APP_SECRET=",
        "DB_PASS=${DB_PASSWORD}",
        "MAILER_DSN=%env(MAILER_URL)%",
        "api_key = '<your-api-key-here>'",
    ],
)
def test_a_placeholder_closes_the_finding(line):
    assert verdict_for(line) == "placeholder"


@pytest.mark.parametrize(
    "line",
    [
        # Constant names, routes, class names and container references. All pass
        # an entropy floor and none is a secret — structure is what separates
        # them: a name has dictionary segments joined by delimiters, a generated
        # key has no such seams.
        "public const CHECK_CREDENTIALS_OPERATION_NAME = 'check_credentials';",
        "private const REFRESH_TOKEN_URL = '/oauth/refresh-token.json';",
        r"authentication_tokens_types: 'App\Doctrine\Type\AuthenticationTokensTypes'",
        "$tokenVerifier: '@app.security.key_verifier'",
    ],
)
def test_an_identifier_is_not_a_credential(line):
    assert verdict_for(line) == "placeholder"


def test_a_connection_string_is_judged_on_its_password():
    """The whole DSN scores as random; the password inside it is `toor`.

    Measured on a real project this was the single largest source of
    over-reporting — 8 findings — before the password was pulled out and judged
    on its own.
    """
    assert verdict_for("ATS_RABBITMQ_DSN=amqp://admin:toor@rabbitmq:5672/%2f") == "placeholder"
    assert verdict_for("DSN=amqp://admin:Xk92mPqRs7vTnB4wLcYe@host:5672/x") == "credential"


def test_an_ambiguous_value_goes_to_the_model_rather_than_being_guessed():
    # Neither clearly generated nor clearly a default. Guessing here is exactly
    # the asymmetric error this policy exists to avoid.
    # Ten characters of interleaved case and digits: short, but exactly what a
    # generated password looks like. Closing it on length would be the
    # asymmetric error.
    assert classify("Xk92mPqRs7")[0] == "unclear"
    assert classify(None)[0] == "unclear"


def test_one_credential_is_one_finding_however_many_rules_spotted_it():
    """Measured on two real projects: 18 lines carried the same assignment twice.

    `default-password-in-config` reports it as CWE-259 and
    `credential-named-assignment` as CWE-798 — one key, two verdicts, two slots
    in a budget-capped queue.
    """
    from appsec_triage.ingest import _dedupe
    from appsec_triage.models import CodeContext, Finding

    def at(rule, cwe):
        return Finding(
            finding_id=rule,
            scanner="semgrep",
            rule_id=rule,
            cwe=cwe,
            code_context=CodeContext(file_path=".env", start_line=18, snippet="APP_SECRET=8924"),
        )

    merged = _dedupe([at("default-password-in-config", "CWE-259"), at("credential-named-assignment", "CWE-798")])
    assert len(merged) == 1


def test_two_genuinely_different_weaknesses_on_one_line_both_survive():
    """The counter-example that keeps the merge narrow.

    `$sign === sha1(...)` is a timing-unsafe comparison *and* a weak hash. They
    have different fixes, so collapsing them would lose one.
    """
    from appsec_triage.ingest import _dedupe
    from appsec_triage.models import CodeContext, Finding

    def at(rule, cwe):
        return Finding(
            finding_id=rule,
            scanner="semgrep",
            rule_id=rule,
            cwe=cwe,
            code_context=CodeContext(file_path="Auth.php", start_line=177, snippet="$sign === sha1($x)"),
        )

    merged = _dedupe([at("php-timing-unsafe-secret-comparison", "CWE-208"), at("php-weak-hash-for-secret", "CWE-327")])
    assert len(merged) == 2
