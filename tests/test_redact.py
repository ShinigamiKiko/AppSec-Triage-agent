"""A secret's shape goes to the model; the secret does not.

Measured on a real project: the flagged lines in one committed `.env` held 32-
and 64-character signing keys and OAuth secrets. Triaging them through a hosted
provider would have written live credentials into a third party's request logs —
while looking for exactly that class of problem.
"""

from __future__ import annotations

from appsec_triage.config import ProviderConfig, load_pipeline_config
from appsec_triage.redact import redact_secrets


def test_a_high_entropy_key_is_replaced_by_its_shape():
    out, n = redact_secrets("ATS_SIGN_KEY=PBD2Y6XMfsn5KZinLGzE4IIi7FZmx4Hm")
    assert n == 1
    assert "PBD2Y6XM" not in out
    # What the verdict actually needs survives: length, alphabet, randomness.
    assert "32 chars" in out and "entropy" in out
    assert "ATS_SIGN_KEY" in out


def test_a_placeholder_stays_visible():
    # `local`, `toor`, `changeme` are the evidence that closes the finding.
    # Hiding them would remove the reason to close it.
    for line in ("POSTGRES_PASSWORD=local", "S3_ACCESS_SECRET=minio123", "$password = 'changeme';"):
        out, n = redact_secrets(line)
        assert n == 0 and out == line


def test_a_sql_fragment_is_not_mistaken_for_a_key():
    # Entropy alone puts an AWS key (3.68) and "SELECT * FROM t WHERE id = "
    # (3.66) on the same side. Redacting the query would delete the evidence an
    # injection verdict rests on — whitespace is what separates them.
    line = 'String q = "SELECT * FROM t WHERE id = " + userId;'
    assert redact_secrets(line) == (line, 0)


def test_an_expression_is_never_redacted():
    # An earlier version accepted any unquoted run after `=` and replaced
    # `String.valueOf(new` — deleting the evidence for a weak-randomness finding
    # to protect a value that was not there.
    line = "String sessionId = String.valueOf(new Random().nextLong());"
    assert redact_secrets(line) == (line, 0)


def test_a_url_keeps_its_host():
    # A reviewer needs to see where it points; the host is not the credential.
    line = "MEDIA_URL=http://media.dev.sberwork.space"
    assert redact_secrets(line) == (line, 0)


def test_the_local_provider_does_not_pay_the_cost():
    """Redaction loses information, so it is applied only where it buys something.

    Ollama runs where the pipeline runs — nothing leaves — so the default is off
    and the CLI turns it on for a hosted provider.
    """
    ollama = ProviderConfig(name="ollama", kind="ollama", model="m", base_url="http://localhost:11434")
    deepseek = ProviderConfig(name="deepseek", kind="deepseek", model="m", base_url="https://api.deepseek.com/v1")
    assert ollama.leaves_the_perimeter is False
    assert deepseek.leaves_the_perimeter is True
    assert load_pipeline_config().redact_secrets is False
