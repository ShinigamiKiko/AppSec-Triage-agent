"""LSP-mandatory contract: no dataflow closure for a required language without resolution."""

from __future__ import annotations

from _helpers import _PHP_CLOSURE, _PHP_SNIPPET, _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.config import (
    PipelineConfig,
)
from appsec_triage.models import Severity, VerdictLabel
from appsec_triage.pipeline import TriagePipeline

# --- LSP is mandatory: no closure of a dataflow class without resolution ------


def _php_mandatory_cfg() -> PipelineConfig:
    from appsec_triage.config import LSPConfig

    cfg = _cfg()
    cfg.lsp = LSPConfig(required_languages=["php"], servers={"php": {"extensions": [".php"]}})
    return cfg


def test_php_dataflow_closure_without_lsp_answer_is_not_valid():
    """The user's contract: a verdict the model produced without the trace is not
    a verdict. A false_positive on a dataflow class in an LSP-mandatory language,
    built with no symbol resolution at all, must go to a human as unknown."""
    finding = _finding(_PHP_SNIPPET, cwe="CWE-89", path="src/Repository/UserRepository.php")
    client = FakeClient(_verdict_json(**_PHP_CLOSURE))
    record = TriagePipeline(client, _PROVIDER, _php_mandatory_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any(o.startswith("lsp_required_no_answer") for o in record.overrides)
    assert record.verdict.requires_human_review
    assert record.verdict.blocking_question, "the reviewer must be told what to check"


def test_php_closure_stands_when_the_resolver_actually_answered():
    """Same closure, but the language server resolved the line — the gate must
    not fire on a run where LSP did its job."""
    from appsec_triage.lsp.client import Location
    from appsec_triage.lsp.service import SymbolContext

    class _StubSymbols:
        def enrich(self, finding):
            return SymbolContext(
                definitions=[
                    Location(
                        file_path="src/Repository/UserRepository.php",
                        line=4,
                        text="$id = (int) $row['id'];",
                        symbol="$id",
                    )
                ],
                resolved=True,
            )

    finding = _finding(_PHP_SNIPPET, cwe="CWE-89", path="src/Repository/UserRepository.php")
    client = FakeClient(_verdict_json(**_PHP_CLOSURE))
    record = TriagePipeline(client, _PROVIDER, _php_mandatory_cfg(), symbols=_StubSymbols()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert not any(o.startswith("lsp_required_no_answer") for o in record.overrides)


def test_php_confirmed_without_lsp_stays_confirmed():
    """The gate is downgrade-only and aims at closures: confirming with less
    context errs toward review, which is the safe direction."""
    finding = _finding(
        '$sql = "SELECT * FROM users WHERE id = \'" . $id . "\'";',
        cwe="CWE-89",
        path="src/Repository/UserRepository.php",
        severity=Severity.high,
    )
    client = FakeClient(
        _verdict_json(
            verdict="confirmed",
            cwe="CWE-89",
            evidence_class="EXPLOITABLE_DATAFLOW",
            evidence=['$sql = "SELECT * FROM users WHERE id = \'" . $id . "\'";'],
            confidence=0.95,
        )
    )
    record = TriagePipeline(client, _PROVIDER, _php_mandatory_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.confirmed
    assert not any(o.startswith("lsp_required_no_answer") for o in record.overrides)


def test_php_non_dataflow_closure_is_not_gated_on_lsp():
    """A hardcoded-credential verdict is judged on the literal, not on a path —
    demanding symbol resolution there would manufacture unknowns for no safety."""
    finding = _finding(
        '$apiKey = "${SERVICE_TOKEN}";',
        cwe="CWE-798",
        path="src/Config/Keys.php",
    )
    client = FakeClient(_verdict_json(evidence=['$apiKey = "${SERVICE_TOKEN}";']))
    record = TriagePipeline(client, _PROVIDER, _php_mandatory_cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert not any(o.startswith("lsp_required_no_answer") for o in record.overrides)


def test_non_required_language_closure_is_untouched():
    """The same dataflow closure in a language with no mandatory resolver keeps
    working exactly as before — this is a PHP contract, not a global one."""
    finding = _finding(_PHP_SNIPPET, cwe="CWE-89", path="src/Repository/UserRepository.php")
    client = FakeClient(_verdict_json(**_PHP_CLOSURE))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert not any(o.startswith("lsp_required_no_answer") for o in record.overrides)


# --- the bench runs the deployed pipeline, resolvers included -----------------
