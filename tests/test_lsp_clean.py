"""LSP-resolved-clean path and the sanity gates that survive it."""

from __future__ import annotations

from _helpers import _PROVIDER, FakeClient, _cfg, _verdict_json

from appsec_triage.config import (
    PipelineConfig,
)
from appsec_triage.models import CodeContext, Finding, Severity, VerdictLabel
from appsec_triage.pipeline import TriagePipeline


def _orm_finding() -> Finding:
    """The createNativeQuery pattern: $select comes from ORM, not user input."""
    return Finding(
        finding_id="orm-1",
        scanner="semgrep",
        rule_id="php-sql-interpolation",
        cwe="CWE-89",
        title="SQL built by interpolation",
        severity=Severity.high,
        code_context=CodeContext(
            file_path="src/Repository/AioRepository.php",
            start_line=4,
            snippet=(
                '$rsm = $this->createResultSetMappingBuilder("aio");\n'
                "$select = $rsm->generateSelectClause();\n"
                '$sql = "SELECT $select FROM aio WHERE deleted_at < :term";\n'
                '$this->getEntityManager()->createNativeQuery($sql, $rsm)->setParameter("term", $t);'
            ),
        ),
    )


def _lsp_clean_cfg() -> PipelineConfig:
    """PHP mandatory with an LSP service that resolved definitions but found no taint."""
    from appsec_triage.config import LSPConfig

    cfg = _cfg()
    cfg.lsp = LSPConfig(required_languages=["php"], servers={"php": {"extensions": [".php"]}})
    return cfg


class _StubSymbolsClean:
    """LSP resolved $rsm and $sql — both origin-clean (ORM, no taint sources)."""

    @staticmethod
    def enrich(finding):
        from appsec_triage.lsp.client import Location
        from appsec_triage.lsp.service import SymbolContext

        ctx = SymbolContext()
        ctx.resolved = True
        ctx.definitions = [
            Location(
                file_path="src/Repository/AioRepository.php",
                line=1,
                text='$rsm = $this->createResultSetMappingBuilder("aio");',
                symbol="$rsm",
            ),
        ]
        ctx.taint_sources = []  # no user input found — ORM-generated
        ctx.reachable_from_entrypoint = None
        ctx.callers_all_non_production = None
        return ctx

    def close(self):
        pass


def test_orm_false_positive_passes_when_lsp_resolved_clean():
    """The whole reason for lsp_resolved_clean: $select comes from ORM builder,
    LSP resolved it, found no user-controlled origin. The sql_value_interpolated
    signal should not gate this verdict — and historically it did, sending a
    semantically correct deepseek answer to unknown."""
    finding = _orm_finding()
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=['$rsm = $this->createResultSetMappingBuilder("aio");'],
            reason="$select originates from ORM builder, not user input",
        )
    )
    record = TriagePipeline(client, _PROVIDER, _lsp_clean_cfg(), symbols=_StubSymbolsClean()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert not any("sanity_conflict" in o for o in record.overrides), (
        f"sanity_conflict fired despite lsp_resolved_clean: {record.overrides}"
    )


def test_sql_interpolation_gate_still_fires_without_lsp_resolution():
    """When LSP did not answer, sql_value_interpolated remains in the strong set
    and the gate must still block the closure — the resolver's absence means the
    ORM vs. user-input question is unanswered."""
    finding = _orm_finding()
    client = FakeClient(
        _verdict_json(
            verdict="false_positive",
            evidence_class="SANITIZED_DATAFLOW",
            cwe="CWE-89",
            evidence=['$rsm = $this->createResultSetMappingBuilder("aio");'],
            reason="ORM query builder generates the column list",
        )
    )
    # No LSP service → lsp_resolved_clean stays False
    record = TriagePipeline(client, _PROVIDER, _lsp_clean_cfg()).triage_one(finding)

    assert any("sanity_conflict" in o or "lsp_required_no_answer" in o for o in record.overrides), (
        "gate must still fire when LSP did not resolve the variables"
    )


def test_credential_sanity_gate_never_cleared_by_lsp():
    """high_entropy_literal and known_secret_shape are NOT in _DATAFLOW_CLEARABLE —
    a JWT that happens to come from a framework call is still a secret, and LSP
    saying 'no taint source found' does not clear those signals."""
    from appsec_triage.lsp.client import Location
    from appsec_triage.lsp.service import SymbolContext

    class _StubSymbolsSecret:
        @staticmethod
        def enrich(_finding):
            ctx = SymbolContext()
            ctx.resolved = True
            ctx.definitions = [Location(file_path="src/Cfg.php", line=1, text="$key = getJwtKey();", symbol="$key")]
            ctx.taint_sources = []
            ctx.reachable_from_entrypoint = None
            ctx.callers_all_non_production = None
            return ctx

        def close(self):
            pass

    # A real-looking secret literal: openai-style key triggers known_secret_shape
    secret_snippet = '$apiKey = "sk-abc123def456ghi789jkl012mno345pqr678stu";'
    finding = Finding(
        finding_id="s-1",
        scanner="test",
        rule_id="r",
        cwe="CWE-798",
        title="Hardcoded API key",
        severity=Severity.high,
        code_context=CodeContext(file_path="src/Cfg.php", start_line=1, snippet=secret_snippet),
    )
    cfg = _cfg()
    cfg.lsp = _lsp_clean_cfg().lsp
    # This test is about the *model* path: what post-validation does when a
    # model closes a real key and the resolver reports a clean dataflow. The
    # deterministic policy would settle this finding before the model is ever
    # called — a stronger guarantee, covered separately below — so it is turned
    # off here rather than allowed to hide the interaction under test.
    cfg.secrets_without_model = False
    client = FakeClient(
        _verdict_json(
            evidence=[secret_snippet],
            verdict="false_positive",
            evidence_class="TEST_PLACEHOLDER",
            cwe="CWE-798",
            reason="this key is from a secure vault via getJwtKey()",
        )
    )
    record = TriagePipeline(client, _PROVIDER, cfg, symbols=_StubSymbolsSecret()).triage_one(finding)

    assert any("sanity_conflict" in o for o in record.overrides), (
        "credential sanity gate must not be cleared by lsp_resolved_clean"
    )


def test_the_same_key_never_reaches_the_model_when_the_policy_is_on():
    """The stronger form of the guarantee above.

    With the deterministic policy enabled — the default — an OpenAI-shaped key
    is confirmed from its own shape, so there is no verdict for the sanity gate
    to rescue and no opportunity for the model to close it at all.
    """
    secret_snippet = '$apiKey = "sk-abc123def456ghi789jkl012mno345pqr678stu";'
    finding = Finding(
        finding_id="s-2",
        scanner="test",
        rule_id="r",
        cwe="CWE-798",
        title="Hardcoded API key",
        severity=Severity.high,
        code_context=CodeContext(file_path="src/Cfg.php", start_line=1, snippet=secret_snippet),
    )

    class NeverCalled(FakeClient):
        def complete(self, *a, **k):  # pragma: no cover - the point is it is not reached
            raise AssertionError("a credential must not be sent to the model")

    record = TriagePipeline(NeverCalled(), _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.confirmed
    assert record.decided_by == "heuristics"
