"""The chain as the pipeline actually runs it.

Testing the parts separately leaves the wiring untested, and the wiring is where
this can go wrong quietly: a chain that never runs costs nothing visible, and a
chain whose section never reaches the prompt looks identical to one that did.

The databases and the registry are replaced here. What is being checked is the
pipeline's behaviour around the chain — that it runs for dependency findings and
not for others, that the one deterministic closure happens without a model call,
and that a lookup failure degrades the finding instead of the run.
"""

from __future__ import annotations

from pathlib import Path

from _helpers import _PROVIDER, FakeClient, _cfg, _verdict_json

from appsec_triage.models import CodeContext, DependencyInfo, Finding, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.sca import advisories as adv
from appsec_triage.sca.chain import DependencyChain


def _dependency_finding(cwe="CWE-79") -> Finding:
    return Finding(
        finding_id="dep-1",
        scanner="trivy",
        rule_id="GHSA-g446-98w2-8p5w",
        cwe=cwe,
        code_context=CodeContext(file_path="composer.lock"),
        dependency=DependencyInfo(
            package="guzzlehttp/guzzle", ecosystem="composer",
            installed_version="7.4.1", fixed_versions=["7.4.5"],
        ),
    )


def _config(**kwargs):
    cfg = _cfg(**kwargs)
    cfg.resolve_vulnerable_symbols = True
    return cfg


class _StubChain:
    """Stands in for the network half, so the wiring is what gets tested."""

    def __init__(self, result) -> None:
        self._result = result
        self.calls = 0

    def run(self, finding, *, codeql_findings=()):
        self.calls += 1
        return self._result


def test_the_chain_runs_for_a_dependency_and_its_section_reaches_the_prompt(tmp_path):
    from appsec_triage.sca.presence import Hit, PresenceResult, SymbolPresence
    from appsec_triage.sca.resolve import VulnerableSymbol
    from appsec_triage.sca.chain import ChainResult
    from appsec_triage.sca.verdict import decide

    result = ChainResult(
        decide(
            VulnerableSymbol("GHSA-g446-98w2-8p5w", "guzzlehttp/guzzle",
                             function="matchesDomain", klass="SetCookie",
                             confirmed_in_source=True),
            PresenceResult(SymbolPresence.CALLED, "SetCookie::matchesDomain",
                           [Hit("src/Http.php", 12, "$c->matchesDomain($h);")]),
            None, cwe="CWE-79",
        )
    )

    client = FakeClient(_verdict_json(verdict="confirmed"))
    pipeline = TriagePipeline(client, _PROVIDER, _config())
    pipeline.dep_chain = _StubChain(result)

    record = pipeline.triage_one(_dependency_finding())

    assert pipeline.dep_chain.calls == 1
    assert "matchesDomain" in client.calls[-1][1], "the chain's section never reached the model"
    assert "src/Http.php:12" in client.calls[-1][1]
    assert record.kind == "dependency"


def test_code_not_in_the_installed_package_closes_without_the_model():
    from appsec_triage.sca.chain import ChainResult
    from appsec_triage.sca.resolve import VulnerableSymbol
    from appsec_triage.sca.verdict import decide

    result = ChainResult(
        decide(VulnerableSymbol("GHSA-x", "phpoffice/phpspreadsheet",
                                file="samples/Convert-Online.php", not_distributed=True),
               None, None, cwe="CWE-79")
    )

    client = FakeClient(_verdict_json(verdict="confirmed"))
    pipeline = TriagePipeline(client, _PROVIDER, _config())
    pipeline.dep_chain = _StubChain(result)

    record = pipeline.triage_one(_dependency_finding())

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.decided_by == "heuristics"
    assert not client.calls, "the model was called for a decision that needs no model"


def test_a_failing_lookup_costs_the_context_not_the_finding():
    class _Broken:
        def run(self, finding, *, codeql_findings=()):
            raise adv.DatabaseUnavailable("api.osv.dev -> timed out")

    client = FakeClient(_verdict_json(verdict="unknown"))
    pipeline = TriagePipeline(client, _PROVIDER, _config())
    pipeline.dep_chain = _Broken()

    record = pipeline.triage_one(_dependency_finding())

    assert record.verdict is not None, "one failed lookup must not lose the finding"
    assert client.calls, "the model should still have been asked"


def test_the_chain_is_not_run_for_first_party_findings():
    client = FakeClient(_verdict_json(verdict="confirmed"))
    pipeline = TriagePipeline(client, _PROVIDER, _config())
    pipeline.dep_chain = _StubChain(None)

    finding = Finding(
        finding_id="w-1", scanner="semgrep", rule_id="r", cwe="CWE-89",
        code_context=CodeContext(file_path="src/App.php", snippet="$db->query($id);"),
    )
    pipeline.triage_one(finding)
    assert pipeline.dep_chain.calls == 0


def test_disabled_by_default():
    pipeline = TriagePipeline(FakeClient(_verdict_json()), _PROVIDER, _cfg())
    assert pipeline.dep_chain is None


def test_advisory_identifiers_prefer_ghsa_over_cve():
    """GHSA carries the maintainer's prose, which is what names the symbol."""
    finding = _dependency_finding()
    finding.dependency.advisory_url = "https://osv.dev/vulnerability/CVE-2022-31091"
    assert DependencyChain._identifiers(finding)[0].startswith("GHSA-")


def test_only_codeql_findings_with_a_trace_are_kept_for_reachability(tmp_path):
    from appsec_triage.models import TraceStep

    client = FakeClient(_verdict_json(verdict="unknown"))
    pipeline = TriagePipeline(client, _PROVIDER, _config())
    pipeline.dep_chain = _StubChain(None)

    with_trace = Finding(
        finding_id="cq-1", scanner="codeql", rule_id="q", cwe="CWE-79",
        code_context=CodeContext(file_path="src/A.php"),
        trace=[TraceStep(file_path="src/A.php", line=3, message="$_GET['x']", role="source"),
               TraceStep(file_path="src/B.php", line=9, message="echo $x;", role="sink")],
    )
    without = Finding(
        finding_id="cq-2", scanner="codeql", rule_id="q", cwe="CWE-79",
        code_context=CodeContext(file_path="src/C.php"),
    )
    pipeline.run([with_trace, without])
    assert [f.finding_id for f in pipeline._codeql_findings] == ["cq-1"]
