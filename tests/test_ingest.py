"""Ingest dedup/agreement, Psalm SARIF mapping, and LSP column/definition resolution."""

from __future__ import annotations

import json

from _helpers import _cfg, _finding, _verdict_json

from appsec_triage import ingest
from appsec_triage.config import (
    HeuristicsConfig,
)
from appsec_triage.models import CodeContext, Finding
from appsec_triage.validate.schema import parse_verdict


def _finding_from(scanner, *, trace=(), snippet="$q = 'SELECT ' . $id;", cwe="CWE-89", rule="r"):
    from appsec_triage.models import TraceStep

    return Finding(
        finding_id=f"{scanner}-1",
        scanner=scanner,
        rule_id=f"{scanner}.{rule}",
        cwe=cwe,
        code_context=CodeContext(file_path="src/Repo.php", start_line=42, snippet=snippet),
        trace=[TraceStep(file_path="src/Repo.php", line=40, message=m, role="source") for m in trace],
    )


def test_the_finding_carrying_a_trace_survives_deduplication():
    """ "The deep tool leads" in practice: the record with `codeFlows` wins."""
    from appsec_triage.ingest import _dedupe

    shallow = _finding_from("semgrep")
    deep = _finding_from("codeql", trace=["user input from getParameter"])

    kept = _dedupe([shallow, deep])
    assert len(kept) == 1
    assert kept[0].scanner == "codeql"
    assert kept[0].trace, "the trace is the whole reason to prefer it"
    assert kept[0].corroborated_by == ["semgrep"]


def test_agreement_becomes_a_signal_the_model_can_read():
    from appsec_triage.context import heuristics

    finding = _finding_from("codeql", trace=["src"])
    finding.corroborated_by = ["semgrep"]
    signals = {s.name: s for s in heuristics.evaluate(finding, HeuristicsConfig()).signals}

    assert "corroborated_by_another_scanner" in signals
    assert signals["corroborated_by_another_scanner"].direction == "toward_confirmed"


def test_a_lone_finding_is_not_marked_as_corroborated():
    from appsec_triage.ingest import _dedupe

    kept = _dedupe([_finding_from("semgrep")])
    assert kept[0].corroborated_by == []


def test_different_weakness_classes_at_one_line_are_not_merged():
    """Two tools flagging different things is not agreement."""
    from appsec_triage.ingest import _dedupe

    sqli = _finding_from("semgrep", cwe="CWE-89")
    secret = _finding_from("gitleaks", cwe="CWE-798")
    assert len(_dedupe([sqli, secret])) == 2


def test_ingest_ignores_tool_working_directories(tmp_path):
    """A CodeQL database sits beside the SARIF and is not a report."""
    db = tmp_path / ".codeql-db-python" / "diagnostic"
    db.mkdir(parents=True)
    (db / "baseline-info.json").write_text('{"languages": ["python"]}', encoding="utf-8")
    (tmp_path / "codeql.sarif.json").write_text(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql","rules":[{"id":"r"}]}},'
        '"results":[{"ruleId":"r","message":{"text":"x"},'
        '"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},'
        '"region":{"startLine":1,"snippet":{"text":"x = 1"}}}}]}]}]}',
        encoding="utf-8",
    )
    findings = ingest.load(tmp_path)
    assert len(findings) == 1 and findings[0].scanner == "codeql"


def test_the_challenger_is_given_the_same_knowledge_as_the_verdict_it_audits():
    """Built on `base` alone it overturned eleven correct verdicts on a blocklist.

    A reviewer who knows less than the author does not review, it second-guesses.
    """
    from appsec_triage import verify
    from appsec_triage.context import builder, heuristics

    finding = _finding("$cmd = shell_exec($target);", cwe="CWE-78")
    pkg = builder.build(finding, heuristics.evaluate(finding, HeuristicsConfig()), _cfg())
    verdict = parse_verdict(_verdict_json(verdict="confirmed", cwe="CWE-78"))

    system, _user = verify._render_prompt(pkg, verdict, "input")

    assert "Blocklist — not effective" in system, "the sanitiser knowledge must reach the challenger"
    assert "Quoting is not parameterisation" in system, "so must the CWE specialization"
    assert "a refutation of an injection verdict" in system


def test_shipped_configs_load():
    """A config that does not parse breaks every command with a stack trace.

    Caught the hard way: a `sed` meant for one section added `mode:` to five of
    them, and nothing noticed until the next run failed at startup.
    """
    from appsec_triage.config import load_lsp_config, load_pipeline_config

    cfg = load_pipeline_config()
    assert cfg.verification.mode in ("advisory", "authoritative")
    assert cfg.queue.review_budget_pct > 0
    load_lsp_config()


def test_two_rules_on_one_line_stay_two_findings():
    """Regression: corroboration grouping collapsed same-scanner rules.

    On a real project it turned 74 findings into 48. Two rules firing on one
    config line are two questions — a credential-shaped literal and a connection
    string are not the same decision — and a lost finding is the one outcome this
    pipeline must never produce.
    """
    from appsec_triage.ingest import _dedupe

    a = _finding_from("semgrep", rule="credential-named-assignment")
    b = _finding_from("semgrep", rule="connection-string-with-password")
    kept = _dedupe([a, b])

    assert len(kept) == 2
    assert {k.rule_id for k in kept} == {
        "semgrep.credential-named-assignment",
        "semgrep.connection-string-with-password",
    }
    assert all(k.corroborated_by == [] for k in kept), "one scanner is not agreement"


def test_one_weakness_seen_by_two_scanners_is_one_decision():
    """Cross-tool duplication collapses; the trace-carrying record wins."""
    from appsec_triage.ingest import _dedupe

    shallow = _finding_from("semgrep", rule="sqli")
    deep = _finding_from("codeql", rule="sqli", trace=["source"])
    kept = _dedupe([shallow, deep])

    assert len(kept) == 1
    assert kept[0].scanner == "codeql" and kept[0].corroborated_by == ["semgrep"]


def test_lsp_columns_are_computed_on_the_unstripped_line(tmp_path):
    """Display formatting must not leak into position arithmetic.

    `_line_text` strips for readability; using it to compute columns shifted
    every offset by the indent, put the cursor inside the wrong identifier, and
    the server answered nothing — which read as "it cannot resolve locals".
    """
    from appsec_triage.config import LSPConfig
    from appsec_triage.lsp.service import LSPService

    src = tmp_path / "Repo.php"
    src.write_text("<?php\n        $query = $this->run($sql);\n", encoding="utf-8")

    svc = LSPService(LSPConfig(), [tmp_path])
    raw = svc._raw_line(src, 2)
    shown = svc._line_text(src, 2)

    assert raw.startswith("        "), "the raw line keeps its indentation"
    assert shown == "$query = $this->run($sql);"
    assert raw.index("$sql") != shown.index("$sql"), "the two differ by the indent — that was the bug"


# --- PHP: Psalm taint ingest + LSP taint-source signal ------------------------


def _psalm_sarif(rule_name: str, message: str, *, with_flow: bool = True) -> dict:
    """A minimal SARIF in Psalm's real shape: numeric ruleId, the taint type in
    `name`, only a `security` tag, and a codeFlow. Psalm carries no CWE, which is
    exactly what the ingest mapping has to supply."""
    loc = {
        "physicalLocation": {
            "artifactLocation": {"uri": "src/Repo.php"},
            "region": {"startLine": 5, "snippet": {"text": "$pdo->query($sql);"}},
        }
    }
    result = {
        "ruleId": "999",
        "message": {"text": message},
        "locations": [loc],
    }
    if with_flow:
        result["codeFlows"] = [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Repo.php"},
                                        "region": {"startLine": 4},
                                    },
                                    "message": {"text": "taint source"},
                                }
                            },
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/Repo.php"},
                                        "region": {"startLine": 5},
                                    },
                                    "message": {"text": "sink"},
                                }
                            },
                        ]
                    }
                ]
            }
        ]
    return {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Psalm",
                        "version": "6.16.1",
                        "rules": [
                            {
                                "id": "999",
                                "name": rule_name,
                                "shortDescription": {"text": rule_name},
                                "properties": {"tags": ["security"]},
                            }
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": True}],
                "results": [result],
            }
        ]
    }


def test_psalm_taint_types_map_to_cwe_and_keep_the_trace(tmp_path):
    """Psalm's SARIF names the sink type (`TaintedSql`) but no CWE. The mapping
    has to supply it, or the finding routes to the base prompt and the queue's
    consequence weighting sees nothing."""
    from appsec_triage.ingest import sarif

    cases = {
        "TaintedSql": "CWE-89",
        "TaintedHtml": "CWE-79",
        "TaintedShell": "CWE-78",
        "TaintedInclude": "CWE-98",
        "TaintedUnserialize": "CWE-502",
    }
    for name, expected in cases.items():
        path = tmp_path / f"{name}.sarif.json"
        path.write_text(json.dumps(_psalm_sarif(name, f"Detected {name}")), encoding="utf-8")
        findings = list(sarif.parse(path))
        assert len(findings) == 1, name
        assert findings[0].cwe == expected, f"{name} -> {findings[0].cwe}, expected {expected}"
        assert findings[0].trace, f"{name}: the codeFlow must survive ingest"
        assert findings[0].source and findings[0].sink


def test_psalm_and_semgrep_at_the_same_place_corroborate_with_psalm_winning(tmp_path):
    """Two tools agreeing is evidence. Psalm carries the taint trace, so its
    record must win the merge and record semgrep as corroboration."""
    from appsec_triage.ingest import _dedupe, sarif

    ppath = tmp_path / "psalm.sarif.json"
    ppath.write_text(json.dumps(_psalm_sarif("TaintedSql", "Detected TaintedSql")), encoding="utf-8")
    psalm_findings = list(sarif.parse(ppath))

    # A semgrep-shaped finding at the same CWE/file/line, but with no trace.
    semgrep = _finding_from("semgrep", cwe="CWE-89")
    semgrep.code_context.file_path = "src/Repo.php"
    semgrep.code_context.start_line = 5

    kept = _dedupe([semgrep, *psalm_findings])
    assert len(kept) == 1
    assert kept[0].scanner == "Psalm"
    assert kept[0].corroborated_by == ["semgrep"]
    assert kept[0].trace, "the trace-bearing Psalm record must be the survivor"


def test_lsp_resolved_taint_source_becomes_a_confirming_signal_below_the_block_threshold():
    """When the language server resolves an interpolated value to user input, the
    model must be told — but not so strongly that every sanitized false_positive
    on the class gets forced to unknown. The signal is `toward_confirmed` yet its
    weight stays under the 0.7 blanket-block threshold post-validation uses."""
    from appsec_triage.context import builder, heuristics
    from appsec_triage.lsp.client import Location
    from appsec_triage.lsp.service import SymbolContext

    finding = _finding(
        '$sql = "SELECT * FROM users WHERE id = \'" . $id . "\'";',
        cwe="CWE-89",
        path="src/Repo.php",
    )
    heur = heuristics.evaluate(finding, HeuristicsConfig(enabled=True))
    symbols = SymbolContext(
        definitions=[Location(file_path="src/Repo.php", line=4, text="$id = $_GET['id'];", symbol="$id")],
        taint_sources=[Location(file_path="src/Repo.php", line=4, text="$id = $_GET['id'];", symbol="$id")],
        resolved=True,
    )
    pkg = builder.build(finding, heur, _cfg(), None, None, symbols)

    sig = next((s for s in pkg.heuristic_signals if s.name == "lsp_resolved_taint_source"), None)
    assert sig is not None, "the resolved taint source must surface as a signal"
    assert sig.direction == "toward_confirmed"
    assert sig.weight < 0.7, "must stay below the blanket false_positive->unknown block"
    assert "$_GET" in "".join(pkg.symbol_context)


def test_php_definitions_resolve_dollar_variables_before_method_names():
    """On an injection sink the interpolated `$`-variable decides the verdict; it
    must be resolved before the definition budget is spent on method names."""
    from appsec_triage.config import LSPConfig
    from appsec_triage.lsp.service import LSPService

    class _FakeClient:
        def __init__(self):
            self.asked: list[str] = []

        def definition(self, path, line, character):
            # Record which identifier (by column) was asked about, in call order.
            return []

    line = "$query = $this->getEntityManager()->createNativeQuery($sql, $rsm);"
    svc = LSPService(LSPConfig(max_definitions=4), ["/tmp"])
    fake = _FakeClient()

    # The resolver points the cursor one past a `$` sigil, so detect a variable
    # by the character immediately before the requested column.
    order: list[bool] = []  # True == this query was for a $-variable

    def _definition(path, line_no, character):
        order.append(character > 0 and line[character - 1] == "$")
        return []

    fake.definition = _definition
    from pathlib import Path

    svc._definitions_in(fake, Path("/tmp/Repo.php"), 1, line)

    dollar_positions = [i for i, is_dollar in enumerate(order) if is_dollar]
    nondollar_positions = [i for i, is_dollar in enumerate(order) if not is_dollar]
    assert dollar_positions, "some $-variables were queried"
    assert max(dollar_positions) < min(nondollar_positions or [10**6]), (
        f"all $-variables must be queried before any non-$ identifier; dollar={dollar_positions} "
        f"nondollar={nondollar_positions}"
    )


def test_the_agent_can_read_what_it_writes(tmp_path):
    """ wrote a file  refused to open: the location is nested and
    the package sat in a field the parser ignored, so any dependency loaded this
    way silently lost the two things the SCA chain runs on."""
    import json as _json

    from appsec_triage.ingest import native

    path = tmp_path / "deps.json"
    path.write_text(_json.dumps([{
        "finding_id": "GHSA-x-guzzle",
        "scanner": "cdxgen+osv",
        "rule_id": "GHSA-x",
        "code_context": {"file_path": "composer.json"},
        "dependency": {"package": "guzzlehttp/guzzle", "ecosystem": "composer",
                        "installed_version": "7.4.1", "dev_only": None},
    }]), encoding="utf-8")

    findings = list(native.parse(path))

    assert len(findings) == 1
    assert findings[0].code_context.file_path == "composer.json"
    assert findings[0].dependency is not None
    assert findings[0].dependency.package == "guzzlehttp/guzzle"
    assert findings[0].dependency.installed_version == "7.4.1"
