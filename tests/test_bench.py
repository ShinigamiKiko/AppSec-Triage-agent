"""Corpus materialization and the bench runner (incl. DeepSeek schema tolerance/repair)."""

from __future__ import annotations

import json

import pytest
from _helpers import _PHP_CLOSURE, _PHP_SNIPPET, _PROVIDER, FakeClient, _cfg, _finding, _verdict_json

from appsec_triage.scanners import selection
from appsec_triage.config import (
    ProviderConfig,
)
from appsec_triage.models import CodeContext, Finding, Severity, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.validate.schema import parse_verdict


def _corpus_finding(snippet: str, *, path: str, cwe: str, sink: str | None = None) -> Finding:
    return Finding(
        finding_id=f"bench-{path}",
        scanner="test",
        rule_id="test.rule",
        cwe=cwe,
        title="corpus entry",
        severity=Severity.high,
        code_context=CodeContext(file_path=path, start_line=1, snippet=snippet),
        sink=sink,
    )


def test_materialized_php_snippet_is_parseable_and_anchored_on_the_sink(tmp_path):
    """The bench used to score bare snippets: nothing on disk, nothing for
    phpactor to index, and `line: 1` pointing at the *source* assignment instead
    of the sink whose interpolated values decide the verdict. Materialization
    must fix all three, or LSP-on-bench is wiring without effect."""
    from appsec_triage.context.source import SourceResolver
    from appsec_triage.evals.materialize import materialize

    snippet = (
        "$id = $_GET['id'];\n"
        '$sql = "SELECT * FROM users WHERE id = \'" . $id . "\'";\n'
        "$rows = $pdo->query($sql)->fetchAll();"
    )
    finding = _corpus_finding(snippet, path="src/Controller/UserController.php", cwe="CWE-89", sink="$pdo->query($sql)")

    [placed] = materialize([finding], tmp_path)

    written = (tmp_path / "src/Controller/UserController.php").read_text()
    assert written.startswith("<?php\n"), "phpactor parses nothing without an opener"
    # <?php + blank line, then the three snippet lines: the sink sits on line 5.
    assert placed.code_context.start_line == 5
    assert placed.code_context.end_line == 5

    # The same resolver production uses must see exactly that line on disk.
    resolver = SourceResolver([tmp_path])
    assert resolver.line(placed.code_context.file_path, placed.code_context.start_line) == (
        "$rows = $pdo->query($sql)->fetchAll();"
    )


def test_materialize_rejects_paths_escaping_the_tree(tmp_path):
    """A corpus is input like any other: `../` in a file path must not write
    outside the tree it claims to describe."""
    from appsec_triage.evals.materialize import materialize

    finding = _corpus_finding("$x = 1;", path="../evil.php", cwe="CWE-89")
    with pytest.raises(ValueError):
        materialize([finding], tmp_path)


def test_two_scanners_one_snippet_stay_at_one_place_after_materialization(tmp_path):
    """Corroboration means "same place". Two scanners reporting the identical
    snippet must land on the same lines, not on two pasted copies of the code."""
    from appsec_triage.evals.materialize import materialize

    snippet = "$host = $_POST['host'];\nsystem('ping -c 1 ' . $host);"
    a = _corpus_finding(snippet, path="src/Service/Pinger.php", cwe="CWE-78", sink="system()")
    b = _corpus_finding(snippet, path="src/Service/Pinger.php", cwe="CWE-78", sink="system()")

    placed = materialize([a, b], tmp_path)

    assert placed[0].code_context.start_line == placed[1].code_context.start_line == 4
    written = (tmp_path / "src/Service/Pinger.php").read_text()
    assert written.count("system('ping") == 1


def test_bench_feeds_the_pipeline_from_a_real_tree(tmp_path, monkeypatch):
    """run_bench must exercise the deployed pipeline: the source resolver reads
    the materialized file (source_stats.resolved > 0), and the comparison table
    records the provenance so resolver-less numbers cannot masquerade as
    resolver-backed ones."""
    from appsec_triage.evals import runner

    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "finding_id": "b-1",
                "cwe": "CWE-79",
                "file_path": "src/Config/Keys.php",
                "line": 1,
                "snippet": '$apiKey = "${SERVICE_TOKEN}";',
                "label": "false_positive",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.setattr(runner, "load_provider_config", lambda name: _PROVIDER)
    monkeypatch.setattr(
        runner,
        "build_client",
        lambda cfg: FakeClient(_verdict_json(evidence=['$apiKey = "${SERVICE_TOKEN}";'])),
    )

    result = runner.run_bench(corpus, ["fake"], _cfg(), tmp_path / "out")

    assert result["materialized_corpus"] is True
    assert result["lsp"] is False  # default LSPConfig has enabled: false
    assert (tmp_path / "out/source/src/Config/Keys.php").is_file()
    assert result["source_stats"]["resolved"] >= 1, "the pipeline never read the materialized tree"
    assert result["detail"]["fake"]["agreement_decided"] == 100.0


def test_bench_refuses_to_score_a_mandatory_language_without_its_resolver(tmp_path):
    """The LSP-mandatory contract holds on the bench: PHP findings with no
    usable phpactor produce no numbers at all, not silently degraded ones —
    unless the caller opts out with --no-lsp, which the table then records."""
    from appsec_triage.config import LSPConfig
    from appsec_triage.evals.runner import BenchSetupError, run_bench

    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "finding_id": "b-php",
                "cwe": "CWE-89",
                "file_path": "src/Repo.php",
                "line": 1,
                "snippet": _PHP_SNIPPET,
                "label": "false_positive",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = _cfg()
    # Enabled, mandatory for PHP — but no server command configured at all.
    cfg.lsp = LSPConfig(enabled=True, required_languages=["php"], servers={"php": {"extensions": [".php"]}})

    with pytest.raises(BenchSetupError):
        run_bench(corpus, ["fake"], cfg, tmp_path / "out")


def test_bench_no_lsp_is_an_explicit_degradation_and_says_so(tmp_path, monkeypatch):
    """--no-lsp on the bench mirrors triage: the run completes, the mandatory
    gate downgrades the dataflow closure to unknown, and the comparison table
    carries lsp: false so the abstention is attributable."""
    from appsec_triage.config import LSPConfig
    from appsec_triage.evals import runner

    corpus = tmp_path / "corpus.jsonl"
    corpus.write_text(
        json.dumps(
            {
                "finding_id": "b-php",
                "cwe": "CWE-89",
                "file_path": "src/Repo.php",
                "line": 1,
                "snippet": _PHP_SNIPPET,
                "label": "false_positive",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    cfg = _cfg()
    cfg.lsp = LSPConfig(enabled=True, required_languages=["php"], servers={"php": {"extensions": [".php"]}})

    monkeypatch.setattr(runner, "load_provider_config", lambda name: _PROVIDER)
    monkeypatch.setattr(
        runner,
        "build_client",
        lambda cfg: FakeClient(_verdict_json(**_PHP_CLOSURE)),
    )

    result = runner.run_bench(corpus, ["fake"], cfg, tmp_path / "out", no_lsp=True)

    assert result["lsp"] is False
    # The closure was downgraded, so the model abstained rather than agreed.
    assert result["detail"]["fake"]["abstention_rate"] == 100.0


# --- providers without server-side schema enforcement (DeepSeek) --------------


def test_deepseek_shaped_dataflow_is_coerced_not_rejected():
    """Measured on the first DeepSeek bench: `json_object` mode has no
    server-side schema, and the model renamed our fields — `step`/`type`/`why`
    for `order`/`role`/`explanation`, extra keys in vulnerable_symbol. The
    verdicts were semantically right 14/14; rejecting them over renames scored
    the provider's JSON discipline, not its triage."""
    raw = json.dumps(
        {
            "verdict": "false_positive",
            "evidence_class": "SANITIZED_DATAFLOW",
            "confidence": 0.9,
            "cwe": "CWE-89",
            "vulnerable_symbol": {
                "name": "createNativeQuery",
                "kind": "sink",
                "location": "src/Repo.php:6",
                "why": "parameterized",
                "severity_note": "extra field the schema forbids",
            },
            "dataflow": [
                {"step": 1, "type": "source", "why": "ORM builder, not user input", "tainted": False},
                {"step": 2, "type": "sink", "why": "receives a parameterized query", "tainted": False},
            ],
            "evidence": [{"quote": "$rsm = $this->createResultSetMappingBuilder('aio');", "explanation": "ORM"}],
            "reason": "test",
            "missing_information": [],
            "requires_human_review": False,
        }
    )
    verdict = parse_verdict(raw)

    assert verdict.verdict is VerdictLabel.false_positive
    assert [s.role.value for s in verdict.dataflow] == ["source", "sink"]
    assert verdict.dataflow[0].explanation == "ORM builder, not user input"
    assert verdict.vulnerable_symbol.name == "createNativeQuery"
    assert verdict.evidence[0].why == "ORM"


def test_language_scanner_routing_adds_php_taint_analysis(tmp_path, monkeypatch):
    """Non-PHP source must never select Semgrep; CodeQL covers its languages."""
    monkeypatch.setattr(selection, "usable_scanners", lambda: ["semgrep", "bandit", "codeql", "gitleaks"])

    (tmp_path / "main.py").write_text("print('ok')", encoding="utf-8")
    assert "semgrep" not in selection.scanners_for_target(tmp_path)
    assert "codeql" in selection.scanners_for_target(tmp_path)

    (tmp_path / "index.php").write_text("<?php echo 'ok';", encoding="utf-8")
    selected = selection.scanners_for_target(tmp_path)
    assert "semgrep" in selected
    assert "codeql" in selected
    assert "psalm" in selected


def test_pure_php_routes_to_semgrep_and_psalm_not_codeql(tmp_path, monkeypatch):
    monkeypatch.setattr(selection, "usable_scanners", lambda: ["semgrep", "psalm", "codeql", "gitleaks"])
    (tmp_path / "index.php").write_text("<?php echo 'ok';", encoding="utf-8")

    assert selection.scanners_for_target(tmp_path) == ["semgrep", "psalm"]


def test_go_requires_codeql_and_govulncheck_even_when_one_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(selection, "usable_scanners", lambda: ["codeql"])
    (tmp_path / "main.go").write_text("package main", encoding="utf-8")

    assert selection.scanners_for_target(tmp_path) == ["govulncheck", "codeql"]


@pytest.mark.parametrize("suffix", [".c", ".cpp", ".rs", ".swift"])
def test_new_codeql_languages_route_to_codeql(tmp_path, monkeypatch, suffix):
    monkeypatch.setattr(selection, "usable_scanners", lambda: ["codeql"])
    (tmp_path / f"sample{suffix}").write_text("", encoding="utf-8")
    assert selection.scanners_for_target(tmp_path) == ["codeql"]


def test_schema_failure_gets_one_repair_round():
    """A missing required field (DeepSeek dropped `evidence_class` on every
    verdict) cannot be invented by the parser — but one correction round with
    the model's own output plus the validation error recovers it. The extra
    round-trip is recorded, and it must not trigger the adversarial second pass:
    it is a formatting problem, not a doubt about the judgement."""
    incomplete = json.dumps(
        {
            "verdict": "false_positive",
            "confidence": 0.9,
            "cwe": "CWE-79",
            "evidence": [{"quote": '$apiKey = "${SERVICE_TOKEN}";', "why": "placeholder"}],
            "reason": "templating placeholder",
            "requires_human_review": False,
        }
    )
    finding = _finding('$apiKey = "${SERVICE_TOKEN}";')
    client = FakeClient(incomplete, _verdict_json(evidence=['$apiKey = "${SERVICE_TOKEN}";']))
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.false_positive
    assert record.error is None
    assert any(o.startswith("schema_repaired") for o in record.overrides)
    assert len(client.calls) == 2
    assert "Correction required" in client.calls[1][1]
    assert "evidence_class" in client.calls[1][1], "the model must be told what was wrong"


def test_a_second_schema_failure_is_an_error_record_not_a_loop():
    """The repair budget is exactly one round: a provider that cannot produce
    the contract twice yields an `unknown` error record — never a dropped
    finding, and never an unbounded retry bill."""
    broken = '{"verdict": "confirmed", "confidence": 0.9}'
    finding = _finding('String token = "x";')
    client = FakeClient(broken, broken)
    record = TriagePipeline(client, _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert record.decided_by == "error"
    assert record.error
    assert len(client.calls) == 2


def test_quotes_living_only_in_dataflow_are_lifted_into_evidence():
    """DeepSeek writes verbatim quotes into `dataflow[].code` and returns
    `evidence: []` — which sent 12 of 14 otherwise-correct verdicts into the
    `no_evidence` downgrade. Lifting relocates the quotes; grounding still
    checks every one of them, so a hallucinated dataflow quote costs the
    verdict exactly as before."""
    snippet = "$host = $_POST['host'];\nsystem('ping -c 1 ' . $host);"
    raw = _verdict_json(
        verdict="confirmed",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-78",
        evidence=[],
        dataflow=[
            {
                "order": 1,
                "role": "source",
                "code": "$host = $_POST['host'];",
                "explanation": "request value",
                "tainted": True,
                "location": None,
            },
            {
                "order": 2,
                "role": "sink",
                "code": "system('ping -c 1 ' . $host);",
                "explanation": "shell execution",
                "tainted": True,
                "location": None,
            },
        ],
    )
    verdict = parse_verdict(raw)
    assert [e.quote for e in verdict.evidence] == [
        "$host = $_POST['host'];",
        "system('ping -c 1 ' . $host);",
    ]

    # End to end: the lifted quotes ground against the snippet and the decisive
    # verdict survives instead of dying on no_evidence.
    finding = _finding(snippet, cwe="CWE-78", path="src/Service/Pinger.php")
    record = TriagePipeline(FakeClient(raw), _PROVIDER, _cfg()).triage_one(finding)
    assert record.verdict.verdict is VerdictLabel.confirmed
    assert not any("no_evidence" in o for o in record.overrides)


def test_lifted_dataflow_quotes_are_still_subject_to_grounding():
    """The lift must not weaken safety: quotes that appear nowhere in the input
    are hallucinations wherever the model wrote them."""
    raw = _verdict_json(
        verdict="confirmed",
        evidence_class="EXPLOITABLE_DATAFLOW",
        cwe="CWE-78",
        confidence=0.99,
        evidence=[],
        dataflow=[
            {
                "order": 1,
                "role": "sink",
                "code": "exec($never_in_the_input);",
                "explanation": "invented",
                "tainted": True,
                "location": None,
            },
        ],
    )
    finding = _finding("$x = 1; // nothing dangerous here", cwe="CWE-78", path="src/a.php")
    record = TriagePipeline(FakeClient(raw), _PROVIDER, _cfg()).triage_one(finding)

    assert record.verdict.verdict is VerdictLabel.unknown
    assert any("hallucinated_evidence" in o for o in record.overrides)


def test_deepseek_gets_the_schema_in_the_prompt_not_just_its_name():
    """`json_object` guarantees syntax, not shape, and the prompt pack says
    "matching the schema" without showing one — the other providers enforce it
    in the decoder. Measured: without the schema in the prompt every DeepSeek
    verdict drifted and cost a repair round-trip."""
    from appsec_triage.llm.openai_compat import DeepSeekClient
    from appsec_triage.validate.schema import VERDICT_SCHEMA

    cfg = ProviderConfig(
        name="deepseek",
        kind="deepseek",
        model="deepseek-chat",
        base_url="http://x",
        api_key="k",
        json_mode="json_object",
        concurrency=1,
    )
    client = DeepSeekClient(cfg)
    try:
        _, payload = client._build_payload("system prompt", "user prompt", VERDICT_SCHEMA)
    finally:
        client.close()

    assert payload["response_format"] == {"type": "json_object"}
    system = payload["messages"][0]["content"]
    assert "Output contract" in system
    assert '"evidence_class"' in system, "the drifted field must be spelled out"
    assert '"order"' in system and '"role"' in system
    # The word-"json" API requirement is satisfied by the contract block itself.
    assert "json" in system.lower()


# --- lsp_resolved_clean clears sql_value_interpolated from sanity gate --------
