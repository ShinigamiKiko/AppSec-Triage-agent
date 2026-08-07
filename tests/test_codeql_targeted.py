from __future__ import annotations

import json
from types import SimpleNamespace

from appsec_triage.config import ScannerConfig
from appsec_triage.models import CodeContext, Finding, TraceStep
from appsec_triage.sca.reach import _taint_into, has_taint_path
from appsec_triage.scanners.codeql_targeted import Target, analyze, render_query, targets_from_report
from appsec_triage.scanners.tools import CodeQLScanner


def _stream(*objects) -> str:
    return "\n".join(json.dumps(obj) for obj in objects)


def test_targets_are_exact_application_locations_from_govulncheck(tmp_path):
    report = tmp_path / "govulncheck.json"
    report.write_text(
        _stream(
            {"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},
            {"SBOM": {"modules": [{"path": "example.com/app"}, {"path": "example.com/lib"}]}},
            {"osv": {"id": "GO-1"}},
            {
                "finding": {
                    "osv": "GO-1",
                    "trace": [
                        {
                            "module": "example.com/lib",
                            "package": "example.com/lib",
                            "function": "Parse",
                        },
                        {
                            "module": "example.com/app",
                            "package": "example.com/app/api",
                            "function": "Handle",
                            "position": {"filename": "api/handler.go", "line": 41},
                        },
                    ],
                }
            },
        ),
        encoding="utf-8",
    )

    assert targets_from_report(report) == [Target("api/handler.go", 41)]


def test_query_matches_file_and_line_not_ambiguous_function_names():
    query = render_query(
        [Target("api/parse.go", 12), Target('api/quote"path.go', 27)]
    )

    assert 'call.getFile().getRelativePath() = "api/parse.go"' in query
    assert "call.getLocation().getStartLine() = 12" in query
    assert 'api/quote\\"path.go' in query
    assert "getAnArgument()" in query
    assert "ActiveThreatModelSource" in query
    assert '"github.com/gofiber/fiber/v3"' in query
    assert '["Body", "Form", "Header", "Query", "URI"]' in query
    assert "Parse" not in query


def test_targeted_analysis_invokes_existing_database_and_reads_sarif(tmp_path, monkeypatch):
    report = tmp_path / "govulncheck.json"
    report.write_text(
        _stream(
            {"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},
            {"SBOM": {"modules": [{"path": "app"}, {"path": "lib"}]}},
            {"osv": {"id": "GO-1"}},
            {
                "finding": {
                    "osv": "GO-1",
                    "trace": [
                        {"module": "lib", "function": "Parse"},
                        {"module": "app", "function": "main", "position": {"filename": "main.go", "line": 8}},
                    ],
                }
            },
        ),
        encoding="utf-8",
    )
    output = tmp_path / "targeted.sarif.json"
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        output.write_text('{"version":"2.1.0","runs":[]}', encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr("appsec_triage.scanners.codeql_targeted.subprocess.run", fake_run)

    document, error = analyze(
        "codeql", tmp_path / "db", report, output, timeout_s=30
    )

    assert error is None
    assert document == {"version": "2.1.0", "runs": []}
    assert seen["argv"][:4] == ["codeql", "database", "analyze", str(tmp_path / "db")]
    assert any(str(arg).startswith("path:") for arg in seen["argv"])
    assert not output.exists()


def test_targeted_codeql_trace_matches_only_its_govulncheck_call_site():
    finding = Finding(
        finding_id="targeted",
        scanner="codeql",
        rule_id="go/govulncheck-targeted-taint",
        code_context=CodeContext(file_path="api/handler.go", start_line=41),
        trace=[
            TraceStep(file_path="api/routes.go", line=10, role="source"),
            TraceStep(file_path="api/handler.go", line=41, role="sink"),
        ],
    )
    matching = SimpleNamespace(file="api/handler.go", line=41)
    other = SimpleNamespace(file="api/handler.go", line=80)

    path, problem = _taint_into([finding], [matching])
    other_path, other_problem = _taint_into([finding], [other])

    assert "api/routes.go:10 -> api/handler.go:41" in path
    assert problem == ""
    assert has_taint_path([finding], [matching])
    assert not has_taint_path([finding], [other])
    assert other_path == ""
    assert "потока в эту точку не нашёл" in other_problem


def test_codeql_scanner_merges_targeted_run_before_deleting_database(tmp_path, monkeypatch):
    from appsec_triage.scanners import tools

    (tmp_path / "govulncheck.json").write_text("{}", encoding="utf-8")
    part = tmp_path / "codeql-go.sarif.json"
    general = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}}]}
    targeted = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "targeted"}}}]}
    seen = {}

    def fake_run(argv, **kwargs):
        if "database" in argv and "analyze" in argv:
            part.write_text(json.dumps(general), encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    def fake_targeted(exe, database, report, output, **kwargs):
        seen["database"] = database
        seen["report"] = report
        return targeted, None

    monkeypatch.setattr(tools.subprocess, "run", fake_run)
    monkeypatch.setattr(tools, "analyze_targeted_go", fake_targeted)
    scanner = CodeQLScanner(ScannerConfig(name="codeql", timeout_s=30))

    error = scanner._analyze_one("codeql", tmp_path, tmp_path, "go", part)

    assert error is None
    merged = json.loads(part.read_text(encoding="utf-8"))
    assert len(merged["runs"]) == 2
    assert seen["report"] == tmp_path / "govulncheck.json"
    assert seen["database"].name == ".codeql-db-go"
