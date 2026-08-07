"""Scanner execution: exit codes, shell-safety, report health, SARIF severity."""

from __future__ import annotations

import json

from appsec_triage import ingest
from appsec_triage.models import Severity


def test_empty_report_from_a_crashed_scanner_is_not_success(tmp_path, monkeypatch):
    """The real trap: semgrep exits 7 on an invalid ruleset but still writes SARIF.

    Treating that as "0 findings" would make the agent report a clean codebase
    because its own rules failed to parse.
    """
    import subprocess

    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import SemgrepScanner

    empty_sarif = '{"version":"2.1.0","runs":[{"results":[]}]}'

    class FakeProc:
        returncode = 7
        stdout = empty_sarif
        stderr = "[ERROR] invalid configuration file found (1 configs were invalid)"

    scanner = SemgrepScanner(ScannerConfig(name="semgrep", mode="native"))
    monkeypatch.setattr(
        scanner,
        "available",
        lambda: __import__("appsec_triage.scanners.base", fromlist=["Availability"]).Availability(
            True, mode="native", version="1.0"
        ),
    )
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())

    result = scanner.scan(tmp_path, tmp_path / "out")
    assert result.ok is False
    # Exit 7 (invalid ruleset) is fatal for semgrep, and the report check would
    # catch it independently: no rules ran, so nothing was checked.
    assert "not a success code" in result.error
    assert scanner.report_health(tmp_path / "out" / "semgrep.sarif.json") is not None


def test_findings_exit_code_is_still_success(tmp_path, monkeypatch):
    import subprocess

    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.base import Availability
    from appsec_triage.scanners.tools import SemgrepScanner

    class FakeProc:
        returncode = 1  # semgrep found something
        stdout = '{"version":"2.1.0","runs":[{"results":[{"ruleId":"x"}]}]}'
        stderr = ""

    scanner = SemgrepScanner(ScannerConfig(name="semgrep", mode="native"))
    monkeypatch.setattr(scanner, "available", lambda: Availability(True, mode="native", version="1.0"))
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: FakeProc())

    result = scanner.scan(tmp_path, tmp_path / "out")
    assert result.ok is True
    assert result.findings == 1


def test_scanner_argv_never_goes_through_a_shell(tmp_path):
    """A repo path with shell metacharacters must not become a command."""
    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import BanditScanner

    nasty = tmp_path / "repo; rm -rf $(echo x)"
    nasty.mkdir()
    argv = BanditScanner(ScannerConfig(name="bandit"))._native_scan_argv(nasty.resolve(), tmp_path / "o.json")

    assert isinstance(argv, list)
    assert str(nasty.resolve()) in argv, "the path must be one argv element, not spliced into a string"


def test_semgrep_requests_dataflow_traces_for_sast_reachability(tmp_path):
    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import SemgrepScanner

    scanner = SemgrepScanner(ScannerConfig(name="semgrep", mode="native"))
    argv = scanner._native_scan_argv(tmp_path, tmp_path / "out.sarif")

    assert "--dataflow-traces" in argv


def test_report_health_rejects_a_scan_that_ran_no_rules(tmp_path):
    """Zero rules is not a clean codebase — it is a scanner that checked nothing."""
    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import SemgrepScanner

    scanner = SemgrepScanner(ScannerConfig(name="semgrep"))
    empty = tmp_path / "empty.sarif.json"
    empty.write_text('{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[]}},"results":[]}]}', encoding="utf-8")
    assert "ran nothing" in scanner.report_health(empty)

    failed = tmp_path / "failed.sarif.json"
    failed.write_text(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"a"}]}},'
        '"invocations":[{"executionSuccessful":false}],"results":[]}]}',
        encoding="utf-8",
    )
    assert "executionSuccessful=false" in scanner.report_health(failed)

    healthy = tmp_path / "ok.sarif.json"
    healthy.write_text(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"rules":[{"id":"a"}]}},'
        '"invocations":[{"executionSuccessful":true}],"results":[]}]}',
        encoding="utf-8",
    )
    assert scanner.report_health(healthy) is None, "a genuinely clean scan must pass"


def test_directory_ingest_skips_the_manifest_and_keeps_going(tmp_path, caplog):
    import json as _json

    (tmp_path / "scan-manifest.json").write_text('{"scans": []}', encoding="utf-8")
    (tmp_path / "junk.json").write_text('{"unrelated": true}', encoding="utf-8")
    (tmp_path / "good.jsonl").write_text(
        _json.dumps({"finding_id": "g-1", "cwe": "798", "path": "a.py", "code": "x = 1"}) + "\n",
        encoding="utf-8",
    )
    findings = ingest.load(tmp_path)
    assert [f.finding_id for f in findings] == ["g-1"]


def test_sarif_severity_falls_back_to_the_rule_default(tmp_path):
    """Semgrep sets the level on the rule, not the result.

    Reading only `result.level` marked 207 of 296 findings on a real project as
    `unknown`, which silently disabled severity-based escalation.
    """
    from appsec_triage.ingest import sarif

    doc = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "semgrep",
                        "rules": [
                            {
                                "id": "r1",
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["CWE-798: Use of Hard-coded Credentials"]},
                            },
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "r1",
                        "message": {"text": "hardcoded credential"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/App.php"},
                                    "region": {"startLine": 10, "snippet": {"text": "$password = 'hunter2';"}},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }
    path = tmp_path / "semgrep.sarif.json"
    path.write_text(json.dumps(doc), encoding="utf-8")

    finding = list(sarif.parse(path))[0]
    assert finding.severity is Severity.high, "rule-level severity must be picked up"
    assert finding.cwe == "CWE-798"


def test_clean_report_is_not_an_error(tmp_path):
    """Zero findings is a legitimate scan outcome, not a failure."""
    path = tmp_path / "gitleaks.sarif.json"
    path.write_text(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}', encoding="utf-8"
    )
    assert ingest.load(path) == []


def test_gitleaks_accepts_a_clean_report_without_enumerated_rules(tmp_path):
    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import GitleaksScanner

    path = tmp_path / "gitleaks.sarif.json"
    path.write_text(
        '{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}',
        encoding="utf-8",
    )

    scanner = GitleaksScanner(ScannerConfig(name="gitleaks"))
    assert scanner.report_health(path) is None


def test_scanner_registry_contains_required_analysis_tools():
    from appsec_triage.scanners.tools import REGISTRY

    assert set(REGISTRY) == {"bandit", "codeql", "gitleaks", "govulncheck", "psalm", "semgrep"}


def test_govulncheck_requests_symbol_level_json(tmp_path):
    from appsec_triage.config import ScannerConfig
    from appsec_triage.scanners.tools import GovulncheckScanner

    scanner = GovulncheckScanner(
        ScannerConfig(name="govulncheck", mode="native", binary="govulncheck", run_in_target=True)
    )
    argv = scanner._native_scan_argv(tmp_path, tmp_path / "govulncheck.json")

    assert argv == ["govulncheck", "-format=json", "-scan=symbol", "./..."]


def test_scan_all_runs_govulncheck_before_codeql_for_targeted_analysis(tmp_path, monkeypatch):
    from appsec_triage.scanners import scan_all
    from appsec_triage.scanners import build_scanner as real_build_scanner
    from appsec_triage.scanners.base import ScanResult

    order = []

    class Stub:
        def __init__(self, name):
            self.name = name

        def scan(self, target, out_dir):
            order.append(self.name)
            return ScanResult(scanner=self.name, ok=True)

    monkeypatch.setattr(
        "appsec_triage.scanners.build_scanner",
        lambda name: Stub(name) if name in {"codeql", "govulncheck"} else real_build_scanner(name),
    )

    scan_all(tmp_path, ["codeql", "govulncheck"], tmp_path / "out")

    assert order == ["govulncheck", "codeql"]


# --- regression: verdict contradicting its own rationale -----------------------
