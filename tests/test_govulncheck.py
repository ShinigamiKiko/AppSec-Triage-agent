from __future__ import annotations

import json

import pytest

from appsec_triage.config import ScannerConfig
from appsec_triage.ingest import detect_format, load
from appsec_triage.models import Severity
from appsec_triage.scanners.tools import GovulncheckScanner


def _stream(*objects) -> str:
    return "\n".join(json.dumps(obj, indent=2) for obj in objects)


def test_reachable_symbol_keeps_versions_and_reverses_call_trace(tmp_path):
    path = tmp_path / "govulncheck.json"
    path.write_text(
        _stream(
            {
                "config": {
                    "scanner_name": "govulncheck",
                    "scan_level": "symbol",
                    "scan_mode": "source",
                }
            },
            {
                "SBOM": {
                    "modules": [
                        {"path": "example.com/app"},
                        {"path": "example.com/lib", "version": "v1.2.3"},
                    ]
                }
            },
            {
                "osv": {
                    "id": "GO-2099-0001",
                    "summary": "Parser panic",
                    "details": "Malformed input panics.",
                    "database_specific": {"cwe_ids": ["CWE-248"]},
                }
            },
            {
                "finding": {
                    "osv": "GO-2099-0001",
                    "fixed_version": "v1.2.4",
                    "trace": [
                        {
                            "module": "example.com/lib",
                            "version": "v1.2.3",
                            "package": "example.com/lib/parser",
                            "function": "Parse",
                            "position": {"filename": "parser.go", "line": 41},
                        },
                        {
                            "module": "example.com/app",
                            "package": "example.com/app/api",
                            "function": "Handle",
                            "position": {"filename": "api/handler.go", "line": 17},
                        },
                    ],
                }
            },
        ),
        encoding="utf-8",
    )

    assert detect_format(path) == "govulncheck"
    finding = load(path)[0]

    assert finding.scanner == "govulncheck"
    assert finding.rule_id == "GO-2099-0001"
    assert finding.cwe == "CWE-248"
    assert finding.severity is Severity.high
    assert finding.code_context.file_path == "api/handler.go"
    assert finding.dependency is not None
    assert finding.dependency.package == "example.com/lib"
    assert finding.dependency.installed_version == "v1.2.3"
    assert finding.dependency.fixed_versions == ["v1.2.4"]
    assert [step.role for step in finding.trace] == ["source", "sink"]
    assert finding.trace[0].file_path == "api/handler.go"
    assert finding.trace[-1].file_path == "example.com/lib@v1.2.3/parser.go"


def test_import_only_advisory_has_no_synthetic_call_trace(tmp_path):
    path = tmp_path / "govulncheck.json"
    path.write_text(
        _stream(
            {"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},
            {
                "SBOM": {
                    "modules": [
                        {"path": "example.com/app"},
                        {"path": "example.com/lib", "version": "v1.2.3"},
                    ]
                }
            },
            {"osv": {"id": "GO-2099-0002", "summary": "Unused vulnerable API"}},
            {
                "finding": {
                    "osv": "GO-2099-0002",
                    "fixed_version": "v1.2.4",
                    "trace": [{"module": "example.com/lib", "version": "v1.2.3"}],
                }
            },
        ),
        encoding="utf-8",
    )

    finding = load(path)[0]

    assert finding.severity is Severity.medium
    assert finding.code_context.file_path == "go.mod"
    assert finding.trace == []
    assert finding.source is None
    assert finding.sink is None
    assert "no vulnerable symbol is called" in (finding.description or "")


def test_multiple_occurrences_use_reachable_symbol_trace(tmp_path):
    path = tmp_path / "govulncheck.json"
    path.write_text(
        _stream(
            {"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},
            {
                "SBOM": {
                    "modules": [
                        {"path": "example.com/app"},
                        {"path": "example.com/lib", "version": "v1.2.3"},
                    ]
                }
            },
            {"osv": {"id": "GO-2099-0003", "summary": "Reachable parser flaw"}},
            {
                "finding": {
                    "osv": "GO-2099-0003",
                    "fixed_version": "v1.2.4",
                    "trace": [{"module": "example.com/lib", "package": "example.com/lib/parser"}],
                }
            },
            {
                "finding": {
                    "osv": "GO-2099-0003",
                    "fixed_version": "v1.3.0",
                    "trace": [
                        {
                            "module": "example.com/lib",
                            "package": "example.com/lib/parser",
                            "function": "Parse",
                        },
                        {
                            "module": "example.com/app",
                            "package": "example.com/app",
                            "function": "main",
                            "position": {"filename": "main.go", "line": 12},
                        },
                    ],
                }
            },
        ),
        encoding="utf-8",
    )

    findings = load(path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity is Severity.high
    assert finding.code_context.file_path == "main.go"
    assert finding.dependency is not None
    assert finding.dependency.installed_version == "v1.2.3"
    assert finding.dependency.fixed_versions == ["v1.2.4", "v1.3.0"]
    assert [step.message for step in finding.trace] == [
        "example.com/app.main",
        "example.com/lib/parser.Parse",
    ]


@pytest.mark.parametrize(
    ("objects", "expected_error"),
    [
        (
            ({"config": {"scanner_name": "govulncheck", "scan_level": "package"}}, {"SBOM": {}}),
            "expected 'symbol'",
        ),
        (
            ({"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},),
            "no SBOM record",
        ),
    ],
)
def test_report_health_requires_complete_symbol_scan(tmp_path, objects, expected_error):
    path = tmp_path / "govulncheck.json"
    path.write_text(_stream(*objects), encoding="utf-8")
    scanner = GovulncheckScanner(ScannerConfig(name="govulncheck"))

    assert expected_error in (scanner.report_health(path) or "")


def test_report_health_accepts_clean_completed_symbol_scan(tmp_path):
    path = tmp_path / "govulncheck.json"
    path.write_text(
        _stream(
            {
                "config": {
                    "scanner_name": "govulncheck",
                    "scanner_version": "v1.1.4",
                    "scan_level": "symbol",
                }
            },
            {"SBOM": {"modules": [{"path": "example.com/app"}]}},
        ),
        encoding="utf-8",
    )
    scanner = GovulncheckScanner(ScannerConfig(name="govulncheck"))

    assert scanner.report_health(path) is None
    assert scanner.count_findings(path) == 0


def test_govulncheck_wins_alias_dedupe_and_keeps_osv_metadata(tmp_path):
    (tmp_path / "dependencies.json").write_text(
        json.dumps(
            [
                {
                    "finding_id": "GHSA-demo-example.com/lib",
                    "scanner": "cdxgen+osv",
                    "rule_id": "GHSA-demo",
                    "cwe": "CWE-79",
                    "code_context": {"file_path": "go.mod"},
                    "dependency": {
                        "package": "example.com/lib",
                        "ecosystem": "go",
                        "installed_version": "v1.2.3",
                        "fixed_versions": ["v1.2.5"],
                        "advisory_aliases": ["GO-2099-0004"],
                    },
                }
            ]
        ),
        encoding="utf-8",
    )
    (tmp_path / "govulncheck.json").write_text(
        _stream(
            {"config": {"scanner_name": "govulncheck", "scan_level": "symbol"}},
            {
                "SBOM": {
                    "modules": [
                        {"path": "example.com/app"},
                        {"path": "example.com/lib", "version": "v1.2.3"},
                    ]
                }
            },
            {
                "osv": {
                    "id": "GO-2099-0004",
                    "aliases": ["GHSA-demo"],
                    "summary": "Import-only flaw",
                }
            },
            {
                "finding": {
                    "osv": "GO-2099-0004",
                    "fixed_version": "v1.2.4",
                    "trace": [{"module": "example.com/lib", "version": "v1.2.3"}],
                }
            },
        ),
        encoding="utf-8",
    )

    findings = load(tmp_path)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.scanner == "govulncheck"
    assert finding.rule_id == "GO-2099-0004"
    assert finding.cwe == "CWE-79"
    assert finding.corroborated_by == ["cdxgen+osv"]
    assert finding.dependency is not None
    assert finding.dependency.fixed_versions == ["v1.2.4", "v1.2.5"]
    assert finding.dependency.advisory_aliases == ["GHSA-demo"]
