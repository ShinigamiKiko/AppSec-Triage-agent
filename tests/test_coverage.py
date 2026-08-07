"""A report has to say what did not run.

A scan where a required analysis leg died still produces a clean-looking report:
fewer findings, no errors, exit zero. The manifest must preserve that gap.
"""

from __future__ import annotations

import json

from appsec_triage import coverage
from appsec_triage.pipeline import TriageRun
from appsec_triage.report import html


def _manifest(tmp_path, scans):
    (tmp_path / "scan-manifest.json").write_text(
        json.dumps({"target": "/src", "scans": scans}), encoding="utf-8"
    )
    return tmp_path


def test_a_complete_scan_says_so(tmp_path):
    cov = coverage.read(_manifest(tmp_path, [
        {"scanner": "semgrep", "ok": True, "findings": 3},
        {"scanner": "cdxgen+osv", "ok": True, "findings": 9},
    ]))
    assert cov.complete
    assert cov.ran == ["semgrep", "cdxgen+osv"]
    assert cov.gaps() == []


def test_a_failure_is_reported_as_lost_coverage_not_as_an_exit_code(tmp_path):
    """`psalm exited 1` tells a reader nothing. What is missing does."""
    cov = coverage.read(_manifest(tmp_path, [
        {"scanner": "semgrep", "ok": True, "findings": 3},
        {"scanner": "psalm", "ok": False, "error": "no composer autoloaders"},
    ]))
    assert not cov.complete
    gap = cov.gaps()[0]
    assert "PHP taint analysis" in gap
    assert "missing from this report" in gap


def test_the_dependency_layer_going_missing_is_stated_plainly(tmp_path):
    cov = coverage.read(_manifest(tmp_path, [
        {"scanner": "cdxgen+osv", "ok": False, "error": "OSV timed out"},
    ]))
    assert "dependency graph" in cov.gaps()[0]


def test_missing_govulncheck_names_lost_symbol_reachability(tmp_path):
    cov = coverage.read(_manifest(tmp_path, [
        {"scanner": "govulncheck", "ok": False, "error": "binary missing"},
    ]))

    assert "vulnerable-symbol reachability" in cov.gaps()[0]


def test_no_manifest_means_unknown_not_complete(tmp_path):
    """Claiming full coverage on no evidence is the error this prevents."""
    cov = coverage.read(tmp_path)
    assert cov.manifest_found is False
    assert cov.complete is False


def test_a_corrupt_manifest_does_not_crash_the_report(tmp_path):
    (tmp_path / "scan-manifest.json").write_text("{ not json", encoding="utf-8")
    assert coverage.read(tmp_path).complete is False


def _run(cov):
    return TriageRun(records=[], provider="p", model="m", prompt_pack="default", coverage=cov)


def test_the_banner_appears_above_the_counts(tmp_path):
    """Placement matters: it changes what the numbers below it mean."""
    cov = coverage.read(_manifest(tmp_path, [
        {"scanner": "cdxgen+osv", "ok": False, "error": "boom"},
    ]))
    page = html.render(_run(cov))
    assert "This report is incomplete" in page
    assert page.index("This report is incomplete") < page.index('<div class="cards">')


def test_a_complete_run_gets_a_quiet_confirmation(tmp_path):
    cov = coverage.read(_manifest(tmp_path, [{"scanner": "semgrep", "ok": True}]))
    page = html.render(_run(cov))
    assert "All scanners completed" in page
    assert "incomplete" not in page


def test_a_report_with_no_coverage_information_says_that_too():
    page = html.render(_run(None))
    assert "coverage unknown" in page.lower()
