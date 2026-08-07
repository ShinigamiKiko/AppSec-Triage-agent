"""Dependency findings from the sole SCA path: cdxgen plus advisory APIs.

The behaviour that matters most is that a database that did not answer is a
recorded failure, never a clean package.
"""

from __future__ import annotations

from pathlib import Path

from appsec_triage.sca import advisories as adv
from appsec_triage.sca import discover as discover_mod
from appsec_triage.sca.advisories import Advisory


_SBOM = {
    "metadata": {"component": {"bom-ref": "root"}},
    "components": [
        {"bom-ref": "g", "purl": "pkg:composer/guzzlehttp/guzzle@7.4.1"},
        {"bom-ref": "t", "purl": "pkg:composer/phpunit/phpunit@9.5.0", "scope": "excluded"},
    ],
    "dependencies": [{"ref": "root", "dependsOn": ["g", "t"]}],
}


def _patch_sbom(monkeypatch, document=_SBOM):
    monkeypatch.setattr(discover_mod.sbom, "generate", lambda root: (document, ""))


def test_a_vulnerable_package_becomes_a_finding(monkeypatch, tmp_path):
    _patch_sbom(monkeypatch)
    monkeypatch.setattr(
        discover_mod.adv, "from_osv",
        lambda name, eco, version: [Advisory("GHSA-x", package=name, ecosystem=eco,
                                             summary="Cookie leakage")]
        if name == "guzzlehttp/guzzle" else [])

    result = discover_mod.discover(tmp_path)

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.dependency.package == "guzzlehttp/guzzle"
    assert finding.dependency.installed_version == "7.4.1"
    assert finding.rule_id == "GHSA-x"
    assert finding.code_context.file_path == "composer.json"


def test_a_build_only_component_keeps_its_scope(monkeypatch, tmp_path):
    """`dev_only` is what closes a finding later; losing it here loses that."""
    _patch_sbom(monkeypatch)
    monkeypatch.setattr(
        discover_mod.adv, "from_osv",
        lambda name, eco, version: [Advisory("GHSA-t", package=name, ecosystem=eco)])

    result = discover_mod.discover(tmp_path)
    by_package = {f.dependency.package: f.dependency.dev_only for f in result.findings}

    assert by_package["phpunit/phpunit"] is True
    assert by_package["guzzlehttp/guzzle"] is None


def test_a_database_failure_is_recorded_not_treated_as_clean(monkeypatch, tmp_path):
    _patch_sbom(monkeypatch)

    def unavailable(name, eco, version):
        raise adv.DatabaseUnavailable("api.osv.dev -> timed out")

    monkeypatch.setattr(discover_mod.adv, "from_osv", unavailable)
    result = discover_mod.discover(tmp_path)

    assert result.findings == []
    assert len(result.problems) == 2
    assert all("timed out" in p for p in result.problems)
    assert result.usable is False


def test_no_sbom_is_reported_and_produces_nothing(monkeypatch, tmp_path):
    monkeypatch.setattr(discover_mod.sbom, "generate",
                        lambda root: (None, "cdxgen не установлен"))
    result = discover_mod.discover(tmp_path)

    assert result.findings == []
    assert result.usable is False
    assert "cdxgen не установлен" in result.problems[0]


def test_a_limit_says_what_it_skipped(monkeypatch, tmp_path):
    _patch_sbom(monkeypatch)
    monkeypatch.setattr(discover_mod.adv, "from_osv", lambda name, eco, version: [])

    result = discover_mod.discover(tmp_path, limit=1)

    assert result.packages_checked == 1
    assert any("пропущены" in p for p in result.problems)


def test_an_existing_sbom_is_reused(monkeypatch, tmp_path):
    """A pipeline stage may already have produced one; running cdxgen twice on a
    large monorepo costs minutes."""
    import json

    path = tmp_path / "sbom.json"
    path.write_text(json.dumps(_SBOM), encoding="utf-8")

    def fail(root):
        raise AssertionError("cdxgen не должен запускаться при готовом SBOM")

    monkeypatch.setattr(discover_mod.sbom, "generate", fail)
    monkeypatch.setattr(discover_mod.adv, "from_osv", lambda name, eco, version: [])

    result = discover_mod.discover(tmp_path, sbom_path=path)
    assert result.packages_checked == 2
