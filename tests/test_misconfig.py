"""Configuration checks are facts, not judgements.

Trivy already parsed the Dockerfile. Routing that through a model produced the
question "does any request-controlled value reach `FROM node:20-alpine`?" — the
generic dataflow question asked of something that has no dataflow.
"""

from __future__ import annotations

import json

from appsec_triage.ingest import sarif
from appsec_triage.models import VerdictLabel


def _sarif(tmp_path, *, tags, precision):
    doc = {
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trivy",
                        "rules": [
                            {
                                "id": "DS-0002",
                                "shortDescription": {"text": "Image user should not be 'root'"},
                                "help": {"text": "Add a USER instruction to your Dockerfile."},
                                "properties": {"tags": tags, "precision": precision},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "DS-0002",
                        "message": {"text": "Specify at least 1 USER command"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "Dockerfile"},
                                    "region": {"startLine": 1, "snippet": {"text": "FROM node:20-alpine"}},
                                }
                            }
                        ],
                    }
                ],
            }
        ]
    }
    path = tmp_path / "trivy.sarif.json"
    path.write_text(json.dumps(doc), encoding="utf-8")
    return path


def test_a_parsed_configuration_check_is_marked_as_one(tmp_path):
    findings = list(sarif.parse(_sarif(tmp_path, tags=["misconfiguration", "security"], precision="very-high")))
    assert findings[0].misconfiguration is True


def test_a_pattern_match_without_very_high_precision_is_not(tmp_path):
    # Both conditions are required: the tag alone is claimed by rules that
    # pattern-match around a directive rather than read it.
    findings = list(sarif.parse(_sarif(tmp_path, tags=["misconfiguration"], precision="medium")))
    assert findings[0].misconfiguration is False


def test_a_weakness_finding_is_untouched(tmp_path):
    findings = list(sarif.parse(_sarif(tmp_path, tags=["security"], precision="very-high")))
    assert findings[0].misconfiguration is False


def test_it_is_decided_without_calling_the_model(tmp_path):
    from tests.test_verdict_evidence import _PROVIDER, _cfg
    from appsec_triage.pipeline import TriagePipeline

    class NeverCalled:
        def complete(self, *a, **k):  # pragma: no cover - the point is it is not reached
            raise AssertionError("a configuration check must not cost a model call")

    finding = list(sarif.parse(_sarif(tmp_path, tags=["misconfiguration"], precision="very-high")))[0]
    record = TriagePipeline(NeverCalled(), _PROVIDER, _cfg()).triage_one(finding)

    assert record.decided_by == "heuristics"
    assert record.verdict.verdict is VerdictLabel.confirmed
    # The remediation is written in the rule, so nothing is deferred to a human.
    assert record.verdict.requires_human_review is False
    assert "USER" in record.verdict.reason


def test_a_dockerfile_check_is_not_read_as_a_vulnerable_package():
    """Trivy labels these `Artifact: Dockerfile`, and the SCA parser took the
    bait — ten configuration checks arrived as dependency findings and were
    asked which version of themselves was affected."""
    from appsec_triage.ingest import dependency

    text = (
        "Artifact: Dockerfile\nType: dockerfile\nVulnerability DS-0001\n"
        "Message: Specify a tag in the 'FROM' statement\n"
        "Link: https://avd.aquasec.com/misconfig/ds-0001"
    )
    assert dependency.looks_like_dependency("Dockerfile", "DS-0001", text) is False
    # A real advisory in a real lockfile is untouched by the guard.
    real = "Package: guzzlehttp/guzzle\nInstalled Version: 7.4.1\nFixed Version: 7.4.5"
    assert dependency.looks_like_dependency("composer.lock", "CVE-2022-31042", real) is True


def test_the_misconfiguration_patterns_actually_match():
    # Same regression as the perimeter index: this escape has been written to
    # the file as a literal backspace twice now. It compiles either way.
    from appsec_triage.ingest.dependency import _MISCONFIG_TELL

    assert _MISCONFIG_TELL.search("Type: dockerfile")
    assert _MISCONFIG_TELL.search("https://avd.aquasec.com/misconfig/ds-0001")
    assert not _MISCONFIG_TELL.search("Package: guzzlehttp/guzzle")
