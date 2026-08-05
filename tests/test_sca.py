"""SCA path: dependency facts must survive from the scanner into the prompt.

The failure this guards against is silent. A dependency finding that loses its
package, version or fix still triages — it just always answers `unknown`, which
is indistinguishable from an honest abstention until someone counts.
"""

from __future__ import annotations

import json

from appsec_triage.config import PipelineConfig
from appsec_triage.context import builder
from appsec_triage.context.deps import DependencyIndex, build_index
from appsec_triage.context.heuristics import HeuristicResult
from appsec_triage.ingest import dependency as dep_parser
from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.prompts import registry


def _finding(dep: DependencyInfo) -> Finding:
    return Finding(
        finding_id="f1",
        scanner="trivy",
        rule_id="CVE-2024-0001",
        code_context=CodeContext(file_path="composer.lock"),
        dependency=dep,
    )


def _build(dep, index=None, roots=None):
    heur = HeuristicResult(
        signals=[], hard_fp=False, hard_fp_reason=None, in_noisy_zone=False, noisy_zone_reason=None
    )
    return builder.build(
        _finding(dep), heur, PipelineConfig(), deps_index=index, deps_roots=roots
    )


def test_the_upgrade_target_stays_on_the_installed_branch():
    # Told "fixed in 4.4.51" while running 5.4.3, a reader concludes they are
    # already patched. They are not, and the CVE is waved away.
    dep = DependencyInfo(
        package="symfony/http-kernel",
        installed_version="5.4.3",
        fixed_versions=["4.4.51", "5.4.31", "6.3.8"],
    )
    assert dep.upgrade_target == "5.4.31"


def test_no_published_fix_above_the_installed_version_reads_as_none():
    dep = DependencyInfo(package="x/y", installed_version="9.0.0", fixed_versions=["1.2.3"])
    assert dep.upgrade_target is None


def test_dependency_facts_reach_the_rendered_prompt():
    dep = DependencyInfo(
        package="symfony/http-kernel",
        ecosystem="packagist",
        installed_version="5.4.3",
        fixed_versions=["5.4.31"],
    )
    text = builder.render_for_prompt(_build(dep))
    assert "symfony/http-kernel" in text
    assert "5.4.3" in text
    assert "5.4.31" in text


def test_a_development_only_package_becomes_a_signal_toward_fp():
    index = DependencyIndex(dev_only={"phpunit/phpunit"}, production={"twig/twig"})
    pkg = _build(DependencyInfo(package="phpunit/phpunit"), index=index)
    signal = next(s for s in pkg.heuristic_signals if s.name == "dev_dependency_only")
    assert signal.direction == "toward_fp"
    assert pkg.dependency.dev_only is True


def test_a_package_missing_from_the_lockfile_is_unknown_not_production():
    # "We could not tell" must never render as "it ships" or as "it does not".
    index = DependencyIndex(dev_only={"phpunit/phpunit"}, production={"twig/twig"})
    pkg = _build(DependencyInfo(package="some/transitive"), index=index)
    assert pkg.dependency.dev_only is None
    assert not any(s.name == "dev_dependency_only" for s in pkg.heuristic_signals)


def test_a_missing_import_never_becomes_a_signal(tmp_path):
    # A framework wires packages through its container and they never appear in
    # an import. Reading that silence as "unused" closes live vulnerabilities.
    (tmp_path / "app.php").write_text("<?php echo 1;", encoding="utf-8")
    pkg = _build(DependencyInfo(package="twig/twig"), roots=[tmp_path])
    assert pkg.dependency.imported is False
    assert not any(s.name == "package_imported" for s in pkg.heuristic_signals)


def test_a_present_import_does_become_a_signal(tmp_path):
    (tmp_path / "app.php").write_text("<?php use Twig\\Environment;", encoding="utf-8")
    pkg = _build(DependencyInfo(package="twig/twig"), roots=[tmp_path])
    signal = next(s for s in pkg.heuristic_signals if s.name == "package_imported")
    assert signal.direction == "toward_confirmed"


def test_lockfile_split_reads_the_development_section(tmp_path):
    (tmp_path / "composer.lock").write_text(
        json.dumps(
            {
                "packages": [{"name": "twig/twig"}],
                "packages-dev": [{"name": "phpunit/phpunit"}],
            }
        ),
        encoding="utf-8",
    )
    index = build_index([tmp_path])
    assert index.is_dev_only("phpunit/phpunit") is True
    assert index.is_dev_only("twig/twig") is False


def test_a_dependency_finding_routes_to_the_sca_prompt():
    # It has no CWE. Without kind routing it gets the generic prompt and is
    # asked to trace a dataflow through code it cannot read.
    _, prompt = registry.render_system(None, kind="dependency")
    assert prompt.id == "sca"


def test_the_parser_recovers_package_version_and_fix_from_prose():
    text = (
        "Package: symfony/http-kernel\n"
        "Installed Version: 5.4.3\n"
        "Fixed Version: 4.4.51, 5.4.31\n"
        "Link: https://avd.aquasec.com/nvd/cve-2024-0001"
    )
    assert dep_parser.looks_like_dependency("composer.lock", "CVE-2024-0001", text)
    dep = dep_parser.parse(text, {})
    assert dep is not None
    assert dep.package == "symfony/http-kernel"
    assert dep.installed_version == "5.4.3"
    assert dep.upgrade_target == "5.4.31"


def test_a_package_coordinate_counts_as_a_grounded_symbol():
    """The SCA prompt asks for `package@version`, which is never a literal line.

    Checking that composite verbatim struck the symbol from 84 of 89 dependency
    findings on a real project — all of them correct — and the resulting
    override pulled every certainty band down with it.
    """
    from appsec_triage.config import PostValidationConfig
    from appsec_triage.validate.postvalidation import _symbol_is_grounded

    dep = DependencyInfo(package="api-platform/core", installed_version="v2.6.8")
    pkg = _build(dep)
    cfg = PostValidationConfig()
    haystack = pkg.quotable_text()

    assert _symbol_is_grounded("api-platform/core@v2.6.8", pkg, haystack, cfg)
    assert _symbol_is_grounded("api-platform/core", pkg, haystack, cfg)
    # A version the evidence does not report cannot pose as the installed one.
    assert not _symbol_is_grounded("api-platform/core@9.9.9", pkg, haystack, cfg)
    # And a package nobody mentioned is still a fabrication.
    assert not _symbol_is_grounded("evil/package@1.0", pkg, haystack, cfg)


def _validated(dep, verdict_label, evidence=("installed: v2.6.8",)):
    from appsec_triage.config import PostValidationConfig
    from appsec_triage.models import EvidenceClass, EvidenceQuote, Severity, Verdict, VerdictLabel
    from appsec_triage.validate.postvalidation import validate

    finding = _finding(dep)
    finding = finding.model_copy(update={"severity": Severity.high})
    pkg = _build(dep)
    verdict = Verdict(
        verdict=VerdictLabel(verdict_label),
        evidence_class=EvidenceClass.identifier_only,
        confidence=0.9,
        evidence=[EvidenceQuote(quote=q) for q in evidence],
        reason="in range and shipped",
        requires_human_review=True,
    )
    return validate(verdict, pkg, finding, PostValidationConfig())


def test_a_confirmed_cve_with_a_published_fix_is_a_patch_task_not_a_review():
    # 49 of 82 findings on a real project sat in the review queue with nothing
    # for the reviewer to decide: the version ships, the fix is named.
    dep = DependencyInfo(
        package="api-platform/core",
        installed_version="v2.6.8",
        fixed_versions=["2.7.10", "3.0.12"],
    )
    outcome = _validated(dep, "confirmed")
    assert outcome.verdict.requires_human_review is False
    assert any("remediation_is_mechanical" in o for o in outcome.overrides)


def test_a_cve_with_no_published_fix_still_needs_a_human():
    # Nothing to bump to: someone has to weigh mitigation or replacement.
    dep = DependencyInfo(package="abandoned/lib", installed_version="1.0.0")
    assert _validated(dep, "confirmed").verdict.requires_human_review is True


def test_a_fix_only_on_another_branch_still_needs_a_human():
    # "Fixed in 4.4.51" while running 5.4.3 is a migration decision, not a bump.
    dep = DependencyInfo(
        package="symfony/http-kernel", installed_version="5.4.3", fixed_versions=["4.4.51"]
    )
    assert _validated(dep, "confirmed").verdict.requires_human_review is True


def test_an_unknown_dependency_verdict_is_never_waved_through():
    dep = DependencyInfo(package="x/y", installed_version="1.0.0", fixed_versions=["2.0.0"])
    assert _validated(dep, "unknown").verdict.requires_human_review is True


def test_a_mechanical_upgrade_note_is_not_counted_as_a_correction():
    # It records what to do, it does not contest the verdict. Counting it as a
    # rewrite made the summary claim post-validation had overridden 64 of 82
    # verdicts when it had overridden none of them.
    dep = DependencyInfo(
        package="api-platform/core", installed_version="v2.6.8", fixed_versions=["2.7.10"]
    )
    outcome = _validated(dep, "confirmed")
    assert outcome.overrides  # the note is still in the audit trail
    assert outcome.changed is False


def test_the_review_brief_asks_a_dependency_question_not_a_dataflow_one():
    """What a reviewer reads must match what decides the finding.

    Seen in a real queue: a CVE in guzzle came with "Does any request-controlled
    value reach `guzzlehttp/psr7@2.1.0`? да → Attacker-controlled → confirmed."
    There is no such path to find, and the version already decided it.
    """
    from appsec_triage import review
    from appsec_triage.models import EvidenceClass, TriageRecord, Verdict, VerdictLabel

    record = TriageRecord(
        finding_id="f",
        cwe=None,
        file_path="composer.lock",
        kind="dependency",
        verdict=Verdict(
            verdict=VerdictLabel.confirmed,
            evidence_class=EvidenceClass.identifier_only,
            confidence=0.9,
            reason="upgrade to 2.4.5",
        ),
    )
    brief = review.build(record)
    texts = " ".join(q.text for q in brief.questions)
    assert "request-controlled" not in texts
    assert "upgrade" in texts.lower()


def test_a_hardcoded_secret_is_asked_about_the_secret_not_the_dataflow():
    # "Does request-controlled input reach this password?" decides nothing. What
    # decides it is whether the value is live and whether the file is published.
    from appsec_triage import review
    from appsec_triage.models import EvidenceClass, TriageRecord, Verdict, VerdictLabel

    record = TriageRecord(
        finding_id="f",
        cwe="CWE-798",
        file_path=".env",
        start_line=3,
        verdict=Verdict(
            verdict=VerdictLabel.unknown,
            evidence_class=EvidenceClass.insufficient_context,
            confidence=0.5,
            reason="cannot tell",
        ),
    )
    texts = " ".join(q.text for q in review.build(record).questions)
    assert "request-controlled" not in texts
    assert "live credential" in texts
