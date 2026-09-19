"""Scope filter — the layer before the layers."""

from __future__ import annotations

import fnmatch
import logging
import re
from dataclasses import dataclass, field

from .config import ScopeConfig
from .models import EvidenceClass, Finding, TriageRecord, Verdict, VerdictLabel
from .reuse import fingerprint as _fingerprint

log = logging.getLogger(__name__)

_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]

_ECOSYSTEM_ALIASES = {
    "go": "go", "golang": "go",
    "npm": "npm", "node": "npm", "nodejs": "npm", "javascript": "npm",
    "js": "npm", "ts": "npm", "typescript": "npm", "yarn": "npm", "pnpm": "npm",
    "composer": "composer", "php": "composer", "packagist": "composer",
    "pypi": "pypi", "python": "pypi", "pip": "pypi",
    "nuget": "nuget", "dotnet": "nuget", "csharp": "nuget", "c#": "nuget",
    "maven": "maven", "java": "maven", "gradle": "maven", "kotlin": "maven",
    "gem": "gem", "rubygems": "gem", "ruby": "gem",
    "cargo": "cargo", "crates": "cargo", "rust": "cargo",
}


def _ecosystem(value: str | None) -> str:
    """One canonical name for an ecosystem, or "" when nothing was given."""
    name = (value or "").strip().lower()
    return _ECOSYSTEM_ALIASES.get(name, name)


@dataclass(slots=True)
class ScopeResult:
    kept: list[Finding] = field(default_factory=list)
    excluded: list[TriageRecord] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)


def _matches(value: str | None, patterns: list[str]) -> str | None:
    """Return the pattern that matched, so the record can name it."""
    if not value:
        return None
    for pat in patterns:
        if fnmatch.fnmatch(value, pat) or re.search(pat, value):
            return pat
    return None


def _excluded_record(finding: Finding, rule: str, why: str,
                     evidence_class: EvidenceClass = EvidenceClass.test_placeholder) -> TriageRecord:
    return TriageRecord(
        finding_id=finding.finding_id,
        cwe=finding.cwe,
        file_path=finding.code_context.file_path,
        rule_id=finding.rule_id,
        fingerprint=_fingerprint(finding),
        verdict=Verdict(
            verdict=VerdictLabel.false_positive,
            evidence_class=evidence_class,
            confidence=1.0,
            confidence_rationale=(
                "Not a model judgement: this finding is outside the configured triage scope, "
                "so no confidence is being asserted about the code itself."
            ),
            cwe=finding.cwe,
            evidence=[],
            reason=f"Out of triage scope: {why} (rule: {rule})",
            missing_information=[],
            requires_human_review=False,
        ),
        decided_by="scope",
        overrides=[f"scope_excluded: {rule}"],
    )


def apply(findings: list[Finding], cfg: ScopeConfig) -> ScopeResult:
    result = ScopeResult()
    if not cfg.enabled:
        result.kept = list(findings)
        return result

    min_idx = _SEVERITY_ORDER.index(cfg.min_severity) if cfg.min_severity else -1
    ecosystems = {_ecosystem(e) for e in cfg.only_ecosystems if e and e.strip()}

    for f in findings:
        if pat := _matches(f.rule_id, cfg.exclude_rules):
            result.excluded.append(_excluded_record(f, pat, "rule is excluded from triage"))
            result.counts[f"rule:{pat}"] = result.counts.get(f"rule:{pat}", 0) + 1
            continue
        if pat := _matches(f.code_context.file_path, cfg.exclude_paths):
            result.excluded.append(_excluded_record(f, pat, "path is excluded from triage"))
            result.counts[f"path:{pat}"] = result.counts.get(f"path:{pat}", 0) + 1
            continue
        if ecosystems and f.dependency is not None:
            found = _ecosystem(f.dependency.ecosystem)
            if found and found not in ecosystems:
                rule = f"only_ecosystems={sorted(ecosystems)}"
                result.excluded.append(_excluded_record(
                    f, rule,
                    f"экосистема {found} не триажится этой установкой — "
                    "о самом пакете это ничего не утверждает",
                    evidence_class=EvidenceClass.insufficient_context))
                key = f"ecosystem:{found}"
                result.counts[key] = result.counts.get(key, 0) + 1
                continue
        if cfg.only_cwes and f.cwe not in cfg.only_cwes:
            rule = f"only_cwes={cfg.only_cwes}"
            result.excluded.append(_excluded_record(f, rule, f"CWE {f.cwe} is not in the triaged set"))
            result.counts["cwe_not_in_scope"] = result.counts.get("cwe_not_in_scope", 0) + 1
            continue
        if (
            min_idx >= 0
            and f.severity.value in _SEVERITY_ORDER
            and _SEVERITY_ORDER.index(f.severity.value) < min_idx
        ):
            rule = f"min_severity={cfg.min_severity}"
            result.excluded.append(_excluded_record(f, rule, f"severity {f.severity.value} is below the floor"))
            result.counts["below_min_severity"] = result.counts.get("below_min_severity", 0) + 1
            continue
        result.kept.append(f)

    for key, count in sorted(result.counts.items()):
        if key.startswith("ecosystem:"):
            log.warning(
                "scope: dropped %d finding(s) in ecosystem %r, which is not in "
                "only_ecosystems=%s. If this ecosystem is now part of the project, "
                "the filter is hiding real findings — update the config.",
                count, key.split(":", 1)[1], sorted(ecosystems))

    return result
