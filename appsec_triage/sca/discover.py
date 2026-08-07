"""Dependency findings without a scanner: cdxgen names the packages, OSV the flaws.

The finding list comes directly from the SBOM and advisory databases. SCA has one
authoritative path: cdxgen builds the graph and OSV supplies affected advisories.

The same rule as everywhere else holds here: a database that fails to answer is
recorded as a failure, never as "this package is clean".
"""

from __future__ import annotations

import logging
from pathlib import Path

from ..models import CodeContext, DependencyInfo, Finding, Severity
from . import advisories as adv
from . import sbom

log = logging.getLogger(__name__)


class Discovery:
    """What was found, and what could not be asked."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.packages_checked = 0
        self.packages_succeeded = 0
        self.problems: list[str] = []

    @property
    def usable(self) -> bool:
        return self.packages_succeeded > 0


def discover(root: Path | str, *, sbom_path: Path | None = None,
             limit: int = 0) -> Discovery:
    """Every advisory affecting a package this project resolves to."""
    out = Discovery()
    root = Path(root)

    if sbom_path is not None and Path(sbom_path).exists():
        document, problem = sbom.read(Path(sbom_path))
    else:
        document, problem = sbom.generate(root)
    if document is None:
        out.problems.append(problem)
        log.warning("%s", problem)
        return out

    parts = sbom.components(document)
    log.info("SBOM: %d components at %s", len(parts), root)

    seen: set[tuple[str, str]] = set()
    for item in parts.values():
        name, version = item["name"], item["version"]
        if not version or (name, version) in seen:
            continue
        if limit and out.packages_checked >= limit:
            out.problems.append(f"опрошено {limit} пакетов из {len(parts)} — остальные пропущены")
            break
        seen.add((name, version))
        out.packages_checked += 1

        try:
            found = adv.from_osv(name, item["ecosystem"], version)
        except adv.DatabaseUnavailable as exc:
            # Not a clean package — an unanswered question, and the difference
            # is the whole point of raising here rather than returning [].
            out.problems.append(f"{name}@{version}: {exc}")
            continue
        out.packages_succeeded += 1

        for entry in found:
            out.findings.append(Finding(
                finding_id=f"{entry.advisory_id}-{name}",
                scanner="cdxgen+osv",
                rule_id=entry.advisory_id,
                cwe=entry.cwe or None,
                title=(entry.summary or entry.advisory_id)[:200],
                severity=Severity.medium,
                code_context=CodeContext(file_path=_manifest_for(item["ecosystem"])),
                dependency=DependencyInfo(
                    package=name,
                    ecosystem=item["ecosystem"],
                    installed_version=version,
                    fixed_versions=entry.fixed_versions,
                    advisory_aliases=entry.aliases,
                    advisory_url=f"https://osv.dev/vulnerability/{entry.advisory_id}",
                    dev_only=item["dev"] or None,
                ),
            ))

    log.info("discovered %d dependency findings across %d packages",
             len(out.findings), out.packages_checked)
    return out


_MANIFESTS = {
    "composer": "composer.json", "npm": "package.json", "pypi": "requirements.txt",
    "go": "go.mod", "maven": "pom.xml", "nuget": "packages.config",
    "rubygems": "Gemfile", "cargo": "Cargo.toml",
}


def _manifest_for(ecosystem: str) -> str:
    """A file path the report can show. The flaw is in a package, not a line."""
    return _MANIFESTS.get((ecosystem or "").strip().lower(), "dependencies")
