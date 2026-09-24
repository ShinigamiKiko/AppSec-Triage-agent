"""Dependency findings without a scanner: cdxgen names the packages, OSV the flaws."""

from __future__ import annotations

import logging
import re
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
        self.problems: list[str] = []

    @property
    def usable(self) -> bool:
        return bool(self.findings) or self.packages_checked > 0


_VERSION = re.compile(r"^[vV]?\d[\w.+~:-]*$")


def _is_a_version(value: str) -> bool:
    """Could this string be a version a database can match a range against?"""
    value = (value or "").strip()
    return bool(value) and bool(_VERSION.match(value))


def _severity(level: str) -> Severity:
    """The advisory's own severity; `medium` only when the database gives none.

    Every dependency finding used to be `medium`, so the high/critical
    escalation and the priority order never saw a difference between them.
    """
    try:
        return Severity(level) if level else Severity.medium
    except ValueError:
        return Severity.medium


def _one_per_flaw(found: list) -> list:
    """One finding per vulnerability, not one per database that described it."""
    groups: dict[str, list] = {}
    for entry in found:
        names = {entry.advisory_id.upper(), *(a.upper() for a in entry.aliases)}
        key = next((k for k in groups if names & groups[k][0]), None)
        if key is None:
            groups[entry.advisory_id] = [names, [entry]]
        else:
            groups[key][0] |= names
            groups[key][1].append(entry)

    out = []
    for names, entries in groups.values():
        entries.sort(key=lambda e: (not e.symbols, not e.import_paths,
                                    not e.fix_refs, -len(e.details)))
        out.append(entries[0])
    return out


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
    wanted: list[dict] = []
    for item in parts.values():
        name, version = item["name"], item["version"]
        if not version or (name, version) in seen:
            continue
        if not _is_a_version(version):
            out.problems.append(
                f"{name}: версия не определена ({version!r}) — пакет пропущен. "
                "У Go это обычно директива `replace` в go.mod, чью стрелку "
                "cdxgen положил в purl; проверьте вручную.")
            continue
        if limit and out.packages_checked >= limit:
            out.problems.append(f"опрошено {limit} пакетов из {len(parts)} — остальные пропущены")
            break
        seen.add((name, version))
        out.packages_checked += 1
        wanted.append(item)

    try:
        answers = adv.from_osv_batch([(i["name"], i["ecosystem"], i["version"]) for i in wanted])
    except adv.DatabaseUnavailable as exc:
        log.warning("OSV querybatch недоступен (%s) — опрос по одному пакету", exc)
        answers = {}
        for i in wanted:
            key = (i["name"], i["ecosystem"], i["version"])
            try:
                answers[key] = adv.from_osv(*key)
            except adv.DatabaseUnavailable as single_exc:
                answers[key] = single_exc

    for item in wanted:
        name, version = item["name"], item["version"]
        found = answers.get((name, item["ecosystem"], version), [])
        if isinstance(found, adv.DatabaseUnavailable):
            out.problems.append(f"{name}@{version}: {found}")
            continue

        for entry in _one_per_flaw(found):
            out.findings.append(Finding(
                finding_id=f"{entry.advisory_id}-{name}",
                scanner="cdxgen+osv",
                rule_id=entry.advisory_id,
                title=(entry.summary or entry.advisory_id)[:200],
                severity=_severity(entry.severity_level),
                code_context=CodeContext(file_path=_manifest_for(item["ecosystem"])),
                dependency=DependencyInfo(
                    package=name,
                    ecosystem=item["ecosystem"],
                    installed_version=version,
                    fixed_versions=entry.fixed_versions,
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
    """A file path the report can show."""
    return _MANIFESTS.get((ecosystem or "").strip().lower(), "dependencies")
