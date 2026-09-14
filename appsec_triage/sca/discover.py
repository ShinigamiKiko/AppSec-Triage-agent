"""Dependency findings without a scanner: cdxgen names the packages, OSV the flaws.

The finding list can also come directly from Wolfee. This fallback works in
a sealed image: drop the scanner and the SCA half still has something to triage, even
though everything it needs — the SBOM and the advisory databases — is already
wired in. A container that can build the graph but cannot start the pipeline is
a container that does not work.

The same rule as everywhere else holds here: a database that fails to answer is
recorded as a failure, never as "this package is clean".
"""

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
    """Could this string be a version a database can match a range against?

    Deliberately narrow: it must start with a digit (after an optional `v`) and
    carry nothing a version never contains. Everything an ecosystem really uses
    passes — `1.2.3`, `v0.10.0`, `2:1.4-1`, `4.17.15-beta.1`, a Go pseudo-version
    — while a build directive, a comparison operator or a range does not.

    The point is not to validate semver. It is that a query built on a string
    like `=>` still returns advisories, and those advisories are about nothing.
    """
    value = (value or "").strip()
    return bool(value) and bool(_VERSION.match(value))


def _one_per_flaw(found: list) -> list:
    """One finding per vulnerability, not one per database that described it.

    OSV answers with the ecosystem's own record *and* its GHSA mirror, tied
    together by `aliases`. Emitting both was measured on a Go project: twenty
    seven findings for thirteen flaws, each reported twice under different ids,
    and an engineer reading the report has no way to tell that the two lines are
    one problem. The surviving copy is the one that states its symbols, since
    that is the copy the rest of the chain can act on.
    """
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
    for item in parts.values():
        name, version = item["name"], item["version"]
        if not version or (name, version) in seen:
            continue
        if not _is_a_version(version):
            # Asking a database "what affects this package at version `=>`" gets
            # an answer, and the answer is not about anything. Measured on a Go
            # project whose go.mod uses `replace`: cdxgen put the directive's
            # arrow in the purl, forty-one findings of a hundred carried it, and
            # one advisory that does not apply to the real version was reported
            # as actual. Better to say the version is unknown than to report
            # findings drawn against it.
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

        try:
            found = adv.from_osv(name, item["ecosystem"], version)
        except adv.DatabaseUnavailable as exc:
            # Not a clean package — an unanswered question, and the difference
            # is the whole point of raising here rather than returning [].
            out.problems.append(f"{name}@{version}: {exc}")
            continue

        for entry in _one_per_flaw(found):
            out.findings.append(Finding(
                finding_id=f"{entry.advisory_id}-{name}",
                scanner="cdxgen+osv",
                rule_id=entry.advisory_id,
                title=(entry.summary or entry.advisory_id)[:200],
                severity=Severity.medium,
                code_context=CodeContext(file_path=_manifest_for(item["ecosystem"])),
                dependency=DependencyInfo(
                    package=name,
                    ecosystem=item["ecosystem"],
                    installed_version=version,
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
