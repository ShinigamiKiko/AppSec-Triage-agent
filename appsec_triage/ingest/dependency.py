"""Pull the dependency facts out of an SCA report.

Every SCA scanner emits the same handful of facts — package, installed version,
fixed version, advisory link — and every one of them emits it as prose in a
`help` blob rather than as fields. Left unparsed the model receives one long
sentence and cannot weigh anything: on a real project all 89 dependency
findings arrived that way and every one landed in `unknown`.

Several common formats are handled because dependency producers encode the same
facts differently:

    SARIF    "Package: api-platform/core\\nInstalled Version: v2.6.8\\n..."
    wolfee   "GHSA-… in packagist/security-http@v5.4.22 - fixed=5.4.53"
    Grype    "…" plus proper `properties`, which are preferred when present

Parsing is best-effort and never fatal: a finding whose package cannot be read
stays a normal finding and reaches the model as before.
"""

from __future__ import annotations

import re
from typing import Any

from ..models import DependencyInfo

_LABELLED = {
    "package": re.compile(r"^\s*(?:Package|Artifact|Component)\s*:\s*(.+?)\s*$", re.I | re.M),
    "installed": re.compile(r"^\s*(?:Installed Version|Version|Current Version)\s*:\s*(.+?)\s*$", re.I | re.M),
    "fixed": re.compile(r"^\s*Fixed Version[s]?\s*:\s*(.+?)\s*$", re.I | re.M),
    "link": re.compile(r"^\s*Link\s*:\s*\[?[^\]]*\]?\(?(https?://\S+?)\)?\s*$", re.I | re.M),
}

_ONE_LINER = re.compile(
    r"\bin\s+(?P<eco>[a-z][\w.-]*)/(?P<name>[\w./@-]+?)@(?P<version>[^\s,]+)"
    r"(?:.*?\bfixed=(?P<fixed>[^\s]+))?",
    re.I | re.S,
)

_PURL = re.compile(r"pkg:(?P<eco>[a-z]+)/(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?", re.I)

_ECOSYSTEM_ALIASES = {
    "packagist": "packagist", "composer": "packagist", "php": "packagist",
    "npm": "npm", "node": "npm",
    "pypi": "pypi", "python": "pypi",
    "maven": "maven", "java": "maven",
    "go": "go", "golang": "go",
    "rubygems": "rubygems", "gem": "rubygems",
    "nuget": "nuget", "cargo": "cargo",
}

LOCKFILE_NAMES = {
    "composer.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "Pipfile.lock", "requirements.txt", "go.sum", "go.mod",
    "Gemfile.lock", "Cargo.lock", "packages.lock.json", "pom.xml", "build.gradle",
}


def _split_versions(raw: str) -> list[str]:
    return [v.strip() for v in re.split(r"[,;]| or ", raw) if v.strip()]


def _normalize_ecosystem(value: str | None) -> str | None:
    if not value:
        return None
    return _ECOSYSTEM_ALIASES.get(value.strip().lower(), value.strip().lower())


_MISCONFIG_TELL = re.compile(r"(/misconfig/|\bType:\s*(dockerfile|kubernetes|terraform|cloudformation)\b)", re.I)
_MISCONFIG_RULE = re.compile(r"^(DS-|AVD-|KSV-|KCV-)", re.I)


def looks_like_dependency(file_path: str, rule_id: str | None, text: str) -> bool:
    """Is this about a shipped component rather than a line of our code?"""
    if (rule_id and _MISCONFIG_RULE.match(rule_id)) or _MISCONFIG_TELL.search(text or ""):
        return False
    name = file_path.replace("\\", "/").rsplit("/", 1)[-1]
    if name in LOCKFILE_NAMES:
        return True
    if rule_id and re.match(r"^(CVE-|GHSA-|GO-|RUSTSEC-|OSV-|DSA-|DLA-)", rule_id, re.I):
        return True
    return bool(_LABELLED["package"].search(text or ""))


def parse(text: str, properties: dict[str, Any] | None = None) -> DependencyInfo | None:
    """Best-effort extraction. Returns None when there is no package to name."""
    text = text or ""
    props = properties or {}

    package = ecosystem = installed = None
    fixed: list[str] = []
    link = None

    for value in props.values():
        if isinstance(value, str) and (m := _PURL.search(value)):
            ecosystem = _normalize_ecosystem(m.group("eco"))
            package = m.group("name")
            installed = m.group("version") or installed
            break

    if m := _LABELLED["package"].search(text):
        package = package or m.group(1)
    if m := _LABELLED["installed"].search(text):
        installed = installed or m.group(1)
    if m := _LABELLED["fixed"].search(text):
        fixed = _split_versions(m.group(1))
    if m := _LABELLED["link"].search(text):
        link = m.group(1)

    if package is None and (m := _ONE_LINER.search(text)):
        ecosystem = ecosystem or _normalize_ecosystem(m.group("eco"))
        package = m.group("name")
        installed = installed or m.group("version")
        if m.group("fixed"):
            fixed = _split_versions(m.group("fixed"))

    if not package:
        return None

    head = package.split("/", 1)[0].lower()
    if head in _ECOSYSTEM_ALIASES and "/" in package:
        ecosystem = ecosystem or _normalize_ecosystem(head)
        package = package.split("/", 1)[1]

    return DependencyInfo(
        package=package.strip(),
        ecosystem=ecosystem,
        installed_version=(installed or "").strip() or None,
        fixed_versions=fixed,
        advisory_url=link,
    )
