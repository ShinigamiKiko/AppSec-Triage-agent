"""Pull the dependency facts out of an SCA report."""

from __future__ import annotations

import re
from typing import Any

from ..models import DependencyInfo

_LABELLED = {
    "package": re.compile(r"^\s*(?:Package|Artifact|Component)\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
    "installed": re.compile(r"^\s*(?:Installed Version|Version|Current Version)\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
    "fixed": re.compile(r"^\s*Fixed Version[s]?\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE),
    "link": re.compile(r"^\s*Link\s*:\s*\[?[^\]]*\]?\(?(https?://\S+?)\)?\s*$", re.IGNORECASE | re.MULTILINE),
}

_ONE_LINER = re.compile(
    r"\bin\s+(?P<eco>[a-z][\w.-]*)/(?P<name>[\w./@-]+?)@(?P<version>[^\s,]+)"
    r"(?:.*?\bfixed=(?P<fixed>[^\s]+))?",
    re.IGNORECASE | re.DOTALL,
)

_PURL = re.compile(r"pkg:(?P<eco>[a-z]+)/(?P<name>[^@?#]+)(?:@(?P<version>[^?#]+))?", re.IGNORECASE)

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


_MISCONFIG_TELL = re.compile(r"(/misconfig/|\bType:\s*(dockerfile|kubernetes|terraform|cloudformation)\b)", re.IGNORECASE)
_MISCONFIG_RULE = re.compile(r"^(DS-|AVD-|KSV-|KCV-)", re.IGNORECASE)


def looks_like_dependency(file_path: str, rule_id: str | None, text: str) -> bool:
    """Is this about a shipped component rather than a line of our code?"""
    if (rule_id and _MISCONFIG_RULE.match(rule_id)) or _MISCONFIG_TELL.search(text or ""):
        return False
    name = file_path.replace("\\", "/").rsplit("/", 1)[-1]
    if name in LOCKFILE_NAMES:
        return True
    if rule_id and re.match(r"^(CVE-|GHSA-|GO-|RUSTSEC-|OSV-|DSA-|DLA-)", rule_id, re.IGNORECASE):
        return True
    return bool(_LABELLED["package"].search(text or ""))


def parse(text: str, properties: dict[str, Any] | None = None) -> DependencyInfo | None:
    """Best-effort extraction."""
    text = text or ""
    props = properties or {}

    package = ecosystem = installed = None
    fixed: list[str] = []
    link = None
    reachability = props.get("reachability")
    call_site = props.get("callSite")
    call_line = props.get("callLine")

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
        reachability=reachability if isinstance(reachability, str) else None,
        call_site=call_site if isinstance(call_site, str) else None,
        call_line=call_line if isinstance(call_line, str) else None,
    )
