"""Pull the dependency facts out of an SCA report."""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
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


log = logging.getLogger(__name__)


def _composer_packages(root: Path) -> list[tuple[str, str]]:
    """(name, version) of every package composer.lock or vendor/composer/installed.json lists."""
    out: list[tuple[str, str]] = []
    for rel, keys in (("composer.lock", ("packages", "packages-dev")),
                      ("vendor/composer/installed.json", ("packages",))):
        path = Path(root) / rel
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        items = data if isinstance(data, list) else [p for k in keys for p in (data.get(k) or [])]
        out += [(str(p.get("name") or ""), str(p.get("version") or "")) for p in items if isinstance(p, dict)]
    return out


def qualify_composer_names(findings, roots) -> int:
    """Restore `vendor/name` for Composer packages a scanner reported by the bare name.

    An older wolfee wrote `packagist/yaml@v7.3.0` for symfony/yaml, and no
    vulnerability database knows a Composer package called `yaml`. The project's
    own lock file does; the name is taken only when it is unambiguous.
    """
    packages: list[tuple[str, str]] = []
    for root in roots or []:
        packages += _composer_packages(Path(root))
    if not packages:
        return 0
    fixed = 0
    for finding in findings:
        dep = getattr(finding, "dependency", None)
        if dep is None or (dep.ecosystem or "") != "packagist" or not dep.package or "/" in dep.package:
            continue
        short = dep.package.lower()
        matches = {name for name, _ in packages if name.lower().endswith("/" + short)}
        if len(matches) > 1:
            version = (dep.installed_version or "").lstrip("vV")
            matches = {name for name, v in packages
                       if name.lower().endswith("/" + short) and v.lstrip("vV") == version}
        if len(matches) == 1:
            full = matches.pop()
            log.info("composer package %s qualified as %s from the lock file", dep.package, full)
            dep.package = full
            fixed += 1
    return fixed
