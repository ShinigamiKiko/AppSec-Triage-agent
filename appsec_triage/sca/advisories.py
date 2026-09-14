"""Where the vulnerability was described and where it was fixed, looked up live.

Every database holds a different part of the answer, so none of them is
sufficient alone:

- **OSV** aggregates. It answers "which advisories affect this package at this
  version", carries the aliases that let one flaw be recognised under CVE, GHSA,
  BIT and DRUPAL ids, and lists references — including, usually, the fix commit.
- **GHSA** carries the maintainer's own write-up. That prose is what most often
  names the vulnerable symbol outright, and it is richer than the NVD summary.
- **NVD** is the fallback and the cross-check. When an advisory reaches us as a
  bare CVE id with no ecosystem, NVD is the source that still knows something,
  and its reference list sometimes carries a patch link the others lack.

References are ranked, not taken first-come: a commit is a fix, a release tag is
a bundle of fixes, and an advisory page is prose. Getting this order wrong was
measured — taking the first link that produced a diff handed two different
advisories the same release diff, and the extraction was then judged on a diff
that need not contain the fix at all. Ranking reads each reference's declared
`type` and does not guess from the URL: Go publishes its fixes as Gerrit
changelists, so a shape test written around `github.com/.../commit/` concluded
that Go advisories carry no fix at all — a measurement of the test, not of Go.

Some ecosystems state the vulnerable symbols outright. Go's database lists them
per import path in `ecosystem_specific`, curated by hand, and that is a better
answer than anything inferred from a diff — so it is read here and used as-is
rather than re-derived. Only the Go-native `GO-` records carry it; the GHSA
mirrors of the same flaw do not, which is why entries that have symbols are
preferred when several describe one vulnerability.
"""

from __future__ import annotations

import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import cassette

log = logging.getLogger(__name__)

_TIMEOUT = 30
_RETRIES = 3
_BACKOFF_S = 1.5
_UA = {"User-Agent": "appsec-triage"}

_COMMIT = re.compile(
    r"https?://github\.com/([^/\s]+)/([^/\s]+)/(commit|pull)/([0-9a-f]{7,40}|\d+)")
_PATCH = re.compile(r"https?://\S+\.(?:patch|diff)$")

_ECOSYSTEM = {
    "composer": "Packagist", "packagist": "Packagist", "php": "Packagist",
    "npm": "npm", "node": "npm", "javascript": "npm", "yarn": "npm",
    "pypi": "PyPI", "python": "PyPI", "pip": "PyPI",
    "go": "Go", "golang": "Go",
    "maven": "Maven", "java": "Maven",
    "nuget": "NuGet", "rubygems": "RubyGems", "gem": "RubyGems",
    "cargo": "crates.io", "rust": "crates.io",
}


def osv_ecosystem(name: str | None) -> str | None:
    return _ECOSYSTEM.get((name or "").strip().lower())


@dataclass(slots=True)
class Advisory:
    """One flaw, with everything needed to find its symbol."""

    advisory_id: str
    package: str = ""
    ecosystem: str = ""
    summary: str = ""
    details: str = ""
    aliases: list[str] = field(default_factory=list)
    fix_refs: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    import_paths: list[str] = field(default_factory=list)
    named_symbols: list[str] = field(default_factory=list)
    """Function names the description mentions — candidates, not a statement.

    Kept apart from `symbols`, which a database curated and which can be acted
    on directly. These come from prose and carry prose's noise, so they are
    offered to the search as things to look for, never as the answer."""
    cwe_ids: list[str] = field(default_factory=list)
    """Weakness classes, when a database states them.

    Decides whether "attacker input does not reach this call" closes a finding:
    it does for a flaw that needs attacker-controlled input and does not for one
    that does not. Go's own records carry no CWE; the GHSA mirror usually does,
    which is one more reason to merge the two rather than take the first."""
    sources: list[str] = field(default_factory=list)
    severity: str = ""
    problem: str = ""

    @property
    def text(self) -> str:
        return f"{self.summary}\n\n{self.details}".strip()

    @property
    def usable(self) -> bool:
        return bool(self.text or self.fix_refs or self.symbols or self.import_paths)


class DatabaseUnavailable(Exception):
    """A database did not answer. Never the same thing as answering "none".

    Swallowing this was measured: one run reported ten advisories for jinja2 and
    the next reported zero, because the query timed out and the empty list was
    indistinguishable from a clean package. A scanner that reports "no known
    vulnerabilities" when it in fact failed to ask is worse than one that
    crashes.
    """


def _get_json(url: str, body: bytes | None = None, headers: dict | None = None):
    """Parsed JSON, or `DatabaseUnavailable`. A 404 is an answer and returns None.

    Retried, because a triage run makes one query per CVE and a single dropped
    connection then costs a whole finding: measured on a real project, 34 of 53
    lookups failed with "network is unreachable" while the same queries
    succeeded moments later. Rate limiting is backed off for; a 404 and a
    malformed body are answers and are not retried.
    """
    last: Exception | None = None
    for attempt in range(_RETRIES):
        try:
            request = urllib.request.Request(
                url, data=body, headers={**_UA, **(headers or {})})
            with cassette.urlopen(request, timeout=_TIMEOUT) as response:
                return json.load(response)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            if exc.code not in (429, 500, 502, 503, 504):
                raise DatabaseUnavailable(f"{url} -> HTTP {exc.code}") from exc
            last = exc
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
        except (ValueError, json.JSONDecodeError) as exc:
            raise DatabaseUnavailable(f"{url} -> нечитаемый ответ: {exc}") from exc
        if attempt + 1 < _RETRIES:
            time.sleep(_BACKOFF_S * (attempt + 1))
    raise DatabaseUnavailable(f"{url} -> {last} (после {_RETRIES} попыток)")


def _severity_of(entry: dict) -> str:
    """The CVSS vector as published, from whichever shape the source uses."""
    for item in entry.get("severity") or []:
        score = str(item.get("score", ""))
        if score.startswith("CVSS:"):
            return score
    for affected in entry.get("affected") or []:
        database = (affected.get("database_specific") or {})
        value = str(database.get("cvss") or database.get("severity") or "")
        if value.startswith("CVSS:"):
            return value
    return ""


def _refs(entry: dict) -> list[tuple[str, str]]:
    """Every reference as (url, declared type), the type upper-cased or empty."""
    out = []
    for ref in entry.get("references") or []:
        url = str(ref.get("url") or "")
        if url:
            out.append((url, str(ref.get("type") or "").upper()))
    return out


def _rank_refs(refs: list[tuple[str, str]]) -> list[str]:
    """Fetchable fix links, best first.

    Only links a diff can be read from survive, since that is the sole use of
    this list; a Gerrit changelist names the fix but cannot be turned into a
    diff here, and keeping it would only buy four dead fetches per advisory.
    Within that, a reference the database itself typed as FIX outranks one
    merely shaped like a commit — `gin` publishes three fix commits and an
    unrelated pull request under the same URL shape.
    """
    tiers: dict[tuple[int, int], list[str]] = {}
    for url, kind in refs:
        match = _COMMIT.match(url)
        if match:
            shape = 2 if match.group(3) == "pull" else 0
        elif _PATCH.match(url):
            shape = 1
        else:
            continue
        tiers.setdefault((0 if kind == "FIX" else 1, shape), []).append(url)

    seen, ranked = set(), []
    for key in sorted(tiers):
        for url in tiers[key]:
            if url not in seen:
                seen.add(url)
                ranked.append(url)
    return ranked


def _github_fix_refs(advisory_id: str) -> list[str]:
    """Find fetchable fix references in GitHub's public advisory record.

    OSV is the primary source. GitHub is only a repair path for npm advisories
    whose OSV record has prose but no usable FIX reference. The REST endpoint is
    used instead of requiring a GraphQL token; a token is still accepted when
    the operator has one, which raises the rate limit without changing behavior.
    """
    if not advisory_id.upper().startswith("GHSA-"):
        return []
    headers = dict(_UA)
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    try:
        data = _get_json(f"https://api.github.com/advisories/{advisory_id}", headers=headers)
    except DatabaseUnavailable:
        return []
    refs = []
    for item in (data or {}).get("references") or []:
        if isinstance(item, dict):
            refs.append((str(item.get("url") or ""), str(item.get("type") or "")))
    return _rank_refs(refs)


_BACKTICKED = re.compile(r"`([^`\n]{1,60})`")
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
# Words that appear in backticks in these descriptions and are never the flaw:
# option names, config keys and the prose's own vocabulary.
_NOT_A_FUNCTION = {
    "true", "false", "null", "undefined", "options", "option", "variable",
    "constructor", "prototype", "__proto__", "name", "value", "type", "default",
}
# Built-in types the prose names as the thing being polluted or parsed, never as
# the call: "modify the prototype of `Object`". Matched with case, because the
# capital is what separates them from real functions — lodash's vulnerable `set`
# must survive while `Set` must not.
_BUILTIN_TYPES = {
    "Object", "Array", "String", "Number", "Boolean", "Function", "JSON",
    "Map", "Set", "Date", "RegExp", "Promise", "Buffer", "Error", "Symbol",
}


def _named_in_prose(text: str, package: str) -> list[str]:
    """Function names the description states outright, in backticks.

    npm has no curated symbol list — the field Go fills is empty — so the only
    place a name is published is the prose, and it is published often enough to
    be worth reading: "The functions `pick`, `set`, `setWith`, `update`,
    `updateWith`, and `zipObjectDeep` allow a malicious user to…".

    Unlike Go's list this is not authoritative. The same backticks wrap package
    names, option names and internal identifiers, so what comes out is a set of
    candidates to search for, not a statement about the flaw. Measured over nine
    npm advisories: two yielded exactly the right names, one added noise, and
    five had no backticks at all.
    """
    segments = {part for part in re.split(r"[/@._-]", (package or "").lower()) if part}
    out: list[str] = []
    for token in _BACKTICKED.findall(text or ""):
        name = token.strip()
        if not _IDENTIFIER.match(name):
            continue
        if name in _BUILTIN_TYPES:
            continue
        if name.lower() in _NOT_A_FUNCTION or name.lower() in segments:
            continue
        if name not in out:
            out.append(name)
    return out


def _cwes_of(entry: dict) -> list[str]:
    """Weakness ids a database states, deduplicated and upper-cased."""
    out: list[str] = []
    for source in (entry, *(entry.get("affected") or [])):
        for value in (source.get("database_specific") or {}).get("cwe_ids") or []:
            ident = str(value).strip().upper()
            if ident and ident not in out:
                out.append(ident)
    return out


def _import_paths_of(entry: dict) -> list[str]:
    """Vulnerable import paths the database names, symbols or not.

    A package-level advisory — "this package is unmaintained and unsafe" — names
    the affected import paths but no function, because the flaw is the package
    itself. That list is what decides such a finding: the module can be present
    through a safe sub-package while the vulnerable path is never imported, so
    the answer is at import-path granularity, not module granularity.
    """
    out: list[str] = []
    for affected in entry.get("affected") or []:
        for item in (affected.get("ecosystem_specific") or {}).get("imports") or []:
            path = str(item.get("path") or "").strip()
            if path and path not in out:
                out.append(path)
    return out


def _symbols_of(entry: dict) -> list[str]:
    """Vulnerable symbols the database states outright, fully qualified.

    Returned as `import/path.Symbol` (or `.Receiver.Method`) so the caller can
    tell a symbol belonging to the package itself from one belonging to the
    standard library it calls through.
    """
    out: list[str] = []
    for affected in entry.get("affected") or []:
        for item in (affected.get("ecosystem_specific") or {}).get("imports") or []:
            path = str(item.get("path") or "").strip()
            for symbol in item.get("symbols") or []:
                name = f"{path}.{symbol}" if path else str(symbol)
                if name not in out:
                    out.append(name)
    return out



def from_osv(package: str, ecosystem: str, version: str) -> list[Advisory]:
    """Every advisory affecting this exact version.

    Raises `DatabaseUnavailable` rather than returning an empty list when the
    query fails, so a caller cannot mistake silence for a clean package.
    """
    osv_name = osv_ecosystem(ecosystem)
    if not (package and osv_name and version):
        return []
    payload = json.dumps({"package": {"name": package, "ecosystem": osv_name},
                          "version": version}).encode()
    data = _get_json("https://api.osv.dev/v1/query", payload,
                     {"Content-Type": "application/json"})
    if not data:
        return []
    out = []
    for vuln in data.get("vulns") or []:
        out.append(Advisory(
            advisory_id=vuln.get("id", ""), package=package, ecosystem=ecosystem,
            summary=(vuln.get("summary") or "")[:300],
            details=(vuln.get("details") or "")[:8000],
            aliases=list(vuln.get("aliases") or []),
            fix_refs=_rank_refs(_refs(vuln)), symbols=_symbols_of(vuln),
            import_paths=_import_paths_of(vuln), cwe_ids=_cwes_of(vuln),
            sources=["osv"], severity=_severity_of(vuln),
        ))
    # One flaw is often returned twice, as the native record and as its mirror.
    # Only the native one states the symbols, so it must be the one kept.
    out.sort(key=lambda a: not a.symbols)
    return out


def from_ghsa(advisory_id: str) -> Advisory | None:
    """The maintainer's write-up, which usually names the symbol."""
    if not advisory_id.upper().startswith("GHSA-"):
        return None
    data = _get_json(f"https://api.osv.dev/v1/vulns/{advisory_id}")
    if not data:
        return None
    return Advisory(
        advisory_id=data.get("id", advisory_id),
        summary=(data.get("summary") or "")[:300],
        details=(data.get("details") or "")[:8000],
        aliases=list(data.get("aliases") or []),
        fix_refs=_rank_refs(_refs(data)), symbols=_symbols_of(data),
        import_paths=_import_paths_of(data), cwe_ids=_cwes_of(data),
        sources=["ghsa"], severity=_severity_of(data),
    )


def from_nvd(cve_id: str, api_key: str | None = None) -> Advisory | None:
    """The fallback when all we have is a CVE id and no ecosystem."""
    if not cve_id.upper().startswith("CVE-"):
        return None
    headers = {"apiKey": api_key} if api_key else None
    data = _get_json(
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}", headers=headers)
    items = (data or {}).get("vulnerabilities") or []
    if not items:
        return None
    cve = items[0].get("cve") or {}
    descriptions = [d.get("value", "") for d in cve.get("descriptions") or []
                    if d.get("lang") == "en"]
    return Advisory(
        advisory_id=cve.get("id", cve_id),
        summary=(descriptions[0] if descriptions else "")[:300],
        details="\n".join(descriptions)[:8000],
        fix_refs=_rank_refs(_refs(cve)), sources=["nvd"],
    )


def collect(
    advisory_id: str = "",
    package: str = "",
    ecosystem: str = "",
    version: str = "",
    *,
    nvd_api_key: str | None = None,
) -> Advisory:
    """One advisory, merged from whichever databases answered.

    Merging matters: OSV reliably has the fix commit, GHSA reliably has the prose
    that names the symbol, and an advisory with only one of the two is much
    harder to resolve. Failures are recorded in `problem` rather than raised —
    a database being down must degrade this to "unknown", not end the scan.
    """
    merged = Advisory(advisory_id=advisory_id, package=package, ecosystem=ecosystem)
    tried: list[str] = []
    failures: list[str] = []

    candidates: list[Advisory] = []
    if package and version:
        try:
            found = from_osv(package, ecosystem, version)
        except DatabaseUnavailable as exc:
            found = []
            failures.append(f"osv: {exc}")
        tried.append("osv")
        if advisory_id:
            wanted = advisory_id.strip().upper()
            found = [a for a in found
                     if wanted in {a.advisory_id.upper(), *(x.upper() for x in a.aliases)}] or found
        candidates.extend(found[:1] if advisory_id else found)

    ids = {advisory_id, *(a.advisory_id for a in candidates)}
    ids |= {alias for a in candidates for alias in a.aliases}
    for ident in [i for i in ids if i]:
        if ident.upper().startswith("GHSA-"):
            tried.append("ghsa")
            try:
                entry = from_ghsa(ident)
            except DatabaseUnavailable as exc:
                failures.append(f"ghsa: {exc}")
                break
            if entry:
                candidates.append(entry)
                break

    if not any(c.details for c in candidates):
        for ident in [i for i in ids if i and i.upper().startswith("CVE-")]:
            tried.append("nvd")
            try:
                entry = from_nvd(ident, nvd_api_key)
            except DatabaseUnavailable as exc:
                failures.append(f"nvd: {exc}")
                break
            if entry:
                candidates.append(entry)
            break

    for entry in candidates:
        merged.advisory_id = merged.advisory_id or entry.advisory_id
        if len(entry.details) > len(merged.details):
            merged.details = entry.details
        if len(entry.summary) > len(merged.summary):
            merged.summary = entry.summary
        for alias in entry.aliases:
            if alias not in merged.aliases:
                merged.aliases.append(alias)
        merged.severity = merged.severity or entry.severity
        for symbol in entry.symbols:
            if symbol not in merged.symbols:
                merged.symbols.append(symbol)
        for path in entry.import_paths:
            if path not in merged.import_paths:
                merged.import_paths.append(path)
        for cwe in entry.cwe_ids:
            if cwe not in merged.cwe_ids:
                merged.cwe_ids.append(cwe)
        for ref in entry.fix_refs:
            if ref not in merged.fix_refs:
                merged.fix_refs.append(ref)
        merged.sources.extend(s for s in entry.sources if s not in merged.sources)

    # npm records occasionally contain the GHSA text but omit a FIX reference
    # from OSV. Do not make symbol extraction fall back to guessing when GitHub
    # can still point us at the patch.
    if ecosystem.lower() in {"npm", "node", "javascript", "yarn"} and not merged.fix_refs:
        for ident in [merged.advisory_id, *merged.aliases]:
            for ref in _github_fix_refs(ident):
                if ref not in merged.fix_refs:
                    merged.fix_refs.append(ref)

    # Read from the merged text, not per source: GHSA carries the prose that
    # names the functions and OSV carries the version data, and only the merge
    # has both.
    merged.named_symbols = _named_in_prose(merged.text, package or merged.package)

    # Each source's list is already ranked and merging preserves that order, so
    # re-ranking here would only re-sort urls whose declared type is long gone —
    # dropping the FIX-outranks-shape rule exactly on the merged path.
    if failures:
        merged.problem = "базы не ответили — " + "; ".join(failures)
    elif not merged.usable:
        merged.problem = (f"базы ответили, но по {advisory_id or package} "
                          f"нет ни текста, ни ссылки на фикс "
                          f"(опрошены: {', '.join(tried) or 'нет'})")
    return merged
