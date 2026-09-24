"""Where the vulnerability was described and where it was fixed, looked up live."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
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
    fixed_versions: list[str] = field(default_factory=list)
    symbols: list[str] = field(default_factory=list)
    import_paths: list[str] = field(default_factory=list)
    named_symbols: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    severity: str = ""
    # critical / high / medium / low, from the database's own label or the CVSS score.
    severity_level: str = ""
    problem: str = ""
    affected: list[dict] = field(default_factory=list)

    @property
    def text(self) -> str:
        return f"{self.summary}\n\n{self.details}".strip()

    @property
    def usable(self) -> bool:
        return bool(self.text or self.fix_refs or self.symbols or self.import_paths)


class DatabaseUnavailable(Exception):
    """A database did not answer."""


def _get_json(url: str, body: bytes | None = None, headers: dict | None = None):
    """Parsed JSON, or `DatabaseUnavailable`."""
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


_LABELS = {"critical": "critical", "high": "high", "moderate": "medium", "medium": "medium",
           "low": "low", "none": "low"}

_CVSS3_WEIGHTS = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(value: float) -> float:
    scaled = round(value * 100000)
    return scaled / 100000.0 if scaled % 10000 == 0 else (scaled // 10000 + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Base score of a CVSS 3.x vector, per the FIRST specification."""
    if not vector.startswith("CVSS:3"):
        return None
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62, "H": 0.5 if scope_changed else 0.27}[metrics["PR"]]
        w = {k: _CVSS3_WEIGHTS[k][metrics[k]] for k in _CVSS3_WEIGHTS}
    except (KeyError, ValueError):
        return None
    iss = 1 - (1 - w["C"]) * (1 - w["I"]) * (1 - w["A"])
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    exploitability = 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
    if impact <= 0:
        return 0.0
    raw = impact + exploitability
    return _roundup(min(1.08 * raw, 10) if scope_changed else min(raw, 10))


def level_from_score(score: float | None) -> str:
    if score is None:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _severity_level_of(entry: dict) -> str:
    """critical/high/medium/low: the database's own label first, then the CVSS 3 score."""
    labels = [(entry.get("database_specific") or {}).get("severity")]
    labels += [(a.get("database_specific") or {}).get("severity") for a in entry.get("affected") or []]
    for label in labels:
        if isinstance(label, str) and label.strip().lower() in _LABELS:
            return _LABELS[label.strip().lower()]
    return level_from_score(cvss3_base_score(_severity_of(entry)))


def _refs(entry: dict) -> list[tuple[str, str]]:
    """Every reference as (url, declared type), the type upper-cased or empty."""
    out = []
    for ref in entry.get("references") or []:
        url = str(ref.get("url") or "")
        if url:
            out.append((url, str(ref.get("type") or "").upper()))
    return out


def _rank_refs(refs: list[tuple[str, str]]) -> list[str]:
    """Fetchable fix links, best first."""
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
    """Find fetchable fix references in GitHub's public advisory record."""
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
_NOT_A_FUNCTION = {
    "true", "false", "null", "undefined", "options", "option", "variable",
    "constructor", "prototype", "__proto__", "name", "value", "type", "default",
}
_BUILTIN_TYPES = {
    "Object", "Array", "String", "Number", "Boolean", "Function", "JSON",
    "Map", "Set", "Date", "RegExp", "Promise", "Buffer", "Error", "Symbol",
}


def _named_in_prose(text: str, package: str) -> list[str]:
    """Function names the description states outright, in backticks."""
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
    """Vulnerable import paths the database names, symbols or not."""
    out: list[str] = []
    for affected in entry.get("affected") or []:
        for item in (affected.get("ecosystem_specific") or {}).get("imports") or []:
            path = str(item.get("path") or "").strip()
            if path and path not in out:
                out.append(path)
    return out


def _symbols_of(entry: dict) -> list[str]:
    """Vulnerable symbols the database states outright, fully qualified."""
    out: list[str] = []
    for affected in entry.get("affected") or []:
        for item in (affected.get("ecosystem_specific") or {}).get("imports") or []:
            path = str(item.get("path") or "").strip()
            for symbol in item.get("symbols") or []:
                name = f"{path}.{symbol}" if path else str(symbol)
                if name not in out:
                    out.append(name)
    return out


def _affected_of(entry: dict) -> list[dict]:
    """Per-package ranges and explicit versions, as OSV states them."""
    out: list[dict] = []
    for affected in entry.get("affected") or []:
        package = (affected.get("package") or {})
        out.append({
            "package": str(package.get("name") or ""),
            "ecosystem": str(package.get("ecosystem") or ""),
            "ranges": [{"type": str(r.get("type") or ""), "events": list(r.get("events") or [])}
                       for r in affected.get("ranges") or []],
            "versions": [str(v) for v in affected.get("versions") or []],
        })
    return out


def _fixed_versions_of(entry: dict) -> list[str]:
    """Versions marked fixed by OSV's affected-range events."""
    out: list[str] = []
    for affected in entry.get("affected") or []:
        for item in affected.get("ranges") or []:
            for event in item.get("events") or []:
                fixed = str(event.get("fixed") or "").strip()
                if fixed and fixed not in out:
                    out.append(fixed)
    return out


_OSV_MEMO: dict[tuple[str, str, str], list[dict]] = {}
_OSV_MEMO_LOCK = threading.Lock()


def from_osv(package: str, ecosystem: str, version: str) -> list[Advisory]:
    """Every advisory affecting this exact version.

    Memoised per (package, ecosystem, version) for the run: nineteen advisories
    of one package used to be nineteen identical queries.
    """
    key = (package, (ecosystem or "").lower(), version)
    with _OSV_MEMO_LOCK:
        cached = _OSV_MEMO.get(key)
    if cached is not None:
        out = [_advisory_from_osv(vuln, package, ecosystem) for vuln in cached]
        out.sort(key=lambda a: not a.symbols)
        return out
    osv_name = osv_ecosystem(ecosystem)
    if not (package and osv_name and version):
        return []
    payload = json.dumps({"package": {"name": package, "ecosystem": osv_name},
                          "version": version}).encode()
    data = _get_json("https://api.osv.dev/v1/query", payload,
                     {"Content-Type": "application/json"})
    if not data:
        return []
    vulns = list(data.get("vulns") or [])
    with _OSV_MEMO_LOCK:
        _OSV_MEMO[key] = vulns
    out = [_advisory_from_osv(vuln, package, ecosystem) for vuln in vulns]
    out.sort(key=lambda a: not a.symbols)
    return out


def _advisory_from_osv(vuln: dict, package: str, ecosystem: str) -> Advisory:
    return Advisory(
        advisory_id=vuln.get("id", ""), package=package, ecosystem=ecosystem,
        summary=(vuln.get("summary") or "")[:300],
        details=(vuln.get("details") or "")[:8000],
        aliases=list(vuln.get("aliases") or []),
        fix_refs=_rank_refs(_refs(vuln)), symbols=_symbols_of(vuln),
        fixed_versions=_fixed_versions_of(vuln), affected=_affected_of(vuln),
        import_paths=_import_paths_of(vuln), cwe_ids=_cwes_of(vuln),
        sources=["osv"], severity=_severity_of(vuln),
        severity_level=_severity_level_of(vuln),
    )


_BATCH = 1000


def from_osv_batch(items: list[tuple[str, str, str]], *, workers: int = 8
                   ) -> dict[tuple[str, str, str], list[Advisory] | DatabaseUnavailable]:
    """Advisories for many (package, ecosystem, version) at once.

    `/v1/querybatch` answers up to a thousand packages per request with the ids
    only; the full records are then fetched once per id, in parallel. 890
    packages used to be 890 sequential requests — about seven minutes.
    A package whose batch answer is paged or missing is asked on its own.
    """
    from concurrent.futures import ThreadPoolExecutor

    results: dict[tuple[str, str, str], list[Advisory] | DatabaseUnavailable] = {}
    queries: list[tuple[tuple[str, str, str], dict]] = []
    for package, ecosystem, version in items:
        osv_name = osv_ecosystem(ecosystem)
        if not (package and osv_name and version):
            results[(package, ecosystem, version)] = []
            continue
        queries.append(((package, ecosystem, version),
                        {"package": {"name": package, "ecosystem": osv_name}, "version": version}))

    ids_for: dict[tuple[str, str, str], list[str]] = {}
    single: list[tuple[str, str, str]] = []
    for start in range(0, len(queries), _BATCH):
        chunk = queries[start:start + _BATCH]
        payload = json.dumps({"queries": [q for _, q in chunk]}).encode()
        data = _get_json("https://api.osv.dev/v1/querybatch", payload,
                         {"Content-Type": "application/json"})
        answers = (data or {}).get("results") or []
        if len(answers) != len(chunk):
            single.extend(key for key, _ in chunk)
            continue
        for (key, _), answer in zip(chunk, answers):
            if (answer or {}).get("next_page_token"):
                single.append(key)
                continue
            ids_for[key] = [v.get("id", "") for v in (answer or {}).get("vulns") or [] if v.get("id")]

    wanted = sorted({vid for ids in ids_for.values() for vid in ids})
    records: dict[str, dict | DatabaseUnavailable] = {}

    def fetch(vid: str):
        try:
            return vid, _get_json(f"https://api.osv.dev/v1/vulns/{vid}")
        except DatabaseUnavailable as exc:
            return vid, exc

    def ask_alone(key: tuple[str, str, str]):
        try:
            return key, from_osv(*key)
        except DatabaseUnavailable as exc:
            return key, exc

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        for vid, record in pool.map(fetch, wanted):
            records[vid] = record
        for key, answer in pool.map(ask_alone, single):
            results[key] = answer

    for key, ids in ids_for.items():
        package, ecosystem, _ = key
        failed = next((records[v] for v in ids if isinstance(records.get(v), DatabaseUnavailable)), None)
        if failed is not None:
            results[key] = failed
            continue
        vulns = [records[v] for v in ids if isinstance(records.get(v), dict)]
        with _OSV_MEMO_LOCK:
            _OSV_MEMO[(package, (ecosystem or "").lower(), key[2])] = vulns
        found = [_advisory_from_osv(v, package, ecosystem) for v in vulns]
        found.sort(key=lambda a: not a.symbols)
        results[key] = found
    return results


def from_ghsa(advisory_id: str) -> Advisory | None:
    """The maintainer's write-up, which usually names the symbol."""
    if not advisory_id.upper().startswith("GHSA-"):
        return None
    # OSV ids are case-sensitive: GHSA-4qpc-3hr4-r2p4 resolves, GHSA-4QPC-3HR4-R2P4 is a 404.
    advisory_id = "GHSA-" + advisory_id[5:].lower()
    data = _get_json(f"https://api.osv.dev/v1/vulns/{advisory_id}")
    if not data:
        return None
    return Advisory(
        advisory_id=data.get("id", advisory_id),
        summary=(data.get("summary") or "")[:300],
        details=(data.get("details") or "")[:8000],
        aliases=list(data.get("aliases") or []),
        fix_refs=_rank_refs(_refs(data)), symbols=_symbols_of(data),
        fixed_versions=_fixed_versions_of(data), affected=_affected_of(data),
        import_paths=_import_paths_of(data), cwe_ids=_cwes_of(data),
        sources=["ghsa"], severity=_severity_of(data),
        severity_level=_severity_level_of(data),
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
    """One advisory, merged from whichever databases answered."""
    merged = Advisory(advisory_id=advisory_id, package=package, ecosystem=ecosystem)
    tried: list[str] = []
    failures: list[str] = []

    wanted = advisory_id.strip().upper()
    candidates: list[Advisory] = []
    if package and version:
        try:
            found = from_osv(package, ecosystem, version)
        except DatabaseUnavailable as exc:
            found = []
            failures.append(f"osv: {exc}")
        tried.append("osv")
        if wanted:
            # Two advisories can list each other as aliases — an "incomplete fix"
            # follow-up and the original do. The record whose own id was asked for
            # is the one to read; an alias match is only the fallback.
            exact = [a for a in found if a.advisory_id.upper() == wanted]
            found = exact or [a for a in found if wanted in {x.upper() for x in a.aliases}]
        candidates.extend(found[:1] if wanted else found)

    # Look further only under this advisory's own ids. A GHSA alias may be a
    # different advisory, and its text would win the "longest text" merge below.
    own = [wanted] if wanted else []
    own += [a.advisory_id.upper() for a in candidates if a.advisory_id.upper() not in own]
    cves = [i for i in own if i.startswith("CVE-")]
    cves += sorted({x.upper() for a in candidates for x in a.aliases if x.upper().startswith("CVE-")} - set(cves))
    for ident in [i for i in own if i.startswith("GHSA-")]:
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
        for ident in cves:
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
        merged.severity_level = merged.severity_level or entry.severity_level
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
        for fixed in entry.fixed_versions:
            if fixed not in merged.fixed_versions:
                merged.fixed_versions.append(fixed)
        if not merged.affected and entry.affected:
            merged.affected = list(entry.affected)
        merged.sources.extend(s for s in entry.sources if s not in merged.sources)

    if ecosystem.lower() in {"npm", "node", "javascript", "yarn"} and not merged.fix_refs:
        # the fix of an aliased GHSA may be the fix of a different flaw
        for ident in [merged.advisory_id, *(a for a in merged.aliases if not a.upper().startswith("GHSA-"))]:
            for ref in _github_fix_refs(ident):
                if ref not in merged.fix_refs:
                    merged.fix_refs.append(ref)

    merged.named_symbols = _named_in_prose(merged.text, package or merged.package)

    if failures:
        merged.problem = "базы не ответили — " + "; ".join(failures)
    elif not merged.usable:
        merged.problem = (f"базы ответили, но по {advisory_id or package} "
                          f"нет ни текста, ни ссылки на фикс "
                          f"(опрошены: {', '.join(tried) or 'нет'})")
    if not merged.severity_level:
        merged.severity_level = level_from_score(cvss3_base_score(merged.severity))
    return merged
