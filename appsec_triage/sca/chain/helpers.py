"""Small, stateless helpers used by the dependency-chain runner."""

from __future__ import annotations

from .. import advisories as adv
from ..bridge import BridgeResult, BridgeSymbol, BridgeWalk

_ID_PREFIXES = ("GHSA-", "CVE-", "GO-", "PYSEC-", "RUSTSEC-", "GMS-",
                "BIT-", "DRUPAL-", "MAL-", "OSV-", "RHSA-", "USN-")
_CODEQL_LANGUAGE = {
    "go": "go", "golang": "go", "npm": "javascript", "node": "javascript",
    "javascript": "javascript", "pypi": "python", "python": "python", "pip": "python",
}


def _call_site_position(call_site: str | None) -> tuple[str, int] | None:
    if not call_site or ":" not in call_site:
        return None
    file_path, raw_line = call_site.rsplit(":", 1)
    try:
        line = int(raw_line)
    except ValueError:
        return None
    return (file_path, line) if file_path and line > 0 else None


def _finding_call_site(finding, dependency) -> tuple[str, int] | None:
    position = _call_site_position(dependency.call_site)
    if position is not None:
        return position
    for step in reversed(finding.trace):
        if step.file_path and step.line and step.line > 0:
            return step.file_path, step.line
    return None


def _render_finding_trace(finding) -> str:
    if not finding.trace:
        return ""
    lines = ["Wolfee/govulncheck call trace:"]
    for step in finding.trace:
        position = f"{step.file_path}:{step.line}" if step.line else step.file_path
        detail = f" — {step.message}" if step.message else ""
        lines.append(f"- {position}{detail}")
    return "\n".join(lines)


def _needs_llm_advisory(advisory: adv.Advisory) -> bool:
    return not advisory.details.strip() and not advisory.symbols and not advisory.import_paths


def _pairs(symbols: list[BridgeSymbol], limit: int = 6) -> list[tuple[str, str]]:
    return [(s.function, s.klass) for s in symbols[:limit]]


def _flaw_of(advisory) -> str:
    """The advisory's own description of the flaw, trimmed to one paragraph."""
    summary = " ".join((getattr(advisory, "summary", "") or "").split())
    details = " ".join((getattr(advisory, "details", "") or "").split())
    if details.startswith(summary):
        details = details[len(summary):].lstrip(" .:—-")
    if len(details) > 420:
        cut = details.rfind(". ", 0, 420)
        details = details[:cut + 1] if cut > 200 else details[:420].rstrip() + "…"
    return ". ".join(part for part in (summary.rstrip("."), details) if part).strip()


def _walk_as_bridge(walk: BridgeWalk) -> BridgeResult:
    detail = walk.detail
    if walk.hops > 1:
        detail = f"{detail} [{walk.hops} шага, уверенность {walk.confidence}]"
    if walk.closed:
        return BridgeResult(calls_it=False, detail=detail)
    if walk.unknown or not walk.targets:
        return BridgeResult(calls_it=None, detail=detail)
    return BridgeResult(calls_it=True, symbols=list(walk.targets), detail=detail)
