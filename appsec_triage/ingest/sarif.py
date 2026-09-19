"""SARIF 2.1.0 adapter — covers CodeQL, Psalm, Wolfee, and Checkmarx exports."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import CodeContext, Finding, Severity, TraceStep
from . import dependency as dependency_parser

_LEVEL_TO_SEVERITY = {
    "error": Severity.high,
    "warning": Severity.medium,
    "note": Severity.low,
    "none": Severity.info,
}

_TAG_TO_SEVERITY = {
    "critical": Severity.critical,
    "high": Severity.high,
    "medium": Severity.medium,
    "moderate": Severity.medium,
    "low": Severity.low,
    "info": Severity.info,
}

_SOURCE_HINTS = ("source", "user input", "untrusted", "taint source")
_SINK_HINTS = ("sink", "dangerous", "executes", "query")
_SANITIZER_HINTS = ("sanitiz", "escape", "encode", "validat")

_PSALM_TAINT_TO_CWE = {
    "TaintedSql": "CWE-89",
    "TaintedTextWithQuotes": "CWE-89",
    "TaintedHtml": "CWE-79",
    "TaintedShell": "CWE-78",
    "TaintedInclude": "CWE-98",
    "TaintedEval": "CWE-95",
    "TaintedUnserialize": "CWE-502",
    "TaintedSSRF": "CWE-918",
    "TaintedLdap": "CWE-90",
    "TaintedFile": "CWE-22",
    "TaintedHeader": "CWE-113",
    "TaintedXpath": "CWE-643",
    "TaintedCallable": "CWE-95",
    "TaintedSystemSecret": "CWE-200",
    "TaintedCookie": "CWE-79",
}


def _is_misconfiguration(rule: dict[str, Any], result: dict[str, Any]) -> bool:
    """A parsed configuration fact, not a weakness to be traced."""
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    tags = [str(t).lower() for t in props.get("tags", [])]
    return "misconfiguration" in tags and str(props.get("precision", "")).lower() == "very-high"


def _uri(loc: dict[str, Any]) -> str:
    art = (loc.get("physicalLocation") or {}).get("artifactLocation") or {}
    return art.get("uri") or art.get("uriBaseId") or "<unknown>"


def _region(loc: dict[str, Any]) -> dict[str, Any]:
    return (loc.get("physicalLocation") or {}).get("region") or {}


def _snippet(loc: dict[str, Any]) -> tuple[str | None, bool]:
    region = _region(loc)
    text = (region.get("snippet") or {}).get("text")
    ctx = ((loc.get("physicalLocation") or {}).get("contextRegion") or {}).get("snippet", {}).get("text")
    chosen = ctx or text
    return chosen, bool(region.get("endLine") and not chosen)


def _flow_role(loc: dict[str, Any]) -> str | None:
    """Read CodeQL's explicit dataflow role when the message is generic."""
    for kind in loc.get("kinds") or []:
        role = str(kind).lower()
        if role in {"source", "entrypoint"}:
            return "source"
        if role in {"sink", "vulnerable-function"}:
            return "sink"
        if role in {"sanitizer", "step", "call"}:
            return "sanitizer" if role == "sanitizer" else "step"
    for taxa in loc.get("taxa") or []:
        role = ((taxa.get("properties") or {}).get("CodeQL/DataflowRole") or "").lower()
        if role in {"source", "sink", "sanitizer", "step"}:
            return role
    return None


def _cwe_from_rule(rule: dict[str, Any], result: dict[str, Any]) -> str | None:
    name = rule.get("name") or (rule.get("shortDescription") or {}).get("text") or ""
    if cwe := _PSALM_TAINT_TO_CWE.get(name):
        return cwe

    candidates: list[str] = []
    props = rule.get("properties") or {}
    candidates += [str(t) for t in props.get("tags", [])]
    candidates += [str(t) for t in (result.get("properties") or {}).get("tags", [])]
    for rel in rule.get("relationships") or []:
        target = (rel.get("target") or {}).get("id")
        if target:
            candidates.append(str(target))
    if cwe_prop := props.get("cwe"):
        candidates += [str(cwe_prop)] if isinstance(cwe_prop, str) else [str(c) for c in cwe_prop]
    for cand in candidates:
        if "cwe" in cand.lower():
            digits = "".join(ch for ch in cand if ch.isdigit())
            if digits:
                return f"CWE-{int(digits)}"
    return None


def _severity(rule: dict[str, Any], result: dict[str, Any]) -> Severity:
    tags = [str(t).lower() for t in (rule.get("properties") or {}).get("tags", [])]
    props = {**(rule.get("properties") or {}), **(result.get("properties") or {})}
    for key in ("security-severity", "problem.severity", "severity", "impact"):
        val = str(props.get(key, "")).lower()
        if val in _TAG_TO_SEVERITY:
            return _TAG_TO_SEVERITY[val]
        if key == "security-severity" and val:
            try:
                score = float(val)
            except ValueError:
                pass
            else:
                return Severity.critical if score >= 9 else Severity.high if score >= 7 else Severity.medium
    for tag in tags:
        if tag in _TAG_TO_SEVERITY:
            return _TAG_TO_SEVERITY[tag]

    level = str(result.get("level") or "").lower()
    if not level:
        level = str(((rule.get("defaultConfiguration") or {}).get("level")) or "").lower()
    return _LEVEL_TO_SEVERITY.get(level, Severity.unknown)


def _trace(result: dict[str, Any]) -> tuple[list[TraceStep], str | None, str | None, list[str]]:
    steps: list[TraceStep] = []
    for flow in result.get("codeFlows") or []:
        for thread in flow.get("threadFlows") or []:
            for loc in thread.get("locations") or []:
                inner = loc.get("location") or {}
                msg = (inner.get("message") or {}).get("text")
                lowered = (msg or "").lower()
                explicit_role = _flow_role(loc)
                role = explicit_role or "step"
                if explicit_role is None and any(h in lowered for h in _SOURCE_HINTS):
                    role = "source"
                elif explicit_role is None and any(h in lowered for h in _SANITIZER_HINTS):
                    role = "sanitizer"
                elif explicit_role is None and any(h in lowered for h in _SINK_HINTS):
                    role = "sink"
                steps.append(
                    TraceStep(
                        file_path=_uri(inner),
                        line=_region(inner).get("startLine"),
                        message=msg,
                        role=role,  # type: ignore[arg-type]
                    )
                )
    if steps and not any(s.role != "step" for s in steps):
        steps[0].role = "source"
        steps[-1].role = "sink"
        for middle in steps[1:-1]:
            middle.role = "step"

    source = next((s.message or f"{s.file_path}:{s.line}" for s in steps if s.role == "source"), None)
    sink = next((s.message or f"{s.file_path}:{s.line}" for s in reversed(steps) if s.role == "sink"), None)
    if steps and not source:
        source = steps[0].message or f"{steps[0].file_path}:{steps[0].line}"
    if steps and not sink:
        sink = steps[-1].message or f"{steps[-1].file_path}:{steps[-1].line}"
    sanitizers = [s.message or f"{s.file_path}:{s.line}" for s in steps if s.role == "sanitizer"]
    return steps, source, sink, sanitizers


def parse(path: Path) -> Iterator[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    for run_idx, run in enumerate(doc.get("runs") or []):
        tool = ((run.get("tool") or {}).get("driver") or {})
        scanner = tool.get("name") or "sarif"
        rules = {r.get("id"): r for r in (tool.get("rules") or []) if r.get("id")}

        for res_idx, result in enumerate(run.get("results") or []):
            rule_id = result.get("ruleId") or (result.get("rule") or {}).get("id")
            rule = rules.get(rule_id, {})
            locations = result.get("locations") or [{}]
            primary = locations[0]
            snippet, truncated = _snippet(primary)
            region = _region(primary)
            steps, source, sink, sanitizers = _trace(result)

            description = (result.get("message") or {}).get("text") or (
                (rule.get("fullDescription") or rule.get("shortDescription") or {}).get("text")
            )

            help_text = "\n".join(
                t
                for t in (
                    (rule.get("help") or {}).get("text"),
                    (rule.get("fullDescription") or {}).get("text"),
                    description,
                )
                if t
            )
            misconfiguration = _is_misconfiguration(rule, result)
            dependency = None
            if not misconfiguration and dependency_parser.looks_like_dependency(_uri(primary), rule_id, help_text):
                dependency = dependency_parser.parse(
                    help_text, {**(rule.get("properties") or {}), **(result.get("properties") or {})}
                )
            if dependency is not None and not description:
                description = help_text[:2000]

            yield Finding(
                finding_id=result.get("guid")
                or result.get("correlationGuid")
                or f"{scanner}:{run_idx}:{res_idx}:{rule_id or 'norule'}",
                scanner=scanner,
                rule_id=rule_id,
                cwe=_cwe_from_rule(rule, result),
                title=(rule.get("shortDescription") or {}).get("text") or rule_id,
                description=description,
                severity=_severity(rule, result),
                code_context=CodeContext(
                    file_path=_uri(primary),
                    start_line=region.get("startLine"),
                    end_line=region.get("endLine"),
                    snippet=snippet,
                    truncated=truncated,
                ),
                trace=steps,
                source=source,
                sink=sink,
                sanitizers=sanitizers,
                dependency=dependency,
                misconfiguration=misconfiguration,
                raw=result,
            )
