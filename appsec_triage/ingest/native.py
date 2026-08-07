"""Native adapter: our own normalized JSON / JSONL.

This is the escape hatch for scanners without decent SARIF. Field names are
aliased generously because every internal export names them differently, but
the *shape* is fixed: one object per finding, a file path, and a snippet.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from ..models import CodeContext, DependencyInfo, Finding, Severity, TraceStep

_ALIASES = {
    "finding_id": ("finding_id", "id", "uuid", "key", "issue_id"),
    "scanner": ("scanner", "tool", "source_tool", "analyzer"),
    "rule_id": ("rule_id", "rule", "check_id", "query_id", "ruleId"),
    "cwe": ("cwe", "cwe_id", "cweId", "vulnerability_class"),
    "title": ("title", "name", "summary", "short_description"),
    "description": ("description", "message", "detail", "full_description"),
    "severity": ("severity", "level", "risk", "priority"),
    "file_path": ("file_path", "path", "file", "filename", "location", "uri"),
    "start_line": ("start_line", "line", "line_number", "startLine"),
    "end_line": ("end_line", "endLine", "line_end"),
    "snippet": ("snippet", "code", "code_context", "excerpt", "fragment"),
    "language": ("language", "lang"),
    "source": ("source", "taint_source", "entry_point"),
    "sink": ("sink", "taint_sink", "dangerous_call"),
    "sanitizers": ("sanitizers", "sanitizer", "mitigations"),
    "trace": ("trace", "dataflow", "path", "flow", "steps"),
}


def _pick(obj: dict[str, Any], field: str) -> Any:
    for key in _ALIASES[field]:
        if key in obj and obj[key] not in (None, ""):
            return obj[key]
    return None


def _severity(value: Any) -> Severity:
    if value is None:
        return Severity.unknown
    text = str(value).strip().lower()
    mapping = {
        "critical": Severity.critical, "crit": Severity.critical, "blocker": Severity.critical,
        "high": Severity.high, "error": Severity.high, "major": Severity.high,
        "medium": Severity.medium, "warning": Severity.medium, "moderate": Severity.medium,
        "low": Severity.low, "note": Severity.low, "minor": Severity.low,
        "info": Severity.info, "informational": Severity.info, "none": Severity.info,
    }
    return mapping.get(text, Severity.unknown)


def _normalize_cwe(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        value = value[0] if value else None
    if value is None:
        return None
    digits = "".join(ch for ch in str(value) if ch.isdigit())
    return f"CWE-{int(digits)}" if digits else None


def _trace(value: Any) -> list[TraceStep]:
    if not isinstance(value, list):
        return []
    steps: list[TraceStep] = []
    for item in value:
        if isinstance(item, str):
            steps.append(TraceStep(file_path=item))
        elif isinstance(item, dict):
            role = str(item.get("role", "step")).lower()
            steps.append(
                TraceStep(
                    file_path=str(_pick(item, "file_path") or item.get("file") or "<unknown>"),
                    line=item.get("line") or item.get("start_line"),
                    message=item.get("message") or item.get("description"),
                    role=role if role in ("source", "sink", "sanitizer", "step") else "step",  # type: ignore[arg-type]
                )
            )
    return steps


def _to_finding(obj: dict[str, Any], fallback_id: str) -> Finding:
    sanitizers = _pick(obj, "sanitizers")
    if isinstance(sanitizers, str):
        sanitizers = [sanitizers]

    # The agent's own output nests the location and carries the package. Not
    # reading it meant `sbom` wrote a file that `triage` refused to open, and
    # any dependency loaded through this parser silently lost its package and
    # version — the two things the SCA chain runs on.
    nested = obj.get("code_context")
    if isinstance(nested, dict):
        obj = {**nested, **{k: v for k, v in obj.items() if k != "code_context"}}

    file_path = _pick(obj, "file_path")
    if file_path is None:
        raise ValueError(f"finding {fallback_id}: no file path field (tried {_ALIASES['file_path']})")

    dependency = None
    raw_dependency = obj.get("dependency")
    if isinstance(raw_dependency, dict) and raw_dependency.get("package"):
        dependency = DependencyInfo(
            package=str(raw_dependency["package"]),
            ecosystem=(str(v) if (v := raw_dependency.get("ecosystem")) else None),
            installed_version=(str(v) if (v := raw_dependency.get("installed_version")) else None),
            fixed_versions=[str(x) for x in (raw_dependency.get("fixed_versions") or [])],
            advisory_aliases=[str(x) for x in (raw_dependency.get("advisory_aliases") or [])],
            advisory_url=(str(v) if (v := raw_dependency.get("advisory_url")) else None),
            dev_only=raw_dependency.get("dev_only"),
            imported=raw_dependency.get("imported"),
        )

    return Finding(
        finding_id=str(_pick(obj, "finding_id") or fallback_id),
        scanner=str(_pick(obj, "scanner") or "native"),
        rule_id=(str(v) if (v := _pick(obj, "rule_id")) else None),
        cwe=_normalize_cwe(_pick(obj, "cwe")),
        title=(str(v) if (v := _pick(obj, "title")) else None),
        description=(str(v) if (v := _pick(obj, "description")) else None),
        severity=_severity(_pick(obj, "severity")),
        code_context=CodeContext(
            file_path=str(file_path),
            start_line=_pick(obj, "start_line"),
            end_line=_pick(obj, "end_line"),
            snippet=(str(v) if (v := _pick(obj, "snippet")) else None),
            language=(str(v) if (v := _pick(obj, "language")) else None),
            truncated=bool(obj.get("truncated", False)),
        ),
        trace=_trace(_pick(obj, "trace")),
        source=(str(v) if (v := _pick(obj, "source")) else None),
        sink=(str(v) if (v := _pick(obj, "sink")) else None),
        sanitizers=[str(s) for s in (sanitizers or [])],
        dependency=dependency,
        raw=obj,
    )


def parse(path: Path) -> Iterator[Finding]:
    path = Path(path)
    text = path.read_text(encoding="utf-8")

    if path.suffix.lower() in (".jsonl", ".ndjson"):
        for i, line in enumerate(text.splitlines()):
            if line.strip():
                yield _to_finding(json.loads(line), f"{path.stem}:{i}")
        return

    doc = json.loads(text)
    if isinstance(doc, dict):
        for key in ("findings", "results", "issues", "vulnerabilities", "items", "data"):
            if isinstance(doc.get(key), list):
                doc = doc[key]
                break
        else:
            doc = [doc]
    for i, obj in enumerate(doc):
        yield _to_finding(obj, f"{path.stem}:{i}")
