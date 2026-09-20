"""Govulncheck JSON protocol adapter."""

from __future__ import annotations

import json
from collections import defaultdict
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from ..models import CodeContext, DependencyInfo, Finding, Severity, TraceStep


def decode_stream(text: str) -> list[dict[str, Any]]:
    """Decode govulncheck's concatenated JSON objects."""
    decoder = json.JSONDecoder()
    objects: list[dict[str, Any]] = []
    offset = 0
    while offset < len(text):
        while offset < len(text) and text[offset].isspace():
            offset += 1
        if offset >= len(text):
            break
        value, offset = decoder.raw_decode(text, offset)
        if isinstance(value, dict):
            objects.append(value)
    return objects


def _cwe(advisory: dict[str, Any]) -> str | None:
    candidates = list((advisory.get("database_specific") or {}).get("cwe_ids") or [])
    for affected in advisory.get("affected") or []:
        candidates.extend((affected.get("database_specific") or {}).get("cwe_ids") or [])
    for value in candidates:
        digits = "".join(ch for ch in str(value) if ch.isdigit())
        if digits:
            return f"CWE-{int(digits)}"
    return None


def _frame_path(frame: dict[str, Any], root_module: str) -> str:
    position = frame.get("position") or {}
    filename = str(position.get("filename") or "")
    module = str(frame.get("module") or "")
    version = str(frame.get("version") or "")
    if module in ("", root_module):
        return filename or "go.mod"
    prefix = module + (f"@{version}" if version else "")
    return f"{prefix}/{filename}" if filename else prefix


def _frame_symbol(frame: dict[str, Any]) -> str:
    package = str(frame.get("package") or frame.get("module") or "")
    receiver = str(frame.get("receiver") or "")
    function = str(frame.get("function") or "")
    symbol = f"{receiver}.{function}" if receiver and function else function
    return f"{package}.{symbol}" if package and symbol else package or symbol


def parse(path: Path) -> Iterator[Finding]:
    objects = decode_stream(Path(path).read_text(encoding="utf-8"))
    advisories = {str(obj["osv"].get("id")): obj["osv"] for obj in objects if isinstance(obj.get("osv"), dict)}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    module_versions: dict[str, str] = {}
    root_module = ""

    for obj in objects:
        sbom = obj.get("SBOM")
        if isinstance(sbom, dict):
            modules = sbom.get("modules") or []
            if modules:
                root_module = str(modules[0].get("path") or "")
            module_versions.update(
                {
                    str(module.get("path")): str(module.get("version") or "")
                    for module in modules
                    if module.get("path")
                }
            )
        finding = obj.get("finding")
        if isinstance(finding, dict) and finding.get("osv"):
            grouped[str(finding["osv"])].append(finding)

    for advisory_id, occurrences in grouped.items():
        advisory = advisories.get(advisory_id, {})
        traces = [list(item.get("trace") or []) for item in occurrences]
        richest = max(traces, key=lambda trace: (sum(bool(frame.get("function")) for frame in trace), len(trace)))
        vulnerable = richest[0] if richest else {}
        package = str(vulnerable.get("module") or "")
        installed = str(vulnerable.get("version") or module_versions.get(package) or "")
        fixed = sorted({str(item.get("fixed_version")) for item in occurrences if item.get("fixed_version")})
        reachable = len(richest) > 1 and bool(vulnerable.get("function"))

        trace: list[TraceStep] = []
        if reachable:
            reversed_trace = list(reversed(richest))
            for index, frame in enumerate(reversed_trace):
                role = "source" if index == 0 else "sink" if index == len(reversed_trace) - 1 else "step"
                trace.append(
                    TraceStep(
                        file_path=_frame_path(frame, root_module),
                        line=(frame.get("position") or {}).get("line"),
                        message=_frame_symbol(frame),
                        role=role,
                    )
                )

        app_frame = next(
            (frame for frame in reversed(richest) if str(frame.get("module") or "") == root_module),
            None,
        )
        location = _frame_path(app_frame, root_module) if app_frame else "go.mod"
        line = (app_frame.get("position") or {}).get("line") if app_frame else 1
        applicability = (
            "Govulncheck found a source-level call path to a vulnerable symbol."
            if reachable
            else "Govulncheck found the affected module/package, but no vulnerable symbol is called."
        )

        yield Finding(
            finding_id=f"govulncheck:{advisory_id}:{package or 'stdlib'}",
            scanner="govulncheck",
            rule_id=advisory_id,
            cwe=_cwe(advisory),
            title=str(advisory.get("summary") or advisory_id),
            description="\n\n".join(
                part for part in (str(advisory.get("details") or "").strip(), applicability) if part
            ),
            severity=Severity.high if reachable else Severity.medium,
            code_context=CodeContext(
                file_path=location,
                start_line=line,
                language="go",
            ),
            trace=trace,
            source=(trace[0].message if trace else None),
            sink=(trace[-1].message if trace else None),
            dependency=DependencyInfo(
                package=package or "stdlib",
                ecosystem="go",
                installed_version=installed or None,
                fixed_versions=fixed,
                advisory_aliases=[str(value) for value in advisory.get("aliases") or []],
                advisory_url=f"https://pkg.go.dev/vuln/{advisory_id}",
                imported=True,
            ),
            raw={
                "advisory": advisory,
                "findings": occurrences,
            },
        )
