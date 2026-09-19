"""Input adapters."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from ..models import Finding
from . import native, sarif

log = logging.getLogger(__name__)


class IngestError(RuntimeError):
    pass


def detect_format(path: Path) -> str:
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        return "native"
    try:
        head = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise IngestError(f"{path}: not valid JSON ({exc})") from exc
    if isinstance(head, dict) and isinstance(head.get("runs"), list):
        return "sarif"
    return "native"


_PARSERS = {"sarif": sarif.parse, "native": native.parse}


def load(path: Path) -> list[Finding]:
    """Load one file or every *.json/*.sarif/*.jsonl in a directory."""
    path = Path(path)
    if path.is_dir():
        files = sorted(
            p
            for p in path.rglob("*")
            if p.suffix.lower() in (".json", ".sarif", ".jsonl", ".ndjson")
            and not any(part.startswith(".") for part in p.relative_to(path).parts)
        )
        if not files:
            raise IngestError(f"{path}: no .json/.sarif/.jsonl files found")
        out: list[Finding] = []
        skipped: list[str] = []
        for f in files:
            if f.name == "scan-manifest.json":
                continue
            try:
                out.extend(load(f))
            except (IngestError, ValueError, KeyError) as exc:
                skipped.append(f"{f.name}: {exc}")
        for note in skipped:
            log.warning("ingest: skipped %s", note)
        if not out:
            raise IngestError(
                f"{path}: no findings parsed from {len(files)} file(s). Skipped: " + "; ".join(skipped[:5])
            )
        return _dedupe(out)
    if not path.is_file():
        raise IngestError(f"{path}: no such file or directory")

    fmt = detect_format(path)
    findings = list(_PARSERS[fmt](path))
    if not findings:
        log.info("%s: parsed as %s, zero findings", path, fmt)
    return _dedupe(findings)


def _richness(f: Finding) -> tuple:
    """Which duplicate to keep."""
    return (len(f.trace), bool(f.source), bool(f.sink), len(f.sanitizers), len(f.code_context.snippet or ""))


def _is_secret_family(cwe: str | None) -> bool:
    from ..context.heuristics import SECRET_FAMILY_CWES

    return bool(cwe) and cwe.upper() in SECRET_FAMILY_CWES


def _dedupe(findings: list[Finding]) -> list[Finding]:
    """Two decisions collapse into one, and the agreement is kept as evidence."""
    exact: dict[tuple, Finding] = {}
    for f in findings:
        key = (
            f.scanner, f.cwe, f.rule_id, f.code_context.file_path,
            f.code_context.start_line, (f.code_context.snippet or "")[:200],
        )
        if key not in exact or _richness(f) > _richness(exact[key]):
            exact[key] = f

    groups: dict[tuple, list[Finding]] = {}
    for f in exact.values():
        cwe_key = "secret-family" if _is_secret_family(f.cwe) else f.cwe
        groups.setdefault((cwe_key, f.code_context.file_path, f.code_context.start_line), []).append(f)

    merged: list[Finding] = []
    for members in groups.values():
        primary = max(members, key=_richness)
        others = sorted({m.scanner for m in members} - {primary.scanner})
        merged.append(primary.model_copy(update={"corroborated_by": others}) if others else primary)

        for m in members:
            if (
                m is not primary
                and m.scanner == primary.scanner
                and m.rule_id != primary.rule_id
                and not _is_secret_family(m.cwe)
            ):
                merged.append(m)
    return merged


__all__ = ["IngestError", "detect_format", "load", "native", "sarif"]
