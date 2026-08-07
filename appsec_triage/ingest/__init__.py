"""Input adapters. Format is detected from the file, not from a CLI flag."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Iterator

from ..models import Finding
from . import bandit, govulncheck, native, sarif

log = logging.getLogger(__name__)


class IngestError(RuntimeError):
    pass


def detect_format(path: Path) -> str:
    if path.suffix.lower() in (".jsonl", ".ndjson"):
        return "native"
    text = path.read_text(encoding="utf-8")
    try:
        head = json.loads(text)
    except json.JSONDecodeError as exc:
        if govulncheck.looks_like_govulncheck(text):
            return "govulncheck"
        raise IngestError(f"{path}: not valid JSON ({exc})") from exc
    if isinstance(head, dict) and isinstance(head.get("runs"), list):
        return "sarif"
    if bandit.looks_like_bandit(head):
        return "bandit"
    return "native"


_PARSERS = {
    "sarif": sarif.parse,
    "bandit": bandit.parse,
    "govulncheck": govulncheck.parse,
    "native": native.parse,
}


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
    """Which duplicate to keep. A finding carrying a dataflow trace wins.

    This is what "the deep tool leads, the pattern matcher supports" means in
    practice: when CodeQL and Semgrep both flag a line, the record that survives
    is the one with `codeFlows`, because the trace is the thing the model cannot
    reconstruct on its own and the whole verdict on a dataflow class hangs on it.
    """
    return (
        len(f.trace),
        bool(f.source),
        bool(f.sink),
        len(f.sanitizers),
        f.scanner.lower() == "govulncheck",
        len(f.code_context.snippet or ""),
    )


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
    dependency_components: dict[tuple[str, str | None], list[tuple[set[str], list[Finding]]]] = {}
    for f in exact.values():
        if f.dependency is not None:
            dependency_key = (f.dependency.package, f.dependency.installed_version)
            identifiers = {
                str(value).upper()
                for value in (f.rule_id, *f.dependency.advisory_aliases)
                if value
            }
            components = dependency_components.setdefault(dependency_key, [])
            matching = [index for index, (known, _) in enumerate(components) if known & identifiers]
            if not matching:
                components.append((identifiers, [f]))
                continue
            first = matching[0]
            components[first][0].update(identifiers)
            components[first][1].append(f)
            for index in reversed(matching[1:]):
                components[first][0].update(components[index][0])
                components[first][1].extend(components[index][1])
                components.pop(index)
            continue
        else:
            cwe_key = "secret-family" if _is_secret_family(f.cwe) else f.cwe
            group_key = (cwe_key, f.code_context.file_path, f.code_context.start_line)
        groups.setdefault(group_key, []).append(f)

    for dependency_key, components in dependency_components.items():
        for index, (_, members) in enumerate(components):
            groups[("dependency", *dependency_key, index)] = members

    merged: list[Finding] = []
    for members in groups.values():
        primary = max(members, key=_richness)
        others = sorted({m.scanner for m in members} - {primary.scanner})
        updates = {}
        if primary.dependency is not None:
            dependencies = [m.dependency for m in members if m.dependency is not None]
            updates["dependency"] = primary.dependency.model_copy(
                update={
                    "fixed_versions": sorted({v for dep in dependencies for v in dep.fixed_versions}),
                    "advisory_aliases": sorted(
                        {
                            value
                            for member in members
                            for value in (
                                member.rule_id,
                                *(member.dependency.advisory_aliases if member.dependency else []),
                            )
                            if value and value != primary.rule_id
                        }
                    ),
                }
            )
            updates["cwe"] = primary.cwe or next((m.cwe for m in members if m.cwe), None)
        if others:
            updates["corroborated_by"] = others
        merged.append(primary.model_copy(update=updates) if updates else primary)

        for m in members:
            if (
                primary.dependency is None
                and m is not primary
                and m.scanner == primary.scanner
                and m.rule_id != primary.rule_id
                and not _is_secret_family(m.cwe)
            ):
                merged.append(m)
    return merged


__all__ = ["load", "detect_format", "IngestError", "sarif", "bandit", "govulncheck", "native"]
