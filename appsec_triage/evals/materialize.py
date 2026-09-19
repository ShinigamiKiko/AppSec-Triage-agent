"""Materialize a labelled corpus into a source tree the pipeline can read."""

from __future__ import annotations

from pathlib import Path

from ..models import Finding

_PHP_OPENER = "<?php"


def _safe_relpath(file_path: str) -> Path:
    """Corpus paths become paths we write to — treat them as untrusted."""
    rel = Path(file_path.replace("\\", "/"))
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError(
            f"corpus file path {file_path!r} is absolute or escapes the tree — "
            "reference a real checkout with --source-root instead of materializing"
        )
    return rel


def _flag_offset(snippet_lines: list[str], declared_line: int | None, sink: str | None) -> int:
    """0-based line of the snippet a scanner would actually flag."""
    if sink:
        needles = [sink]
        if "(" in sink:
            needles.append(sink[: sink.index("(") + 1])
        for needle in needles:
            for i, line in enumerate(snippet_lines):
                if needle in line:
                    return i
    if declared_line and 1 <= declared_line <= len(snippet_lines):
        return declared_line - 1
    return 0


def materialize(findings: list[Finding], root: Path) -> list[Finding]:
    """Write each snippet under `root`, return findings re-pointed at the tree."""
    root = Path(root).resolve()
    root.mkdir(parents=True, exist_ok=True)

    contents: dict[Path, list[str]] = {}
    placed_at: dict[tuple[Path, str], int] = {}
    out: list[Finding] = []

    for finding in findings:
        ctx = finding.code_context
        snippet = ctx.snippet
        full = root / _safe_relpath(ctx.file_path)
        if not snippet:
            out.append(finding)
            continue

        base = placed_at.get((full, snippet))
        snippet_lines = snippet.splitlines() or [snippet]
        if base is None:
            lines = contents.get(full)
            if lines is None:
                lines = []
                if full.suffix.lower() == ".php" and _PHP_OPENER not in snippet:
                    lines += [_PHP_OPENER, ""]
                contents[full] = lines
            else:
                lines.append("")
            base = len(lines) + 1
            lines.extend(snippet_lines)
            placed_at[(full, snippet)] = base

        start = base + _flag_offset(snippet_lines, ctx.start_line, finding.sink)
        end = base + len(snippet_lines) - 1
        out.append(
            finding.model_copy(
                update={
                    "code_context": ctx.model_copy(
                        update={"start_line": start, "end_line": max(end, start)}
                    )
                }
            )
        )

    for full, lines in contents.items():
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out
