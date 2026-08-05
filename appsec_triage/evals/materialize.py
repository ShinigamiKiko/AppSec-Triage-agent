"""Materialize a labelled corpus into a source tree the pipeline can read.

The bench used to hand the pipeline bare snippets: no file on disk, nothing
for the source resolver to widen, nothing for a language server to index.
That silently benched a *different* pipeline than the one deployed — the live
procim run closed the ORM-interpolation CWE-89 that the bench got wrong,
purely because the live run had phpactor and the bench did not.

Writing every snippet to a real file closes that gap. Two adjustments make
the tree worth indexing:

* PHP fragments get a `<?php` opener when they lack one — phpactor parses
  nothing in a file that opens with a bare `$id = $_GET['id'];`.
* The flagged line is anchored on the sink. Corpus entries say `line: 1`
  because a snippet has no meaningful absolute line, but a real scanner flags
  the sink, and the language server resolves identifiers *on the flagged
  line* — pointed at line 1 it would resolve the source assignment instead
  of the interpolated values that decide the verdict.

Everything else is left alone: the snippet text is written verbatim, so
grounding checks compare against exactly what the corpus author wrote.
"""

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
    """0-based line of the snippet a scanner would actually flag.

    The sink wins when it can be located: `$pdo->query($sql)` is searched
    verbatim, then as its call prefix (`system()` -> `system(`) because corpus
    authors write the sink without arguments. When nothing matches, the
    declared line is honoured, and line 1 is the final fallback.
    """
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
    """Write each snippet under `root`, return findings re-pointed at the tree.

    Findings sharing a file path are appended to one file (a blank line
    apart); a byte-identical snippet seen twice — two scanners, one weakness —
    lands once and both findings point at the same region, so corroboration
    keeps meaning "same place" after materialization.
    """
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
