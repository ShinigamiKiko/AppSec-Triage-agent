"""Remove inline comments, keeping docstrings and pragmas.

Done with the tokenizer rather than a regular expression: `#` appears inside
string literals all over this codebase — regexes in `presence.py`, URLs, prompt
text — and a textual pass would corrupt them silently.

Two kinds of comment stay. Pragmas (`# noqa`, `# type:`, `# pragma:`) are
instructions to other tools, not prose. Shebangs and encoding declarations are
part of the file's contract with the interpreter.

Docstrings are untouched: they are the description of what each module does,
which is what makes the project readable at all.
"""

from __future__ import annotations

import argparse
import io
import sys
import tokenize
from pathlib import Path

KEEP = ("# noqa", "# type:", "# pragma:", "# fmt:", "#!", "# -*-", "# isort:")


def _keep(text: str) -> bool:
    stripped = text.strip()
    return any(stripped.startswith(marker) for marker in KEEP)


def strip(source: str) -> str:
    """Return `source` without its prose comments.

    The tokenizer is used only to *locate* comments; the text is then edited in
    place. Rebuilding a file from its token stream loses indentation — the first
    attempt at that produced files where `return` had escaped its function — and
    nothing about this task needs the file rewritten, only shortened.
    """
    lines = source.splitlines(keepends=True)
    drop_lines: set[int] = set()
    cuts: dict[int, int] = {}

    for token in tokenize.generate_tokens(io.StringIO(source).readline):
        if token.type is not tokenize.COMMENT or _keep(token.string):
            continue
        line_no, column = token.start
        if not token.line[:column].strip():
            drop_lines.add(line_no)
        else:
            cuts[line_no] = min(column, cuts.get(line_no, column))

    out: list[str] = []
    for number, line in enumerate(lines, 1):
        if number in drop_lines:
            continue
        if number in cuts:
            kept = line[: cuts[number]].rstrip()
            out.append(kept + "\n" if kept else "")
            continue
        out.append(line)
    return "".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="+", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    files = [p for path in args.paths
             for p in (path.rglob("*.py") if path.is_dir() else [path])]
    changed = 0
    for path in sorted(files):
        source = path.read_text(encoding="utf-8")
        try:
            stripped = strip(source)
        except (tokenize.TokenError, IndentationError) as exc:
            print(f"  ПРОПУЩЕН {path}: {exc}", file=sys.stderr)
            continue
        try:
            compile(stripped, str(path), "exec")
        except SyntaxError as exc:
            print(f"  ПРОПУЩЕН {path}: результат не компилируется ({exc})", file=sys.stderr)
            continue
        if stripped != source:
            changed += 1
            removed = source.count("\n") - stripped.count("\n")
            print(f"  {path}: -{removed} строк")
            if not args.dry_run:
                path.write_text(stripped, encoding="utf-8")

    print(f"\nизменено файлов: {changed} из {len(files)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
