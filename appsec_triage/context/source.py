"""Widen the code window by reading the real file.

Scanners crop aggressively. Bandit's `code` for a multi-line call starts at the
flagged line, so `subprocess.Popen(` never appears — the model correctly infers
the call and then fails the grounding check because it cannot quote it. On a
real repository that accounted for most of the remaining hallucination flags.

This is not the thing the article warns against. We are not reconstructing a
dataflow the scanner did not report; we are showing more of the file the scanner
already pointed at, verbatim. The window is bounded, and every line still comes
from disk rather than from the model.

Paths are resolved strictly inside the configured roots — a scanner report is
untrusted input, and `../../etc/shadow` in a filename must not read anything.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 2_000_000


@dataclass(slots=True)
class Window:
    text: str
    start_line: int
    end_line: int
    resolved: bool


class SourceResolver:
    """Reads bounded line windows out of the scanned tree."""

    def __init__(self, roots: list[Path]) -> None:
        self.roots = [Path(r).resolve() for r in roots if Path(r).exists()]
        self._cache: dict[Path, list[str] | None] = {}
        self.hits = 0
        self.misses = 0

    def _resolve(self, file_path: str) -> Path | None:
        rel = Path(file_path.replace("\\", "/"))
        for root in self.roots:
            for candidate in (root / rel, root / rel.name):
                try:
                    full = candidate.resolve()
                except OSError:
                    continue
                if not full.is_relative_to(root) or not full.is_file():
                    continue
                return full
            parts = rel.parts
            for i in range(1, len(parts)):
                try:
                    full = (root / Path(*parts[i:])).resolve()
                except OSError:
                    continue
                if full.is_relative_to(root) and full.is_file():
                    return full
        return None

    def _lines(self, path: Path) -> list[str] | None:
        if path not in self._cache:
            try:
                if path.stat().st_size > MAX_FILE_BYTES:
                    self._cache[path] = None
                else:
                    self._cache[path] = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                log.debug("cannot read %s: %s", path, exc)
                self._cache[path] = None
        return self._cache[path]

    def window(
        self,
        file_path: str,
        start: int | None,
        end: int | None,
        context: int,
        before: int | None = None,
    ) -> Window | None:
        """Lines around the flagged region, 1-indexed inclusive.

        `before` allows an asymmetric window, which matters more than it sounds:
        for a dataflow finding the sanitiser is almost always *above* the sink.
        Measured on DVWA, a symmetric ±6 window cut the four `is_numeric()`
        octet checks out of view and the model confirmed a command injection in
        the deliberately-fixed version, writing "there is no sanitization" —
        which was true of what it had been shown.
        """
        if not self.roots or not start:
            return None
        path = self._resolve(file_path)
        if path is None:
            self.misses += 1
            return None
        lines = self._lines(path)
        if not lines:
            self.misses += 1
            return None

        lo = max(1, start - (before if before is not None else context))
        hi = min(len(lines), (end or start) + context)
        self.hits += 1
        body = "\n".join(f"{n:>5} | {lines[n - 1]}" for n in range(lo, hi + 1))
        return Window(text=body, start_line=lo, end_line=hi, resolved=True)

    def line(self, file_path: str, number: int | None) -> str | None:
        """One source line, for annotating a trace.

        CodeQL's threadFlow steps carry `file:line` and an engine-internal node
        name ("ControlFlowNode for Attribute") and no code at all. Rendered as-is
        the trace is noise; with the real line beside it, it becomes the thing
        the model cannot otherwise reconstruct.
        """
        if not self.roots or not number:
            return None
        path = self._resolve(file_path)
        if path is None:
            return None
        lines = self._lines(path)
        if not lines or number > len(lines):
            return None
        return lines[number - 1].strip() or None

    def stats(self) -> dict[str, int]:
        return {"resolved": self.hits, "unresolved": self.misses, "roots": len(self.roots)}
