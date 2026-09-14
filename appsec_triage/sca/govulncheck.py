"""Reachability as a call graph states it, read from a govulncheck artifact.

Everything else in this package approximates the question "is the vulnerable
function actually reached" — from names, from imports, from a language server's
view of one call site. govulncheck answers it outright for Go, by building the
call graph of the program, and a pipeline that already runs it is holding the
answer this agent works hardest to guess.

It is read as an artifact rather than executed here. Running it needs the module
sources on disk and a working build, which is the neighbouring job's business,
not the scanner's — the same arrangement as vendor arriving from the psalm job.

Three levels come out of its report, and they are not equally strong:

- **called** — a function-level trace exists, so the flaw is on a real path from
  an entry point. The trace itself is the evidence, and it names every frame.
- **imported** — the vulnerable package is linked in but no vulnerable symbol is
  called.
- **module only** — the module is in the build list and its vulnerable package
  is not even imported.

The last two both mean "not reached" and close a finding. That is a claim about
a static call graph: calls made through reflection, `go:linkname`, or a plugin
loaded at run time are outside what it can see, so the closure says what it
rests on rather than pretending to be a proof of impossibility.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)


class GovulncheckUnavailable(RuntimeError):
    """A call-graph report was asked for and did not arrive.

    Raised rather than logged because the request itself is the statement that
    this run's verdicts should rest on a call graph. Continuing without one
    produces a report that looks like every other, drawn from weaker evidence,
    with nothing on the page to say so — and a Go finding closed on a name
    search reads exactly like one closed on a proven unreachable path.
    """


class Reach(str, Enum):
    CALLED = "called"
    IMPORTED = "imported"
    MODULE_ONLY = "module_only"


_STRENGTH = {Reach.CALLED: 3, Reach.IMPORTED: 2, Reach.MODULE_ONLY: 1}


@dataclass(slots=True)
class Verdict:
    """What govulncheck established for one advisory."""

    advisory_id: str
    reach: Reach
    trace: list[str] = field(default_factory=list)
    sites: list[tuple[str, int]] = field(default_factory=list)
    """Each frame's file and line, outermost first, for reading the call site."""

    @property
    def reachable(self) -> bool:
        return self.reach is Reach.CALLED

    def render(self) -> str:
        if self.reachable:
            path = " <- ".join(self.trace[:6]) or "трасса не приведена"
            return f"govulncheck: уязвимая функция вызывается — {path}"
        if self.reach is Reach.IMPORTED:
            return ("govulncheck: пакет слинкован, но ни одна уязвимая функция "
                    "не вызывается — по графу вызовов путь не идёт")
        return ("govulncheck: уязвимый пакет не импортируется в сборке — "
                "по графу вызовов путь не идёт")


@dataclass(slots=True)
class Report:
    """Every advisory govulncheck had an opinion about."""

    verdicts: dict[str, Verdict] = field(default_factory=dict)
    problem: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.verdicts)

    def lookup(self, *identifiers: str) -> Verdict | None:
        """The verdict under any of this finding's ids — GO-, CVE- or GHSA-."""
        for identifier in identifiers:
            found = self.verdicts.get((identifier or "").strip().upper())
            if found is not None:
                return found
        return None


def _messages(text: str):
    """govulncheck streams JSON objects back to back rather than one array."""
    decoder, at = json.JSONDecoder(), 0
    while at < len(text):
        while at < len(text) and text[at] in " \n\r\t":
            at += 1
        if at >= len(text):
            return
        try:
            obj, at = decoder.raw_decode(text, at)
        except ValueError as exc:
            raise ValueError(f"нечитаемый JSON на позиции {at}: {exc}") from exc
        yield obj


def _frames(trace: list[dict]) -> list[str]:
    """The call stack as names, innermost frame first — flaw, then its callers."""
    out = []
    for frame in trace:
        function = frame.get("function")
        if not function:
            continue
        package = (frame.get("package") or "").rsplit("/", 1)[-1]
        receiver = frame.get("receiver") or ""
        name = f"{receiver}.{function}" if receiver else function
        out.append(f"{package}.{name}" if package else name)
    return out


def _positions(trace: list[dict]) -> list[tuple[str, int]]:
    """Where each frame sits, outermost first — the entry point comes last.

    Kept because "the call graph reaches it" and "this call can actually fire the
    flaw" are different questions, and the second is answered by reading the call
    site. A trace that reports `http.Client.Get` says nothing about the URL being
    plain HTTP to a link-local address, which is what decides an HTTP/2 flaw.
    """
    out = []
    for frame in reversed(trace):
        position = frame.get("position") or {}
        filename, line = position.get("filename"), position.get("line")
        if filename and line:
            out.append((str(filename), int(line)))
    return out


def load(path: Path | str) -> Report:
    """Parse a `govulncheck -format json` artifact.

    A missing or unreadable file is reported in `problem` and leaves the report
    empty: the rest of the chain then works exactly as it does without it. A
    reachability source that fails must cost nothing more than its own evidence.
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return Report(problem=f"отчёт govulncheck не прочитан ({path}): {exc}")

    verdicts: dict[str, Verdict] = {}
    aliases: dict[str, list[str]] = {}
    try:
        for message in _messages(text):
            if osv := message.get("osv"):
                ident = (osv.get("id") or "").upper()
                if ident:
                    aliases[ident] = [a.upper() for a in (osv.get("aliases") or [])]
                continue

            finding = message.get("finding")
            if not finding:
                continue
            ident = (finding.get("osv") or "").upper()
            if not ident:
                continue
            trace = finding.get("trace") or []
            frames = _frames(trace)
            if frames:
                reach = Reach.CALLED
            elif any(f.get("package") for f in trace):
                reach = Reach.IMPORTED
            else:
                reach = Reach.MODULE_ONLY

            # One advisory produces several findings, one per path found; the
            # strongest is the answer — a symbol called anywhere is called.
            previous = verdicts.get(ident)
            if previous is None or _STRENGTH[reach] > _STRENGTH[previous.reach]:
                verdicts[ident] = Verdict(ident, reach, frames, _positions(trace))
    except ValueError as exc:
        return Report(problem=f"отчёт govulncheck повреждён ({path}): {exc}")

    # Findings arrive under Go's own ids; a scanner may report the same flaw as
    # its CVE or GHSA alias, so both spellings have to resolve.
    for ident, names in aliases.items():
        verdict = verdicts.get(ident)
        if verdict is None:
            continue
        for alias in names:
            verdicts.setdefault(alias, verdict)

    log.info("govulncheck: %d advisories from %s", len(verdicts), path)
    return Report(verdicts=verdicts)
