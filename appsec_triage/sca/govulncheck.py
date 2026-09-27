"""Reachability as a call graph states it, read from a govulncheck artifact."""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from . import gotoolchain

log = logging.getLogger(__name__)

_MODULE_LINE = re.compile(r"^\s*module\s+(\S+)", re.MULTILINE)
_NOT_MODULES = {"vendor", "testdata", "node_modules"}
_RUN_TIMEOUT_S = int(os.environ.get("APPSEC_GOVULNCHECK_TIMEOUT_S", "900"))


class GovulncheckUnavailable(RuntimeError):
    """A call-graph report was asked for and did not arrive."""


class Reach(str, Enum):
    CALLED = "called"
    IMPORTED = "imported"
    MODULE_ONLY = "module_only"


_STRENGTH = {Reach.CALLED: 3, Reach.IMPORTED: 2, Reach.MODULE_ONLY: 1}
# Paths kept per advisory. One reached through an S3 client and one through an HTTP
# handler are different questions; keeping only the first hid the one that mattered.
_MAX_PATHS = 4


@dataclass(slots=True)
class Verdict:
    """What govulncheck established for one advisory."""

    advisory_id: str
    reach: Reach
    trace: list[str] = field(default_factory=list)
    sites: list[tuple[str, int]] = field(default_factory=list)
    # Every distinct call path, `trace` first, with where each enters the project.
    paths: list[list[str]] = field(default_factory=list)
    entries: list[str] = field(default_factory=list)

    @property
    def reachable(self) -> bool:
        return self.reach is Reach.CALLED

    def render(self) -> str:
        if self.reachable:
            if len(self.paths) > 1:
                listed = "\n".join(
                    f"  {n}) {_shown(path)}" + (f" (вход: {entry})" if entry else "")
                    for n, (path, entry) in enumerate(zip(self.paths, self.entries), 1))
                return (f"govulncheck: уязвимая функция вызывается — путей {len(self.paths)}. Они "
                        "независимы: один путь не отменяет другой; для каждого реши, кто присылает "
                        f"данные, на которых срабатывает изъян:\n{listed}")
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


def _shown(path: list[str]) -> str:
    """A call path, flaw first; a long one keeps both ends — the flaw and the entry."""
    if len(path) > 6:
        path = [*path[:3], "…", *path[-3:]]
    return " <- ".join(path)


def _positions(trace: list[dict]) -> list[tuple[str, int]]:
    """Where each frame sits, outermost first — the entry point comes last."""
    out = []
    for frame in reversed(trace):
        position = frame.get("position") or {}
        filename, line = position.get("filename"), position.get("line")
        if filename and line:
            out.append((str(filename), int(line)))
    return out


def load(path: Path | str) -> Report:
    """Parse a `govulncheck -format json` artifact."""
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

            previous = verdicts.get(ident)
            positions = _positions(trace)
            entry = f"{positions[0][0]}:{positions[0][1]}" if positions else ""
            if previous is None or _STRENGTH[reach] > _STRENGTH[previous.reach]:
                verdicts[ident] = Verdict(ident, reach, frames, positions,
                                          paths=[frames] if frames else [], entries=[entry] if frames else [])
            elif (reach is Reach.CALLED and previous.reachable and frames not in previous.paths
                  and len(previous.paths) < _MAX_PATHS):
                previous.paths.append(frames)
                previous.entries.append(entry)
                # Entry points first, one per path: whoever reads a few sites reads every way in.
                if positions and positions[0] not in previous.sites:
                    previous.sites.insert(len(previous.paths) - 1, positions[0])
                previous.sites.extend(p for p in positions if p not in previous.sites)
    except ValueError as exc:
        return Report(problem=f"отчёт govulncheck повреждён ({path}): {exc}")

    for ident, names in aliases.items():
        verdict = verdicts.get(ident)
        if verdict is None:
            continue
        for alias in names:
            verdicts.setdefault(alias, verdict)

    log.info("govulncheck: %d advisories from %s", len(verdicts), path)
    return Report(verdicts=verdicts)


def modules(root: Path) -> list[Path]:
    """Every Go module in the tree: a repository with its backend in a subdirectory has one there."""
    found: list[Path] = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _NOT_MODULES and not d.startswith(".")
                         and not d.startswith("appsec-out"))
        if "go.mod" in files:
            found.append(Path(directory))
    return found


def run(root: Path, out_file: Path, *, binary: str = "govulncheck",
        timeout_s: int = _RUN_TIMEOUT_S) -> tuple[int, int, list[str]]:
    """govulncheck over every Go module, as one report with paths from the root.

    (modules, findings, problems); the report is written only when it holds a finding.
    wolfee runs govulncheck at the root, where a repository whose Go module sits in
    backend/ has none — every Go finding there went without a call graph.
    """
    root = Path(root)
    found = modules(root)
    lines: list[str] = []
    problems: list[str] = []
    findings = 0
    for module in found:
        relative = module.relative_to(root).as_posix()
        try:
            match = _MODULE_LINE.search((module / "go.mod").read_text(encoding="utf-8", errors="replace"))
        except OSError:
            match = None
        main = match.group(1) if match else ""
        # The standard library as the project builds it; the image's Go when that
        # release cannot be fetched — said, not silent.
        toolchain = gotoolchain.env_for(root, module)
        messages, problem = _one_module(binary, module, timeout_s, toolchain)
        if problem and toolchain:
            problems.append(f"{relative}: с {toolchain['GOTOOLCHAIN']} не вышло ({problem[:160]}); "
                            f"stdlib проверена по {gotoolchain.local_release() or 'Go образа'}")
            messages, problem = _one_module(binary, module, timeout_s, {})
        if problem:
            problems.append(f"{relative}: {problem}")
            continue
        for message in messages:
            finding = message.get("finding")
            if finding:
                findings += 1
                # The module's own files, from the module root to the repository root;
                # frames in dependencies keep their paths — they are not in the tree.
                for frame in finding.get("trace") or []:
                    position = frame.get("position") or {}
                    name = position.get("filename")
                    if relative != "." and name and frame.get("module") == main and not Path(name).is_absolute():
                        position["filename"] = f"{relative}/{name}"
            lines.append(json.dumps(message, ensure_ascii=False))
    if findings:
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(found), findings, problems


def _one_module(binary: str, module: Path, timeout_s: int, toolchain: dict[str, str]) -> tuple[list[dict], str]:
    """(messages, problem) of govulncheck over one module."""
    try:
        proc = subprocess.run([binary, "-json", "./..."], cwd=module, capture_output=True, text=True,
                              timeout=timeout_s, encoding="utf-8", errors="replace", check=False,
                              env={**os.environ, **toolchain})
    except subprocess.TimeoutExpired:
        return [], f"не уложился в {timeout_s}s"
    except OSError as exc:
        return [], f"не запустился: {exc}"
    try:
        messages = list(_messages(proc.stdout))
    except ValueError as exc:
        return [], str(exc)
    if proc.returncode != 0 and not any("finding" in m for m in messages):
        tail = " ".join((proc.stderr or "").strip().splitlines()[-2:])
        return [], f"код {proc.returncode}: {tail[:300]}"
    return messages, ""
