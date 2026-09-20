"""Scanner abstraction: the agent acquires its own findings."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ..config import ScannerConfig


def _native_scanner_env() -> dict[str, str]:
    """Local scanners must not inherit the host's HTTP proxy configuration."""
    env = os.environ.copy()
    for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        env.pop(key, None)
    return env

log = logging.getLogger(__name__)


class ScannerError(RuntimeError):
    pass


@dataclass(slots=True)
class Availability:
    usable: bool
    mode: str | None = None
    version: str | None = None
    detail: str = ""

    def __str__(self) -> str:
        if self.usable:
            return f"ok via {self.mode}" + (f" ({self.version})" if self.version else "")
        return self.detail or "unavailable"


@dataclass(slots=True)
class ScanResult:
    scanner: str
    ok: bool
    output_path: Path | None = None
    findings: int = 0
    duration_s: float = 0.0
    command: list[str] = field(default_factory=list)
    version: str | None = None
    mode: str | None = None
    error: str | None = None
    stderr_tail: str = ""

    def as_dict(self) -> dict:
        return {
            "scanner": self.scanner,
            "ok": self.ok,
            "output": str(self.output_path) if self.output_path else None,
            "findings": self.findings,
            "duration_s": round(self.duration_s, 1),
            "command": self.command,
            "version": self.version,
            "mode": self.mode,
            "error": self.error,
            "stderr_tail": self.stderr_tail or None,
        }


class Scanner(ABC):
    """One SAST tool, run either natively or in a container."""

    name: str = "scanner"

    def __init__(self, cfg: ScannerConfig) -> None:
        self.cfg = cfg


    def available(self) -> Availability:
        """Prefer the configured mode; fall back to the other if allowed."""
        order = [self.cfg.mode] if self.cfg.mode != "auto" else ["native", "docker"]
        problems = []
        for mode in order:
            probe = self._probe_native() if mode == "native" else self._probe_docker()
            if probe.usable:
                return probe
            problems.append(f"{mode}: {probe.detail}")
        return Availability(usable=False, detail="; ".join(problems))

    def resolve_binary(self, default: str) -> str:
        """The first configured candidate that exists, else PATH."""
        configured = self.cfg.binary
        if not configured:
            return default

        candidates = [configured] if isinstance(configured, str) else list(configured)
        for candidate in candidates:
            path = Path(str(candidate)).expanduser()
            if path.is_file() or shutil.which(str(candidate)):
                return str(path) if path.is_file() else str(candidate)
        return str(Path(str(candidates[0])).expanduser())

    def _probe_native(self) -> Availability:
        argv = self._native_version_argv()
        if not argv:
            return Availability(False, detail="no native invocation defined")
        exe = argv[0]
        on_disk = Path(exe).expanduser()
        if exe != sys.executable and shutil.which(exe) is None and not on_disk.is_file():
            hint = " (set `binary:` in the scanner profile)" if not self.cfg.binary else ""
            return Availability(False, detail=f"{exe!r} not on PATH and not a file{hint}")
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=60, env=_native_scanner_env(), check=False)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Availability(False, detail=f"version probe failed: {exc}")
        if proc.returncode != 0:
            return Availability(False, detail=f"version probe exited {proc.returncode}")
        return Availability(True, mode="native", version=_first_line(proc.stdout or proc.stderr))

    def _probe_docker(self) -> Availability:
        if not self.cfg.image:
            return Availability(False, detail="no docker image configured")
        if shutil.which("docker") is None:
            return Availability(False, detail="docker not on PATH")
        try:
            daemon = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True, text=True, timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Availability(False, detail=f"docker unreachable: {exc}")
        if daemon.returncode != 0:
            return Availability(False, detail="docker daemon not reachable")
        return Availability(True, mode="docker", version=f"image {self.cfg.image}")


    @abstractmethod
    def _native_version_argv(self) -> list[str] | None: ...

    @abstractmethod
    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]: ...

    @abstractmethod
    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]: ...

    @property
    def output_suffix(self) -> str:
        return ".sarif.json"

    @property
    def writes_stdout(self) -> bool:
        """True when the report arrives on stdout rather than a file the tool writes."""
        return True

    @property
    def success_exit_codes(self) -> frozenset[int]:
        """Exit codes that mean "ran fine" — normally {clean, found something}."""
        return frozenset({0, 1})

    def report_health(self, path: Path) -> str | None:
        """Inspect the report itself."""
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"report is not readable JSON: {exc}"
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list):
            return None

        for run in doc["runs"]:
            for inv in run.get("invocations") or []:
                if inv.get("executionSuccessful") is False:
                    detail = (inv.get("exitCodeDescription") or "").strip()
                    return f"SARIF reports executionSuccessful=false{': ' + detail if detail else ''}"

        rules = sum(len(((r.get("tool") or {}).get("driver") or {}).get("rules") or []) for r in doc["runs"])
        results = sum(len(r.get("results") or []) for r in doc["runs"])
        if rules == 0 and results == 0:
            return "the report lists no rules and no results — the scanner ran nothing, which is not a clean codebase"
        return None

    def count_findings(self, path: Path) -> int:
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return 0
        if isinstance(doc, dict) and isinstance(doc.get("runs"), list):
            return sum(len(r.get("results") or []) for r in doc["runs"])
        if isinstance(doc, dict) and isinstance(doc.get("results"), list):
            return len(doc["results"])
        return 0


    def scan(self, target: Path, out_dir: Path) -> ScanResult:
        avail = self.available()
        if not avail.usable:
            return ScanResult(scanner=self.name, ok=False, error=str(avail))

        target = Path(target).resolve()
        if not target.exists():
            return ScanResult(scanner=self.name, ok=False, error=f"target does not exist: {target}")

        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{self.name}{self.output_suffix}"

        argv = (
            self._native_scan_argv(target, out_file)
            if avail.mode == "native"
            else self._docker_scan_argv(target, out_file)
        )

        log.info("%s: %s", self.name, " ".join(argv))
        started = time.monotonic()
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=self.cfg.timeout_s,
                cwd=str(target) if self.cfg.run_in_target else None,
                env=_native_scanner_env() if avail.mode == "native" else None,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ScanResult(
                scanner=self.name, ok=False, command=argv, mode=avail.mode, version=avail.version,
                duration_s=time.monotonic() - started,
                error=f"timed out after {self.cfg.timeout_s}s — raise timeout_s or narrow the target",
            )
        except OSError as exc:
            return ScanResult(scanner=self.name, ok=False, command=argv, error=str(exc))

        duration = time.monotonic() - started
        stderr_tail = "\n".join((proc.stderr or "").strip().splitlines()[-6:])

        if self.writes_stdout:
            if not (proc.stdout or "").strip():
                return ScanResult(
                    scanner=self.name, ok=False, command=argv, mode=avail.mode, version=avail.version,
                    duration_s=duration, stderr_tail=stderr_tail,
                    error=f"produced no report on stdout (exit {proc.returncode}): {stderr_tail[-600:]}",
                )
            out_file.write_text(proc.stdout, encoding="utf-8")

        if not out_file.is_file():
            return ScanResult(
                scanner=self.name, ok=False, command=argv, mode=avail.mode, version=avail.version,
                duration_s=duration, stderr_tail=stderr_tail,
                error=f"no report written (exit {proc.returncode}): {stderr_tail[-600:]}",
            )

        if proc.returncode not in self.success_exit_codes:
            return ScanResult(
                scanner=self.name, ok=False, command=argv, mode=avail.mode, version=avail.version,
                duration_s=duration, stderr_tail=stderr_tail, output_path=out_file,
                findings=self.count_findings(out_file),
                error=f"exited {proc.returncode}, not a success code for this scanner "
                      f"(expected one of {sorted(self.success_exit_codes)}): {stderr_tail[-400:]}",
            )

        if reason := self.report_health(out_file):
            return ScanResult(
                scanner=self.name, ok=False, command=argv, mode=avail.mode, version=avail.version,
                duration_s=duration, stderr_tail=stderr_tail, output_path=out_file,
                error=f"report is not trustworthy: {reason}",
            )

        count = self.count_findings(out_file)
        return ScanResult(
            scanner=self.name, ok=True, output_path=out_file, findings=count,
            duration_s=duration, command=argv, version=avail.version, mode=avail.mode,
            stderr_tail=stderr_tail,
        )


def _first_line(text: str) -> str:
    return (text or "").strip().splitlines()[0].strip() if (text or "").strip() else ""
