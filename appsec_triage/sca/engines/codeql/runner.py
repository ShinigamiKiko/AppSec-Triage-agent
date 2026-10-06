"""The one place CodeQL runs: a persistent query pack, constant queries, one long-lived JVM.

Three costs dominated a dependency run and none of them was evaluation:

* every question wrote a fresh query pack into a temporary directory, so pack
  resolution and the frontend cache started cold each time;
* every question inlined its package names into the query text, so the compile
  cache missed and each query was compiled again (28.8 s of a 37 s question);
* every command started a JVM of its own.

Here the pack lives in one directory for the life of the machine, the query
texts never change (what varies arrives through `external` predicates read from
CSV), and commands go to one `codeql execute cli-server` process when it works.
If the server misbehaves, the command runs as a plain subprocess instead — a
slower answer is still an answer.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
import queue
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

PACK_ROOT_ENV = "APPSEC_CODEQL_PACKS"
CLI_SERVER_ENV = "APPSEC_CODEQL_CLI_SERVER"


def pack_root() -> Path:
    configured = os.environ.get(PACK_ROOT_ENV)
    if configured:
        return Path(configured).expanduser()
    return Path.home() / ".cache" / "appsec-triage" / "codeql-packs"


_PACK_LOCK = threading.Lock()


def query_file(language: str, text: str) -> Path:
    """The query, stored once in a persistent pack and named by its content."""
    pack = pack_root() / language
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:16]
    path = pack / f"q_{digest}.ql"
    with _PACK_LOCK:
        pack.mkdir(parents=True, exist_ok=True)
        manifest = pack / "qlpack.yml"
        wanted = (f"name: wolfee/sca-{language}\nversion: 0.0.1\n"
                  f"dependencies:\n  codeql/{language}-all: \"*\"\n")
        if not manifest.is_file() or manifest.read_text(encoding="utf-8") != wanted:
            _atomic_write(manifest, wanted)
        if not path.is_file():
            _atomic_write(path, text)
    return path


def _atomic_write(path: Path, text: str) -> None:
    handle, temp = tempfile.mkstemp(dir=str(path.parent), prefix=".tmp-", suffix=path.suffix)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="\n") as out:
            out.write(text)
        os.replace(temp, path)
    except BaseException:
        Path(temp).unlink(missing_ok=True)
        raise


def write_external(directory: Path, name: str, rows) -> Path:
    """Rows of an `external predicate`, as the CSV `--external=<name>=<file>` reads."""
    path = Path(directory) / f"{name}.csv"
    with open(path, "w", encoding="utf-8", newline="") as out:
        writer = csv.writer(out)
        for row in rows:
            writer.writerow(list(row))
    return path


# --------------------------------------------------------------------------- #
# cli-server
# --------------------------------------------------------------------------- #

@dataclass(slots=True)
class Completed:
    """The part of `subprocess.CompletedProcess` the callers read."""

    args: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""


class _CliServer:
    """`codeql execute cli-server`: JSON argv in, output and a NUL byte out.

    The protocol is the one the VS Code extension speaks: one JSON array of
    arguments followed by a NUL byte on stdin; the command's stdout, then a NUL
    byte, on stdout. The protocol carries no exit status, so a command counts
    as successful only if the file it was asked to write exists; otherwise the
    caller runs it again as a subprocess and gets a real exit code.
    """

    def __init__(self, binary: str) -> None:
        self.binary = binary
        self._proc: subprocess.Popen | None = None
        self._out: queue.Queue | None = None
        self._stderr: list[str] = []
        self._lock = threading.Lock()
        self.broken = ""

    def _start(self) -> bool:
        try:
            self._proc = subprocess.Popen(
                [self.binary, "execute", "cli-server"],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except OSError as exc:
            self.broken = f"cli-server не запустился: {exc}"
            return False
        self._out = queue.Queue()
        threading.Thread(target=self._pump_stdout, daemon=True, name="codeql-cli-out").start()
        threading.Thread(target=self._pump_stderr, daemon=True, name="codeql-cli-err").start()
        log.info("codeql cli-server started (%s)", self.binary)
        return True

    def _pump_stdout(self) -> None:
        stream = self._proc.stdout if self._proc else None
        buffer = bytearray()
        while stream is not None:
            chunk = stream.read1(65536) if hasattr(stream, "read1") else stream.read(1)
            if not chunk:
                self._out.put(None)
                return
            buffer.extend(chunk)
            while (index := buffer.find(b"\0")) >= 0:
                self._out.put(bytes(buffer[:index]))
                del buffer[:index + 1]

    def _pump_stderr(self) -> None:
        stream = self._proc.stderr if self._proc else None
        while stream is not None:
            line = stream.readline()
            if not line:
                return
            text = line.decode("utf-8", errors="replace").rstrip()
            self._stderr.append(text)
            del self._stderr[:-200]

    def run(self, argv: list[str], timeout_s: float) -> Completed | None:
        """The command's output, or None when the server cannot be trusted with it."""
        with self._lock:
            if self.broken:
                return None
            if self._proc is None or self._proc.poll() is not None:
                if not self._start():
                    return None
            mark = len(self._stderr)
            try:
                self._proc.stdin.write(json.dumps(argv[1:]).encode("utf-8") + b"\0")
                self._proc.stdin.flush()
            except OSError as exc:
                self._disable(f"cli-server не принял команду: {exc}")
                return None
            try:
                output = self._out.get(timeout=timeout_s)
            except queue.Empty:
                self._disable(f"cli-server не ответил за {timeout_s:.0f} с")
                return Completed(argv, 124, "", f"CodeQL не уложился в {timeout_s:.0f}с")
            if output is None:
                self._disable("cli-server завершился")
                return None
            return Completed(argv, 0, output.decode("utf-8", errors="replace"),
                             "\n".join(self._stderr[mark:]))

    def _disable(self, reason: str) -> None:
        self.broken = reason
        log.warning("codeql cli-server выключен до конца прогона: %s — дальше отдельные процессы", reason)
        self.close()

    def close(self) -> None:
        if self._proc is not None:
            try:
                self._proc.stdin.close()
                self._proc.wait(timeout=10)
            except (OSError, subprocess.TimeoutExpired):
                self._proc.kill()
            self._proc = None


_SERVERS: dict[str, _CliServer] = {}
_SERVERS_LOCK = threading.Lock()


def cli_server_enabled() -> bool:
    return os.environ.get(CLI_SERVER_ENV, "1").strip().lower() not in ("0", "false", "no", "off")


def _server_for(binary: str) -> _CliServer:
    with _SERVERS_LOCK:
        server = _SERVERS.get(binary)
        if server is None:
            server = _SERVERS[binary] = _CliServer(binary)
        return server


def _expected_output(argv: list[str]) -> Path | None:
    for arg in argv:
        if arg.startswith("--output="):
            return Path(arg.split("=", 1)[1])
    return None


def via_server(argv: list[str], timeout_s: float) -> Completed | None:
    """Run through the cli-server when that is safe to judge, else None.

    Only commands whose success leaves a file behind (`query run`,
    `database analyze`, `bqrs interpret`) or whose whole answer is stdout
    (`bqrs decode`) are sent; for the former the file must exist afterwards.
    """
    if not cli_server_enabled() or len(argv) < 3:
        return None
    verb = tuple(argv[1:3])
    output = _expected_output(argv)
    if verb in (("query", "run"), ("database", "analyze"), ("bqrs", "interpret")):
        if output is None:
            return None
        output.unlink(missing_ok=True)
    elif verb == ("bqrs", "decode"):
        target = Path(argv[-1])
        if not target.is_file() or target.stat().st_size == 0:
            return None
    else:
        return None
    started = time.monotonic()
    done = _server_for(argv[0]).run(argv, timeout_s)
    if done is None:
        return None
    if done.returncode == 0 and output is not None and not output.is_file():
        log.debug("cli-server: %s produced no %s — rerunning as a process", " ".join(argv[1:3]), output.name)
        return None
    log.debug("cli-server: %s in %.1fs", " ".join(argv[1:3]), time.monotonic() - started)
    return done


def close_servers() -> None:
    with _SERVERS_LOCK:
        for server in _SERVERS.values():
            server.close()
        _SERVERS.clear()
