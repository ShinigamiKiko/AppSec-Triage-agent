"""A minimal LSP client: JSON-RPC over the server's stdio."""

from __future__ import annotations

import json
import logging
import os
import queue
import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self
from urllib.parse import quote, unquote, urlparse
from urllib.request import url2pathname

log = logging.getLogger(__name__)


class LSPError(RuntimeError):
    pass


def path_to_uri(path: Path, path_map: dict[str, str] | None = None) -> str:
    """A file URI the *server* can open."""
    text = str(Path(path).resolve()).replace("\\", "/")
    for src, dst in (path_map or {}).items():
        src_norm = src.replace("\\", "/")
        if text.lower().startswith(src_norm.lower()):
            text = dst.replace("\\", "/").rstrip("/") + "/" + text[len(src_norm) :].lstrip("/")
            break
    return "file:///" + quote(text.lstrip("/"))


def uri_to_path(uri: str, path_map: dict[str, str] | None = None) -> Path:
    """The inverse: a URI from the server, mapped back into our filesystem."""
    parsed = urlparse(uri)
    text = unquote(parsed.path)
    for src, dst in (path_map or {}).items():
        dst_norm = dst.replace("\\", "/").rstrip("/")
        if text.lower().startswith(dst_norm.lower()):
            tail = text[len(dst_norm) :].lstrip("/")
            return Path(src.replace("/", "\\") if "\\" in src else src) / tail
    return Path(url2pathname(text))


@dataclass(slots=True)
class Location:
    """One place in the codebase, already resolved to a readable line."""

    file_path: str
    line: int
    text: str = ""
    symbol: str = ""

    def __str__(self) -> str:
        return f"{self.file_path}:{self.line}  |  {self.text}".rstrip()


@dataclass(slots=True)
class LSPClient:
    """One language server process, driven synchronously."""

    command: list[str]
    root: Path
    timeout_s: float = 30.0
    init_timeout_s: float = 120.0
    index_timeout_s: float = 90.0
    path_map: dict[str, str] = field(default_factory=dict)
    warmup: tuple[Path, str] | None = None
    index_ready: bool = field(default=False, init=False)

    _proc: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _next_id: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _opened: set[str] = field(default_factory=set, init=False, repr=False)
    started: bool = field(default=False, init=False)
    error: str | None = field(default=None, init=False)
    capabilities: dict[str, Any] = field(default_factory=dict, init=False, repr=False)
    # Health guard: a server that times out again and again, or answers slowly,
    # is switched off for the run with one ERROR line instead of costing every
    # finding its full timeout on every question.
    max_consecutive_timeouts: int = 3
    slow_median_s: float = 5.0
    disabled: str | None = field(default=None, init=False)
    _timeouts_in_row: int = field(default=0, init=False, repr=False)
    _latencies: list[float] = field(default_factory=list, init=False, repr=False)
    _slow_reported: bool = field(default=False, init=False, repr=False)
    _inbox: Any = field(default=None, init=False, repr=False)
    _reader: threading.Thread | None = field(default=None, init=False, repr=False)


    def _write(self, payload: dict[str, Any]) -> None:
        if not self._proc or not self._proc.stdin:
            raise LSPError("server is not running")
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._proc.stdin.write(header + body)
        self._proc.stdin.flush()

    def _pump(self) -> None:
        """Reader thread: frames from the server's stdout into the inbox.

        `readline()` on a pipe blocks; reading inline meant a silent server held
        the request past its deadline indefinitely. The deadline now lives on
        the queue, where it can actually expire.
        """
        stream = self._proc.stdout if self._proc else None
        inbox = self._inbox
        while stream is not None:
            try:
                length = 0
                while True:
                    line = stream.readline()
                    if not line:
                        inbox.put(None)
                        return
                    line = line.strip()
                    if not line:
                        break
                    if line.lower().startswith(b"content-length:"):
                        length = int(line.split(b":", 1)[1])
                if not length:
                    continue
                raw = stream.read(length)
                if not raw:
                    inbox.put(None)
                    return
                try:
                    inbox.put(json.loads(raw.decode("utf-8")))
                except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                    log.debug("undecodable LSP message: %s", exc)
            except (OSError, ValueError):
                inbox.put(None)
                return

    def _read(self, deadline: float) -> dict[str, Any] | None:
        """One message from the reader thread, or None on timeout / EOF."""
        if self._inbox is None:
            return None
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        try:
            return self._inbox.get(timeout=remaining)
        except queue.Empty:
            return None

    def _note_latency(self, method: str, elapsed: float, answered: bool) -> None:
        """Count timeouts in a row and watch the median; switch off a server that stalls."""
        if method in ("initialize", "shutdown"):
            return
        if not answered:
            self._timeouts_in_row += 1
            if self._timeouts_in_row >= self.max_consecutive_timeouts and not self.disabled:
                self.disabled = (f"{self._timeouts_in_row} запроса подряд без ответа "
                                 f"(последний {method}, {elapsed:.0f} с)")
                log.error("LSP %s отключён до конца прогона: %s — ответы по коду пойдут без него",
                          self.command[0], self.disabled)
            return
        self._timeouts_in_row = 0
        self._latencies.append(elapsed)
        recent = self._latencies[-20:]
        if len(recent) >= 10 and not self._slow_reported:
            median = statistics.median(recent)
            if median > self.slow_median_s:
                self._slow_reported = True
                log.error("LSP %s тормозит: медиана ответа %.1f с на последних %d запросах "
                          "(проект на /mnt/c, нет node_modules/vendor или сервер без индекса)",
                          self.command[0], median, len(recent))

    def _request(self, method: str, params: dict[str, Any], timeout: float | None = None,
                 *, track: bool = True) -> Any:
        """Send a request and wait for its reply, skipping unrelated traffic."""
        if self.disabled and method != "shutdown":
            return None
        with self._lock:
            self._next_id += 1
            request_id = self._next_id
            started = time.monotonic()
            deadline = started + (timeout or self.timeout_s)
            try:
                self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
                while True:
                    message = self._read(deadline)
                    if message is None:
                        log.debug("%s timed out or the server closed the stream", method)
                        if track:
                            self._note_latency(method, time.monotonic() - started, answered=False)
                        return None
                    if message.get("id") == request_id and "method" not in message:
                        if track:
                            self._note_latency(method, time.monotonic() - started, answered=True)
                        if "error" in message:
                            log.debug("%s returned an error: %s", method, message["error"])
                            return None
                        return message.get("result")
            except (OSError, LSPError) as exc:
                log.debug("%s failed: %s", method, exc)
                return None

    def _notify(self, method: str, params: dict[str, Any]) -> None:
        with self._lock:
            try:
                self._write({"jsonrpc": "2.0", "method": method, "params": params})
            except (OSError, LSPError) as exc:
                log.debug("notification %s failed: %s", method, exc)


    def start(self) -> bool:
        try:
            self._proc = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=str(self.root),
                env={**os.environ, "PYTHONIOENCODING": "utf-8"},
            )
        except OSError as exc:
            self.error = f"cannot start {self.command[0]!r}: {exc}"
            return False
        self._inbox = queue.Queue()
        self._reader = threading.Thread(target=self._pump, name=f"lsp-{self.command[0]}", daemon=True)
        self._reader.start()

        result = self._request(
            "initialize",
            {
                "processId": os.getpid(),
                "rootUri": path_to_uri(self.root, self.path_map),
                "workspaceFolders": [{"uri": path_to_uri(self.root, self.path_map), "name": self.root.name}],
                "capabilities": {
                    "textDocument": {
                        "definition": {"linkSupport": True},
                        "references": {},
                        "callHierarchy": {"dynamicRegistration": False},
                        "hover": {"contentFormat": ["plaintext", "markdown"]},
                    },
                    "workspace": {"symbol": {}},
                },
            },
            timeout=self.init_timeout_s,
        )
        if result is None:
            self.error = "server did not answer `initialize`"
            self.stop()
            return False

        self.capabilities = (result or {}).get("capabilities") or {}
        self._notify("initialized", {})
        self.started = True
        if self.warmup is not None:
            self.open_document(*self.warmup)
        self._await_index()
        return True

    def supports(self, capability: str) -> bool:
        return bool(self.capabilities.get(capability))

    def _await_index(self) -> None:
        """Wait until the server can actually answer, not just until it started."""
        if not self.supports("workspaceSymbolProvider"):
            return
        deadline = time.monotonic() + self.index_timeout_s
        attempt = 0
        while time.monotonic() < deadline:
            if (self._request("workspace/symbol", {"query": "a"}, timeout=10, track=False)
                    or self._request("workspace/symbol", {"query": ""}, timeout=10, track=False)):
                self.index_ready = True
                return
            attempt += 1
            time.sleep(min(0.5 * attempt, 3.0))
        log.error(
            "LSP %s: индекс пуст через %.0f с — ответы о коде будут неполными. Частые причины: "
            "не установлены зависимости (node_modules/vendor), проект на /mnt/c под WSL, "
            "у сервера нет открытого файла проекта",
            self.command[0],
            self.index_timeout_s,
        )

    def stop(self) -> None:
        if not self._proc:
            return
        try:
            self._request("shutdown", {}, timeout=5)
            self._notify("exit", {})
            self._proc.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self._proc.kill()
        finally:
            self._proc = None
            self.started = False

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()


    def open_document(self, path: Path, language_id: str) -> bool:
        """Servers answer nothing about a file they were never told about."""
        uri = path_to_uri(path, self.path_map)
        if uri in self._opened:
            return True
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        self._notify(
            "textDocument/didOpen",
            {"textDocument": {"uri": uri, "languageId": language_id, "version": 1, "text": text}},
        )
        self._opened.add(uri)
        return True


    def definition(self, path: Path, line: int, character: int) -> list[dict[str, Any]]:
        """Where is the symbol under this position defined?"""
        result = self._request(
            "textDocument/definition",
            {
                "textDocument": {"uri": path_to_uri(path, self.path_map)},
                "position": {"line": max(0, line - 1), "character": character},
            },
        )
        return _as_locations(result)

    def references(self, path: Path, line: int, character: int) -> list[dict[str, Any]]:
        result = self._request(
            "textDocument/references",
            {
                "textDocument": {"uri": path_to_uri(path, self.path_map)},
                "position": {"line": max(0, line - 1), "character": character},
                "context": {"includeDeclaration": False},
            },
        )
        return _as_locations(result)

    def incoming_calls(self, path: Path, line: int, character: int) -> list[dict[str, Any]]:
        """Who calls the function at this position — the reachability question."""
        if not self.supports("callHierarchyProvider"):
            return []
        items = self._request(
            "textDocument/prepareCallHierarchy",
            {
                "textDocument": {"uri": path_to_uri(path, self.path_map)},
                "position": {"line": max(0, line - 1), "character": character},
            },
        )
        if not items:
            return []
        calls = self._request("callHierarchy/incomingCalls", {"item": items[0]})
        out: list[dict[str, Any]] = []
        for call in calls or []:
            caller = call.get("from") or {}
            if caller.get("uri"):
                out.append(
                    {
                        "uri": caller["uri"],
                        "range": caller.get("selectionRange") or caller.get("range") or {},
                        "name": caller.get("name", ""),
                    }
                )
        return out


def _as_locations(result: Any) -> list[dict[str, Any]]:
    """`definition` may return a Location, a list, or LocationLinks."""
    if not result:
        return []
    items = result if isinstance(result, list) else [result]
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        uri = item.get("uri") or item.get("targetUri")
        rng = item.get("range") or item.get("targetSelectionRange") or item.get("targetRange")
        if uri and rng:
            out.append({"uri": uri, "range": rng, "name": item.get("name", "")})
    return out
