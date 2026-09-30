"""A minimal LSP client: JSON-RPC over the server's stdio."""

from __future__ import annotations

import json
import logging
import os
import queue
import select
import statistics
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Self
from urllib.parse import quote, unquote, urlparse
from urllib.request import url2pathname

from .. import timing

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


_SEARCHES = frozenset({"textDocument/references", "textDocument/implementation", "workspace/symbol",
                       "callHierarchy/incomingCalls", "callHierarchy/outgoingCalls"})
_MAX_OVERDUE = 64
_STOP_S = 5.0
MAX_OPEN_BYTES = 256 * 1024


@dataclass(slots=True)
class LSPClient:
    """One language server process, driven synchronously."""

    command: list[str]
    root: Path
    timeout_s: float = 30.0
    init_timeout_s: float = 120.0
    index_timeout_s: float = 90.0
    search_timeout_s: float = 60.0
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
    max_consecutive_timeouts: int = 3
    slow_median_s: float = 5.0
    disabled: str | None = field(default=None, init=False)
    _timeouts_in_row: int = field(default=0, init=False, repr=False)
    _overdue: set[int] = field(default_factory=set, init=False, repr=False)
    _last_heard: float = field(default_factory=time.monotonic, init=False, repr=False)
    cooldown_s: float = 120.0
    max_pauses: int = 2
    _paused_until: float = field(default=0.0, init=False, repr=False)
    _pauses: int = field(default=0, init=False, repr=False)
    _latencies: list[float] = field(default_factory=list, init=False, repr=False)
    _slow_reported: bool = field(default=False, init=False, repr=False)
    _inbox: Any = field(default=None, init=False, repr=False)
    write_timeout_s: float = 10.0
    _fd: int | None = field(default=None, init=False, repr=False)
    max_restarts: int = 2
    _broken: str | None = field(default=None, init=False, repr=False)
    _restarts: int = field(default=0, init=False, repr=False)
    _restart_lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _reader: threading.Thread | None = field(default=None, init=False, repr=False)


    def _write(self, payload: dict[str, Any], deadline: float) -> None:
        """One whole message into the server's input by the deadline; the caller holds the lock.

        Nothing written by then: the server is not reading, and is paused. Part of it
        written: the stream is corrupt, and the connection is dropped.
        """
        proc = self._proc
        if proc is None or proc.stdin is None or self._broken:
            raise LSPError(self._broken or "server is not running")
        body = json.dumps(payload).encode("utf-8")
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        if self._fd is None:
            proc.stdin.write(frame)
            proc.stdin.flush()
            return
        view, sent = memoryview(frame), 0
        while sent < len(frame):
            try:
                sent += os.write(self._fd, view[sent:])
                continue
            except BlockingIOError:
                pass
            except OSError as exc:
                self._drop(f"запись в сервер не удалась: {exc}")
                raise LSPError(str(exc)) from None
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            select.select([], [self._fd], [], min(remaining, 1.0))
        if sent < len(frame):
            what = payload.get("method") or "ответ"
            if sent:
                self._drop(f"{what} отправлен не целиком ({sent} из {len(frame)} байт) — поток испорчен")
            else:
                self._pause(f"сервер не читает ввод: {what} не ушёл за {self.write_timeout_s:.0f} с")
            raise LSPError("write timed out")

    def _pause(self, reason: str) -> None:
        """Stop asking this server for a while; off for the run once the pauses ran out."""
        if self.disabled:
            return
        self.disabled = reason
        self._timeouts_in_row = 0
        if self._pauses < self.max_pauses:
            self._pauses += 1
            pause = self.cooldown_s * self._pauses
            self._paused_until = time.monotonic() + pause
            log.warning("LSP %s на паузе %.0f с: %s — пока ответы по коду идут без него",
                        self.command[0], pause, reason)
        else:
            self._paused_until = 0.0
            log.error("LSP %s отключён до конца прогона: %s — ответы по коду пойдут без него",
                      self.command[0], reason)

    def _drop(self, reason: str) -> None:
        """This connection is done: the server is killed, whoever waits on it hears so at once."""
        self._broken = reason
        self.started = False
        proc, self._proc, self._fd = self._proc, None, None
        if proc is not None:
            try:
                proc.kill()
            except OSError:
                pass
        if self._inbox is not None:
            self._inbox.put(None)
        log.warning("LSP %s: соединение разорвано (%s) — сервер будет запущен заново",
                    self.command[0], reason)

    def _reconnect(self) -> bool:
        """Start a new server in place of a dropped one, in the background: no finding waits
        for `initialize` and the index. False until it is up, or when no restart is left."""
        if not self._broken:
            return True
        if not self._restart_lock.acquire(blocking=False):
            return False
        if self._restarts >= self.max_restarts:
            if not self.disabled:
                self.disabled, self._paused_until = self._broken, 0.0
                log.error("LSP %s отключён до конца прогона: %s (перезапусков: %d)",
                          self.command[0], self._broken, self._restarts)
            self._restart_lock.release()
            return False
        self._restarts += 1
        threading.Thread(target=self._restart, name=f"lsp-{self.command[0]}-restart", daemon=True).start()
        return False

    def _restart(self) -> None:
        try:
            reason = self._broken
            self._opened.clear()
            self._overdue.clear()
            self._broken, self.disabled, self._paused_until, self._timeouts_in_row = None, None, 0.0, 0
            if self.start():
                log.info("LSP %s запущен заново (%d-й раз) после: %s", self.command[0], self._restarts, reason)
            else:
                self._broken = reason
        finally:
            self._restart_lock.release()

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
                    self._last_heard = time.monotonic()
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
            silent = time.monotonic() - self._last_heard
            if (self._timeouts_in_row >= self.max_consecutive_timeouts and silent >= self.search_timeout_s
                    and not self.disabled):
                self._pause(f"{self._timeouts_in_row} запроса подряд без ответа, сервер молчит "
                            f"{silent:.0f} с (последний {method}, {elapsed:.0f} с)")
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

    def _usable(self) -> bool:
        """Not paused or off; a pause that is over ends here."""
        if not self.disabled:
            return True
        if not (self._paused_until and time.monotonic() >= self._paused_until):
            return False
        log.info("LSP %s: пауза кончилась, спрашиваю снова", self.command[0])
        self.disabled, self._paused_until = None, 0.0
        self._last_heard = time.monotonic()
        return True

    def _request(self, method: str, params: dict[str, Any], timeout: float | None = None,
                 *, track: bool = True) -> Any:
        """Send a request and wait for its reply, all of it within one deadline.

        The deadline covers the wait for the client's lock (one request at a time per
        server), sending, and the answer: a queue of findings behind one slow answer ends
        in timeouts, not in a run that stands still.
        """
        if method not in ("initialize", "shutdown"):
            if self._broken and not self._reconnect():
                return None
            if not self.started or not self._usable():
                return None
        search = method in _SEARCHES
        queued = time.monotonic()
        deadline = queued + (timeout or (self.search_timeout_s if search else self.timeout_s))
        if not self._lock.acquire(timeout=max(0.0, deadline - queued)):
            timing.add("lsp-wait", time.monotonic() - queued)
            return None
        try:
            timing.add("lsp-wait", time.monotonic() - queued)
            if method not in ("initialize", "shutdown") and (self._broken or self.disabled):
                return None
            self._next_id += 1
            request_id = self._next_id
            started = time.monotonic()
            try:
                self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}, deadline)
                while True:
                    message = self._read(deadline)
                    if message is None:
                        timing.add("lsp", time.monotonic() - started)
                        if self._broken:
                            return None
                        log.debug("%s timed out or the server closed the stream", method)
                        self._give_up(request_id)
                        if track and not search:
                            self._note_latency(method, time.monotonic() - started, answered=False)
                        return None
                    if "method" not in message and message.get("id") in self._overdue:
                        self._overdue.discard(message.get("id"))
                        self._timeouts_in_row = 0
                        continue
                    if message.get("id") == request_id and "method" not in message:
                        if track:
                            self._note_latency(method, time.monotonic() - started, answered=True)
                        timing.add("lsp", time.monotonic() - started)
                        if "error" in message:
                            log.debug("%s returned an error: %s", method, message["error"])
                            return None
                        return message.get("result")
            except (OSError, LSPError) as exc:
                timing.add("lsp", time.monotonic() - started)
                log.debug("%s failed: %s", method, exc)
                return None
        finally:
            self._lock.release()

    def _give_up(self, request_id: int) -> None:
        """Stop waiting for a request: ask the server to drop it, and remember it in case it answers.

        The caller holds the lock; the cancel gets a second of its own to go out.
        """
        if len(self._overdue) >= _MAX_OVERDUE:
            self._overdue.clear()
        self._overdue.add(request_id)
        try:
            self._write({"jsonrpc": "2.0", "method": "$/cancelRequest", "params": {"id": request_id}},
                        time.monotonic() + 1.0)
        except (OSError, LSPError) as exc:
            log.debug("cancelling request %s failed: %s", request_id, exc)

    def _notify(self, method: str, params: dict[str, Any], timeout: float | None = None) -> bool:
        """A notification, within its own deadline; not sent while the server is paused or restarting."""
        if method not in ("initialized", "exit") and (self._broken or not self.started or self.disabled):
            return False
        queued = time.monotonic()
        deadline = queued + (timeout or self.write_timeout_s)
        if not self._lock.acquire(timeout=max(0.0, deadline - queued)):
            return False
        try:
            self._write({"jsonrpc": "2.0", "method": method, "params": params}, deadline)
            return True
        except (OSError, LSPError) as exc:
            log.debug("notification %s failed: %s", method, exc)
            return False
        finally:
            self._lock.release()


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
        self._fd = None
        if os.name == "posix" and self._proc.stdin is not None:
            try:
                self._fd = self._proc.stdin.fileno()
                os.set_blocking(self._fd, False)
            except (OSError, ValueError):
                self._fd = None
        self._last_heard = time.monotonic()
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
        """Shut the server down, every step bounded; killed if it does not go."""
        proc = self._proc
        if not proc:
            return
        try:
            if not self._broken:
                self._request("shutdown", {}, timeout=_STOP_S)
                self._notify("exit", {}, timeout=1.0)
            proc.wait(timeout=_STOP_S)
        except (OSError, subprocess.TimeoutExpired):
            pass
        finally:
            if proc.poll() is None:
                try:
                    proc.kill()
                    proc.wait(timeout=2)
                except (OSError, subprocess.TimeoutExpired):
                    pass
            self._proc, self._fd = None, None
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
            if Path(path).stat().st_size > MAX_OPEN_BYTES:
                return False
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        if not self._notify(
            "textDocument/didOpen",
            {"textDocument": {"uri": uri, "languageId": language_id, "version": 1, "text": text}},
        ):
            return False
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
