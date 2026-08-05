"""A minimal LSP client: JSON-RPC over the server's stdio.

Only the handful of requests triage actually needs. A full client would handle
diagnostics, completion and the rest of the protocol; none of that helps decide
whether a finding is real, and every extra feature is another thing to hang.

The hard-won rules, learned from the scanner layer:

* **Everything is bounded.** A language server that stops answering must not
  stop the run. Every request has a timeout and a failure returns `None`, never
  an exception that propagates into triage.
* **Failure is visible.** A silently degraded resolver would quietly turn into
  "no extra context, verdicts got worse for no visible reason".
* **The server sees the workspace read-only.** We open documents and ask
  questions; we never send edits.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlparse
from urllib.request import url2pathname

log = logging.getLogger(__name__)


class LSPError(RuntimeError):
    pass


def path_to_uri(path: Path, path_map: dict[str, str] | None = None) -> str:
    """A file URI the *server* can open.

    `path_map` exists because a language server does not always share the
    client's filesystem. The PHP servers here run inside WSL, where the project
    lives at `/mnt/c/Users/...` while this process sees `C:\\Users\\...`. Without
    translation every request names a path the server cannot find, and it answers
    nothing at all — which looks exactly like a server that does not work.
    """
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
    index_ready: bool = field(default=False, init=False)

    _proc: subprocess.Popen | None = field(default=None, init=False, repr=False)
    _next_id: int = field(default=0, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)
    _opened: set[str] = field(default_factory=set, init=False, repr=False)
    started: bool = field(default=False, init=False)
    error: str | None = field(default=None, init=False)
    capabilities: dict[str, Any] = field(default_factory=dict, init=False, repr=False)


    def _write(self, payload: dict[str, Any]) -> None:
        if not self._proc or not self._proc.stdin:
            raise LSPError("server is not running")
        body = json.dumps(payload).encode("utf-8")
        header = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
        self._proc.stdin.write(header + body)
        self._proc.stdin.flush()

    def _read(self, deadline: float) -> dict[str, Any] | None:
        """Read one framed message, or None on timeout / EOF."""
        if not self._proc or not self._proc.stdout:
            return None
        stream = self._proc.stdout

        length = 0
        while True:
            if time.monotonic() > deadline:
                return None
            line = stream.readline()
            if not line:
                return None
            line = line.strip()
            if not line:
                break
            if line.lower().startswith(b"content-length:"):
                length = int(line.split(b":", 1)[1])
        if not length:
            return None
        raw = stream.read(length)
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            log.debug("undecodable LSP message: %s", exc)
            return None

    def _request(self, method: str, params: dict[str, Any], timeout: float | None = None) -> Any:
        """Send a request and wait for its reply, skipping unrelated traffic.

        Servers interleave diagnostics and progress notifications with replies,
        so the id has to be matched rather than assuming the next message is ours.
        """
        with self._lock:
            self._next_id += 1
            request_id = self._next_id
            deadline = time.monotonic() + (timeout or self.timeout_s)
            try:
                self._write({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
                while True:
                    message = self._read(deadline)
                    if message is None:
                        log.debug("%s timed out or the server closed the stream", method)
                        return None
                    if message.get("id") == request_id:
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
        self._await_index()
        return True

    def supports(self, capability: str) -> bool:
        return bool(self.capabilities.get(capability))

    def _await_index(self) -> None:
        """Wait until the server can actually answer, not just until it started.

        Servers index in the background after `initialized`, and until that
        finishes they answer every question with an empty result rather than an
        error. Measured on a real PHP project: the first four findings resolved
        nothing and the last two resolved fine, purely because the index had
        caught up by then — which reads as a flaky resolver, not a warm-up.

        `workspace/symbol` is the probe because it is the one request that
        touches the index directly. A timeout here is not fatal: an unindexed
        server degrades to fewer answers, which is the same as no server.
        """
        if not self.supports("workspaceSymbolProvider"):
            return
        deadline = time.monotonic() + self.index_timeout_s
        attempt = 0
        while time.monotonic() < deadline:
            if self._request("workspace/symbol", {"query": "a"}, timeout=10):
                self.index_ready = True
                return
            attempt += 1
            time.sleep(min(0.5 * attempt, 3.0))
        log.warning(
            "%s: index still empty after %.0fs — answers will be sparse",
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

    def __enter__(self) -> "LSPClient":
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
        """Where is the symbol under this position defined? (`line` is 1-indexed.)"""
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
