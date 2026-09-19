"""Record and replay of the chain's HTTP lookups, so a bench measures the pipeline."""

from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

DIR_ENV = "APPSEC_HTTP_CASSETTE"
MODE_ENV = "APPSEC_HTTP_MODE"


class _Replayed(io.BytesIO):
    """The subset of a urllib response the callers use: read, geturl, `with`."""

    def __init__(self, body: bytes, url: str) -> None:
        super().__init__(body)
        self._url = url

    def geturl(self) -> str:
        return self._url


def _key(request: urllib.request.Request) -> str:
    body = request.data or b""
    if isinstance(body, str):
        body = body.encode("utf-8")
    digest = hashlib.sha256()
    for part in (request.get_method().encode(), request.full_url.encode(), body):
        digest.update(part)
        digest.update(b"\0")
    return digest.hexdigest()


def _write(path: Path, url: str, status: int, body: bytes, final_url: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"url": url, "status": status, "final_url": final_url,
             "body": base64.b64encode(body).decode("ascii")}
    path.write_text(json.dumps(entry), encoding="utf-8")


def urlopen(request: urllib.request.Request, *, timeout: float, opener=None):
    """`urllib.request.urlopen` (or `opener.open`), routed through the cassette when one is set."""
    live = opener.open if opener is not None else urllib.request.urlopen
    directory = os.environ.get(DIR_ENV)
    if not directory:
        return live(request, timeout=timeout)

    path = Path(directory) / f"{_key(request)}.json"
    if os.environ.get(MODE_ENV, "replay").strip().lower() != "record":
        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            raise urllib.error.URLError(f"not in cassette: {request.full_url[:200]}") from None
        if entry.get("status", 200) != 200:
            raise urllib.error.HTTPError(entry["url"], entry["status"], "replayed", None, None)
        return _Replayed(base64.b64decode(entry["body"]), entry["final_url"])

    try:
        with live(request, timeout=timeout) as response:
            body = response.read()
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            _write(path, request.full_url, 404, b"", request.full_url)
        raise
    _write(path, request.full_url, 200, body, final_url)
    return _Replayed(body, final_url)
