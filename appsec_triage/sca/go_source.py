"""The published source of one Go module version, when the runner has no copy.

A Go project keeps its dependencies in the module cache, not in the tree, and a
CI runner starts with a cold one: nothing downloads the modules unless the job
builds the project first. Vendoring is the other way, and most projects do not.
So the chain reaches a dependency it cannot read, and the exact version named
by `go.mod` is fetched from the module proxy and read in memory.

The download is checked against the module's `h1:` hash — from the project's own
`go.sum` when it has the entry, and from the checksum database otherwise. This
is the same hash the Go tool verifies, so a proxy cannot serve altered source
without being caught.
"""

from __future__ import annotations

import base64
import hashlib
import io
import logging
import re
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

from . import cassette

log = logging.getLogger(__name__)

ECOSYSTEMS = {"go", "golang"}

_PROXY_HOST = "proxy.golang.org"
_SUMDB_HOST = "sum.golang.org"
_ALLOWED_HOSTS = {_PROXY_HOST, _SUMDB_HOST}
_TIMEOUT_S = 45
_MAX_LOOKUP_BYTES = 256 * 1024
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_UNPACKED_BYTES = 192 * 1024 * 1024
_MAX_ARCHIVE_FILES = 20_000
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 4_000
# How many trailing elements may be dropped to reach the module root: an
# advisory names a package ("…/gin/binding"), the proxy only knows modules.
_MAX_TRIMS = 3
_SKIP_PARTS = {"testdata", "examples", "example", "internal/testdata"}
_UA = {"User-Agent": "appsec-triage source-reader"}
_MODULE = re.compile(r"^[a-z0-9][a-z0-9._~/-]*$", re.IGNORECASE)
_VERSION = re.compile(r"^v[0-9][0-9a-z.+-]*$", re.IGNORECASE)

_cache: dict[tuple[str, str], dict[str, str]] = {}
_locks: dict[tuple[str, str], threading.Lock] = {}
_guard = threading.Lock()


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only while it stays on the proxy or the database."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_HOSTS:
            raise urllib.error.URLError(f"redirect leaves the module proxy: {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def supported(ecosystem: str | None) -> bool:
    return (ecosystem or "").strip().lower() in ECOSYSTEMS


def _version(version: str) -> str:
    value = (version or "").strip()
    return value if value[:1] == "v" else f"v{value}"


def escape(path: str) -> str:
    """The proxy's spelling of a path: an upper-case letter becomes `!` + its lower."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def fetch(module: str, version: str, roots=()) -> dict[str, str]:
    """`{path: text}` for one exact module version, downloaded at most once per run."""
    name, exact = (module or "").strip().strip("/"), _version(version)
    if not _MODULE.match(name) or not _VERSION.match(exact):
        return {}
    key = (name.lower(), exact)
    with _guard:
        if key in _cache:
            return _cache[key]
        lock = _locks.setdefault(key, threading.Lock())
    # Two findings on the same module wait for one download, not two.
    with lock:
        with _guard:
            if key in _cache:
                return _cache[key]
        files = _download(name, exact, [Path(r) for r in roots])
        with _guard:
            _cache[key] = files
            _locks.pop(key, None)
        return files


def _download(module: str, version: str, roots: list[Path]) -> dict[str, str]:
    path, archive = None, b""
    candidate = module
    for _ in range(_MAX_TRIMS + 1):
        try:
            archive, _ = _get(
                f"https://{_PROXY_HOST}/{escape(candidate)}/@v/{escape(version)}.zip",
                _MAX_ARCHIVE_BYTES)
            path = candidate
            break
        except urllib.error.HTTPError as exc:
            # 404 and 410 both mean "no such module here"; try the parent path.
            if exc.code not in (404, 410) or "/" not in candidate:
                log.info("go source for %s@%s not read: %s", module, version, exc)
                return {}
            candidate = candidate.rsplit("/", 1)[0]
        except (OSError, ValueError, urllib.error.URLError) as exc:
            log.info("go source for %s@%s not read: %s", module, version, str(exc)[:200])
            return {}
    if path is None:
        log.info("go source for %s@%s not read: the proxy knows no module on this path",
                 module, version)
        return {}

    try:
        expected = _known_hash(path, version, roots)
        actual = _dirhash(archive)
        if expected and actual != expected:
            raise ValueError(f"module hash {actual} does not match the recorded {expected}")
        if not expected:
            raise ValueError("no h1 hash for this version in go.sum or the checksum database")
        files = _unpack(archive, f"{path}@{version}/")
    except (OSError, ValueError, zipfile.BadZipFile, urllib.error.URLError) as exc:
        log.info("go source for %s@%s not read: %s", path, version, str(exc)[:200])
        return {}
    log.info("go source for %s@%s: %d file(s) from the module proxy", path, version, len(files))
    return files


def _known_hash(module: str, version: str, roots: list[Path]) -> str:
    """The module's `h1:` hash: the project's own go.sum first, the database second."""
    wanted = f"{module} {version} h1:"
    for root in roots:
        for gosum in (root / "go.sum", *sorted(root.glob("*/go.sum"))[:20]):
            try:
                text = gosum.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            for line in text.splitlines():
                if line.startswith(wanted):
                    return line[len(wanted) - 3:].strip()
    try:
        raw, _ = _get(f"https://{_SUMDB_HOST}/lookup/{escape(module)}@{escape(version)}",
                      _MAX_LOOKUP_BYTES)
    except (OSError, ValueError, urllib.error.URLError) as exc:
        log.debug("checksum database did not answer for %s@%s: %s", module, version, exc)
        return ""
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if line.startswith(wanted):
            return line[len(wanted) - 3:].strip()
    return ""


def _dirhash(archive: bytes) -> str:
    """Go's dirhash H1 over a module zip: sha256 of "<sha256>  <name>" per file."""
    digest = hashlib.sha256()
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        names = sorted(info.filename for info in zipped.infolist() if not info.is_dir())
        if any("\n" in name for name in names):
            raise ValueError("archive member name contains a newline")
        for name in names:
            body = zipped.read(name)
            digest.update(f"{hashlib.sha256(body).hexdigest()}  {name}\n".encode())
    return "h1:" + base64.b64encode(digest.digest()).decode()


def _member_path(name: str, prefix: str) -> PurePosixPath | None:
    if not name.startswith(prefix):
        return None
    rest = name[len(prefix):]
    if not rest or "\x00" in rest or "\\" in rest:
        return None
    path = PurePosixPath(rest)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"archive member escapes its directory: {name[:120]!r}")
    return path


def _wanted(path: PurePosixPath) -> bool:
    parts = {part.lower() for part in path.parts}
    if parts & _SKIP_PARTS or path.suffix.lower() != ".go":
        return False
    # A dependency's own tests say nothing about what it exposes to its callers.
    return not path.name.endswith("_test.go")


def _unpack(archive: bytes, prefix: str) -> dict[str, str]:
    """Read the Go files out of a module zip, without writing any of it to disk."""
    files: dict[str, str] = {}
    unpacked = 0
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        infos = [info for info in zipped.infolist() if not info.is_dir()]
        if len(infos) > _MAX_ARCHIVE_FILES:
            raise ValueError(f"archive holds more than {_MAX_ARCHIVE_FILES} entries")
        for info in infos:
            path = _member_path(info.filename, prefix)
            if path is None or not _wanted(path) or info.file_size > _MAX_FILE_BYTES:
                continue
            unpacked += info.file_size
            if unpacked > _MAX_UNPACKED_BYTES:
                raise ValueError(f"archive expands past {_MAX_UNPACKED_BYTES} bytes")
            if len(files) >= _MAX_FILES:
                break
            files[str(path)] = zipped.read(info).decode("utf-8", errors="replace")
    if not files:
        raise ValueError("archive holds no Go source outside tests")
    return files


def _get(url: str, limit: int) -> tuple[bytes, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_HOSTS:
        raise ValueError(f"address is not the module proxy: {url[:200]}")
    opener = urllib.request.build_opener(_SameHostRedirects())
    with cassette.urlopen(urllib.request.Request(url, headers=_UA),
                          timeout=_TIMEOUT_S, opener=opener) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError(f"download is larger than {limit} bytes")
        return body, response.geturl()


def stats() -> dict[str, int]:
    """How many versions were fetched and how many of them could be read."""
    with _guard:
        return {"modules": len(_cache),
                "downloaded": sum(1 for files in _cache.values() if files),
                "unavailable": sum(1 for files in _cache.values() if not files)}
