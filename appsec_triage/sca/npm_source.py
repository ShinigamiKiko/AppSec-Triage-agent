"""The published source of one npm version, for packages the project never installed.

A call chain through dependencies can only be walked when each package in it can
be read. `node_modules` holds the packages the project installs, and a chain
often runs through one that is missing there — a transitive dependency of a
package that was itself pruned, or a tree that was never installed at all. The
exact version named by the lockfile is then fetched from the registry and read
in memory; nothing is written to the project and nothing is executed.
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import logging
import re
import tarfile
import threading
import urllib.error
import urllib.parse
import urllib.request
from pathlib import PurePosixPath

from . import cassette

log = logging.getLogger(__name__)

ECOSYSTEMS = {"npm", "node", "nodejs", "javascript", "js"}

_REGISTRY_HOST = "registry.npmjs.org"
_ALLOWED_HOSTS = {_REGISTRY_HOST}
_TIMEOUT_S = 30
_MAX_MANIFEST_BYTES = 4 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
_MAX_UNPACKED_BYTES = 96 * 1024 * 1024
_MAX_ARCHIVE_FILES = 10_000
_MAX_FILE_BYTES = 2 * 1024 * 1024
_MAX_FILES = 4_000
_CODE_SUFFIXES = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}
_SKIP_PARTS = {"test", "tests", "spec", "specs", "fixtures", "__tests__", "docs",
               "node_modules", "example", "examples", "benchmark", "benchmarks"}
_UA = {"User-Agent": "appsec-triage source-reader", "Accept": "application/json"}
# The registry keeps "@" and "/" literal in a path, so the name is checked
# rather than escaped: only a real package name may shape the address.
_NAME = re.compile(r"^(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*$", re.IGNORECASE)
_VERSION = re.compile(r"^[a-z0-9][a-z0-9.+-]*$", re.IGNORECASE)

_cache: dict[tuple[str, str], dict[str, str]] = {}
_locks: dict[tuple[str, str], threading.Lock] = {}
_guard = threading.Lock()


class _SameHostRedirects(urllib.request.HTTPRedirectHandler):
    """Follow a redirect only while it stays on the registry."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_HOSTS:
            raise urllib.error.URLError(f"redirect leaves the registry: {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def supported(ecosystem: str | None) -> bool:
    return (ecosystem or "").strip().lower() in ECOSYSTEMS


def _version(version: str) -> str:
    value = (version or "").strip()
    return value[1:] if value[:1].lower() == "v" else value


def fetch(package: str, version: str) -> dict[str, str]:
    """`{path: text}` for one exact npm version, downloaded at most once per run."""
    name, exact = (package or "").strip(), _version(version)
    if not _NAME.match(name) or not _VERSION.match(exact):
        return {}
    key = (name.lower(), exact)
    with _guard:
        if key in _cache:
            return _cache[key]
        lock = _locks.setdefault(key, threading.Lock())
    # Two findings on the same package wait for one download, not two.
    with lock:
        with _guard:
            if key in _cache:
                return _cache[key]
        files = _download(name, exact)
        with _guard:
            _cache[key] = files
            _locks.pop(key, None)
        return files


def _download(name: str, version: str) -> dict[str, str]:
    try:
        url, integrity, shasum = _tarball(name, version)
        archive, _ = _get(url, _MAX_ARCHIVE_BYTES)
        _verify(archive, integrity, shasum)
        files = _unpack(archive)
    except (OSError, ValueError, tarfile.TarError, urllib.error.URLError) as exc:
        log.info("npm source for %s@%s not read: %s", name, version, str(exc)[:200])
        return {}
    log.info("npm source for %s@%s: %d file(s) from the registry", name, version, len(files))
    return files


def _tarball(name: str, version: str) -> tuple[str, str, str]:
    """The archive URL and the digests the registry publishes with it."""
    raw, _ = _get(f"https://{_REGISTRY_HOST}/{name}/{version}", _MAX_MANIFEST_BYTES)
    try:
        manifest = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"registry answer is not JSON: {exc}") from exc
    dist = manifest.get("dist") or {}
    url = str(dist.get("tarball") or "")
    if not url:
        raise ValueError("registry lists no archive for this version")
    return url, str(dist.get("integrity") or ""), str(dist.get("shasum") or "").lower()


def _verify(archive: bytes, integrity: str, shasum: str) -> None:
    """Compare against whichever digest the registry gave; refuse a mismatch."""
    algorithm, _, encoded = integrity.partition("-")
    if encoded and algorithm in {"sha512", "sha384", "sha256"}:
        try:
            expected = base64.b64decode(encoded, validate=True)
        except ValueError as exc:
            raise ValueError(f"integrity field is not base64: {exc}") from exc
        if hashlib.new(algorithm, archive).digest() != expected:
            raise ValueError(f"archive does not match its {algorithm} integrity")
        return
    if len(shasum) == 40:
        if hashlib.sha1(archive).hexdigest() != shasum:
            raise ValueError("archive does not match its sha1 checksum")
        return
    raise ValueError("registry published no checksum for this archive")


def _get(url: str, limit: int) -> tuple[bytes, str]:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_HOSTS:
        raise ValueError(f"address is not the npm registry: {url[:200]}")
    opener = urllib.request.build_opener(_SameHostRedirects())
    with cassette.urlopen(urllib.request.Request(url, headers=_UA),
                          timeout=_TIMEOUT_S, opener=opener) as response:
        body = response.read(limit + 1)
        if len(body) > limit:
            raise ValueError(f"download is larger than {limit} bytes")
        return body, response.geturl()


def _member_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ValueError(f"archive member has an unusable name: {name[:120]!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"archive member escapes its directory: {name[:120]!r}")
    return path


def _wanted(path: PurePosixPath) -> bool:
    parts = {part.lower() for part in path.parts}
    return not (parts & _SKIP_PARTS) and path.suffix.lower() in _CODE_SUFFIXES


def _unpack(archive: bytes) -> dict[str, str]:
    """Read the code files out of a .tgz, without writing any of it to disk."""
    files: dict[str, str] = {}
    unpacked = 0
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for seen, member in enumerate(tar, 1):
            if seen > _MAX_ARCHIVE_FILES:
                raise ValueError(f"archive holds more than {_MAX_ARCHIVE_FILES} entries")
            if member.issym() or member.islnk():
                raise ValueError(f"archive holds a link: {member.name[:120]}")
            if not member.isfile():
                continue
            path = _member_path(member.name.rstrip("/"))
            # npm publishes everything under a single "package/" directory.
            if len(path.parts) > 1 and path.parts[0] == "package":
                path = PurePosixPath(*path.parts[1:])
            if not _wanted(path) or member.size > _MAX_FILE_BYTES:
                continue
            unpacked += member.size
            if unpacked > _MAX_UNPACKED_BYTES:
                raise ValueError(f"archive expands past {_MAX_UNPACKED_BYTES} bytes")
            if len(files) >= _MAX_FILES:
                break
            handle = tar.extractfile(member)
            if handle is None:
                continue
            files[str(path)] = handle.read().decode("utf-8", errors="replace")
    if not files:
        raise ValueError("archive holds no JavaScript or TypeScript source")
    return files


def stats() -> dict[str, int]:
    """How many versions were fetched and how many of them could be read."""
    with _guard:
        return {"packages": len(_cache),
                "downloaded": sum(1 for files in _cache.values() if files),
                "unavailable": sum(1 for files in _cache.values() if not files)}
