"""Run-scoped, read-only source cache for exact dependency versions.

The cache exists for transitive bridge analysis. It never installs a package,
runs package-manager scripts, or adds files to the project. Composer archives
are resolved through Packagist metadata, bounded, validated, and unpacked into
a fresh temporary directory that is deleted when the SCA run ends.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import stat
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath

log = logging.getLogger(__name__)

_TIMEOUT_S = 45
_MAX_METADATA_BYTES = 8 * 1024 * 1024
_MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
_MAX_UNPACKED_BYTES = 192 * 1024 * 1024
_MAX_ARCHIVE_FILES = 20_000
_MAX_SOURCE_FILE_BYTES = 2 * 1024 * 1024
_MAX_SOURCE_FILES = 6_000
_CODE_SUFFIXES = {".php", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".go", ".java"}
_SKIP_PARTS = {"test", "tests", "spec", "specs", "fixtures", "__tests__", "docs"}
_ALLOWED_ARCHIVE_HOSTS = {
    "api.github.com",
    "github.com",
    "codeload.github.com",
    "gitlab.com",
    "bitbucket.org",
    "api.bitbucket.org",
}
_UA = {"User-Agent": "appsec-triage/0.1 source-cache"}


class _AllowlistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts: set[str]) -> None:
        self._allowed_hosts = allowed_hosts

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        parsed = urllib.parse.urlparse(newurl)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in self._allowed_hosts:
            raise urllib.error.URLError(f"redirect URL is not allowlisted: {newurl[:200]}")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(slots=True)
class SourceSnapshot:
    ecosystem: str
    package: str
    version: str
    files: dict[str, str] = field(default_factory=dict)
    source_url: str = ""
    archive_sha256: str = ""
    problem: str = ""
    cache_status: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.files) and not self.problem

    def describe(self) -> str:
        identity = f"{self.package}@{self.version}"
        if self.problem:
            return f"{identity}: source unavailable ({self.problem})"
        return f"{identity}: {len(self.files)} source file(s) from {self.source_url}"


def _normalise_version(version: str) -> str:
    value = (version or "").strip()
    return value[1:] if value.lower().startswith("v") else value


def _safe_member_path(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name:
        raise ValueError(f"unsafe archive member path: {name!r}")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        raise ValueError(f"unsafe archive member path: {name!r}")
    return path


def _common_root(paths: list[PurePosixPath]) -> str:
    if not paths or any(len(path.parts) < 2 for path in paths):
        return ""
    first = {path.parts[0] for path in paths}
    return next(iter(first)) if len(first) == 1 else ""


def _interesting(path: PurePosixPath) -> bool:
    parts = {part.lower() for part in path.parts}
    return not (parts & _SKIP_PARTS) and path.suffix.lower() in _CODE_SUFFIXES


class PackageSourceCache:
    """Download each exact package version at most once during one SCA run."""

    def __init__(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="appsec-triage-sources-")
        self.root = Path(self._temp.name)
        self._entries: dict[tuple[str, str, str], SourceSnapshot] = {}
        self._lock = threading.Lock()
        self.downloads = 0
        self.hits = 0
        self.failures = 0

    @staticmethod
    def _key(ecosystem: str, package: str, version: str) -> tuple[str, str, str]:
        return ecosystem.strip().lower(), package.strip().lower(), _normalise_version(version)

    def source(self, ecosystem: str, package: str, version: str) -> dict[str, str]:
        return self.snapshot(ecosystem, package, version).files

    def snapshot(self, ecosystem: str, package: str, version: str) -> SourceSnapshot:
        key = self._key(ecosystem, package, version)
        with self._lock:
            if key in self._entries:
                self.hits += 1
                return replace(self._entries[key], cache_status="cache_hit")
            snapshot = self._download(*key)
            snapshot.cache_status = "downloaded" if snapshot.usable else "unavailable"
            self._entries[key] = snapshot
            if snapshot.usable:
                self.downloads += 1
            else:
                self.failures += 1
            return snapshot

    def note(self, ecosystem: str, package: str, version: str) -> str:
        key = self._key(ecosystem, package, version)
        snapshot = self._entries.get(key)
        return snapshot.describe() if snapshot else ""

    def stats(self) -> dict[str, int]:
        return {
            "packages": len(self._entries),
            "downloads": self.downloads,
            "cache_hits": self.hits,
            "failures": self.failures,
        }

    def close(self) -> None:
        self._entries.clear()
        self._temp.cleanup()

    def _download(self, ecosystem: str, package: str, version: str) -> SourceSnapshot:
        snapshot = SourceSnapshot(ecosystem, package, version)
        if ecosystem not in {"composer", "packagist", "php"}:
            snapshot.problem = f"remote source cache does not support ecosystem {ecosystem or 'unknown'}"
            return snapshot
        if not package or "/" not in package or not version:
            snapshot.problem = "Composer package name or exact version is missing"
            return snapshot

        try:
            release = self._composer_release(package, version)
            dist = release.get("dist") or {}
            url = str(dist.get("url") or "")
            if str(dist.get("type") or "zip").lower() != "zip" or not url:
                raise ValueError("Packagist release has no zip dist archive")
            self._validate_archive_url(url)
            archive, final_url = self._fetch_bytes(
                url, _MAX_ARCHIVE_BYTES, allowed_hosts=_ALLOWED_ARCHIVE_HOSTS)
            self._validate_archive_url(final_url)
            shasum = str(dist.get("shasum") or "").lower()
            if shasum and len(shasum) == 40 and hashlib.sha1(archive).hexdigest() != shasum:
                raise ValueError("archive SHA-1 does not match Packagist metadata")
            destination = self.root / hashlib.sha256("://".join((ecosystem, package, version)).encode()).hexdigest()[:20]
            destination.mkdir()
            snapshot.files = self._extract_zip(archive, destination)
            if not snapshot.files:
                raise ValueError("archive contains no supported source files")
            snapshot.source_url = final_url
            snapshot.archive_sha256 = hashlib.sha256(archive).hexdigest()
            log.info("source cache downloaded %s", snapshot.describe())
        except (OSError, RuntimeError, ValueError, zipfile.BadZipFile, urllib.error.URLError) as exc:
            snapshot.problem = str(exc)[:500]
            log.warning("source cache: %s", snapshot.describe())
        return snapshot

    def _composer_release(self, package: str, version: str) -> dict:
        encoded = urllib.parse.quote(package, safe="/")
        url = f"https://repo.packagist.org/p2/{encoded}.json"
        raw, _ = self._fetch_bytes(
            url, _MAX_METADATA_BYTES, allowed_hosts={"repo.packagist.org"})
        try:
            document = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Packagist metadata is not valid JSON: {exc}") from exc
        releases = (document.get("packages") or {}).get(package) or []
        wanted = _normalise_version(version)
        for release in releases:
            if _normalise_version(str(release.get("version") or "")) == wanted:
                return release
        raise ValueError(f"Packagist has no exact release {package}@{version}")

    @staticmethod
    def _validate_archive_url(url: str) -> None:
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in _ALLOWED_ARCHIVE_HOSTS:
            raise ValueError(f"archive URL is not on the trusted host allowlist: {url[:200]}")

    @staticmethod
    def _fetch_bytes(
        url: str, limit: int, *, allowed_hosts: set[str] | None = None
    ) -> tuple[bytes, str]:
        parsed = urllib.parse.urlparse(url)
        hosts = allowed_hosts or {(parsed.hostname or "").lower()}
        if parsed.scheme != "https" or (parsed.hostname or "").lower() not in hosts:
            raise ValueError(f"download URL is not allowlisted: {url[:200]}")
        request = urllib.request.Request(url, headers=_UA)
        opener = urllib.request.build_opener(_AllowlistedRedirectHandler(hosts))
        with opener.open(request, timeout=_TIMEOUT_S) as response:
            body = response.read(limit + 1)
            if len(body) > limit:
                raise ValueError(f"download exceeds {limit} bytes")
            return body, response.geturl()

    @staticmethod
    def _extract_zip(archive: bytes, destination: Path) -> dict[str, str]:
        with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
            infos = zipped.infolist()
            if len(infos) > _MAX_ARCHIVE_FILES:
                raise ValueError(f"archive contains more than {_MAX_ARCHIVE_FILES} entries")
            total = sum(info.file_size for info in infos)
            if total > _MAX_UNPACKED_BYTES:
                raise ValueError(f"archive expands beyond {_MAX_UNPACKED_BYTES} bytes")

            paths: list[PurePosixPath] = []
            for info in infos:
                path = _safe_member_path(info.filename.rstrip("/"))
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode):
                    raise ValueError(f"archive contains a symlink: {info.filename}")
                if not info.is_dir():
                    paths.append(path)
            root = _common_root(paths)

            files: dict[str, str] = {}
            for info, original in ((i, _safe_member_path(i.filename.rstrip("/"))) for i in infos if not i.is_dir()):
                relative = PurePosixPath(*original.parts[1:]) if root and original.parts[0] == root else original
                if not relative.parts or not _interesting(relative):
                    continue
                if info.file_size > _MAX_SOURCE_FILE_BYTES:
                    continue
                if len(files) >= _MAX_SOURCE_FILES:
                    raise ValueError(f"archive has more than {_MAX_SOURCE_FILES} supported source files")
                body = zipped.read(info)
                target = destination.joinpath(*relative.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                files[str(relative)] = body.decode("utf-8", errors="replace")
            return files
