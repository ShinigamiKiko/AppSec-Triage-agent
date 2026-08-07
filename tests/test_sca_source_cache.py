from __future__ import annotations

import io
import stat
import zipfile

import pytest

from appsec_triage.sca.source_cache import PackageSourceCache, SourceSnapshot


def _zip(entries: dict[str, bytes], *, symlink: str | None = None) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, body in entries.items():
            archive.writestr(name, body)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
    return output.getvalue()


def test_one_download_serves_multiple_cves_for_the_same_package(monkeypatch):
    cache = PackageSourceCache()
    calls = []

    def download(ecosystem, package, version):
        calls.append((ecosystem, package, version))
        return SourceSnapshot(
            ecosystem, package, version, {"src/A.php": "<?php"},
            source_url="https://github.com/acme/lib/archive/1.0.0.zip")

    monkeypatch.setattr(cache, "_download", download)
    first = cache.snapshot("composer", "acme/lib", "1.0.0")
    second = cache.snapshot("composer", "acme/lib", "1.0.0")

    assert len(calls) == 1
    assert first.cache_status == "downloaded"
    assert second.cache_status == "cache_hit"
    assert cache.stats() == {"packages": 1, "downloads": 1, "cache_hits": 1, "failures": 0}
    cache.close()


@pytest.mark.parametrize("name", ["../escape.php", "/absolute.php", "root/../../escape.php", "root\\escape.php"])
def test_safe_extraction_rejects_path_traversal(tmp_path, name):
    with pytest.raises(ValueError, match="unsafe archive member path"):
        PackageSourceCache._extract_zip(_zip({name: b"<?php"}), tmp_path)


def test_safe_extraction_rejects_symlinks(tmp_path):
    with pytest.raises(ValueError, match="symlink"):
        PackageSourceCache._extract_zip(_zip({}, symlink="root/link.php"), tmp_path)


def test_safe_extraction_strips_archive_root(tmp_path):
    files = PackageSourceCache._extract_zip(
        _zip({"repo-abc/src/A.php": b"<?php function a() {}"}), tmp_path)

    assert list(files) == ["src/A.php"]
    assert (tmp_path / "src" / "A.php").is_file()
