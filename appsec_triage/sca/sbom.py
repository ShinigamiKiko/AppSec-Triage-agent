"""The dependency graph from cdxgen, for every ecosystem at once."""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote

log = logging.getLogger(__name__)

# Сколько ждать cdxgen. Шестисот секунд хватает, пока он читает только
# манифесты и лок-файлы. С установленным деревом (на landing-develop это 892
# пакета) рекурсивный обход по смонтированному диску Windows в них не уложился,
# и SBOM вышел пустым — то есть SCA-часть прогона потерялась целиком. Значение
# настраивается, потому что зависит не от проекта, а от того, где он лежит.
_TIMEOUT_S = int(os.environ.get("APPSEC_SBOM_TIMEOUT_S", "600"))

_PURL_ECOSYSTEM = {
    "composer": "composer", "npm": "npm", "pypi": "pypi", "golang": "go",
    "maven": "maven", "nuget": "nuget", "gem": "rubygems", "cargo": "cargo",
}


def available() -> str | None:
    """Path to cdxgen, or None."""
    return shutil.which("cdxgen")


def parse_purl(purl: str) -> tuple[str, str, str]:
    """(ecosystem, name, version) from a package URL."""
    if not purl.startswith("pkg:"):
        return "", "", ""
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    kind, _, rest = body.partition("/")
    name, _, version = rest.rpartition("@")
    if not name:
        name, version = rest, ""
    return _PURL_ECOSYSTEM.get(kind.lower(), kind.lower()), unquote(name), unquote(version)


def load(path: Path | str) -> tuple[dict | None, str]:
    """An SBOM produced earlier in the run, so cdxgen is not asked twice."""
    path = Path(path)
    if not path.is_file():
        return None, f"SBOM не найден: {path}"
    try:
        return json.loads(path.read_text(encoding="utf-8")), ""
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"SBOM нечитаем ({path}): {exc}"


def generate(project: Path, *, timeout_s: int = _TIMEOUT_S) -> tuple[dict | None, str]:
    """Run cdxgen over `project`."""
    exe = available()
    if not exe:
        return None, "cdxgen не установлен — граф зависимостей недоступен"

    with tempfile.TemporaryDirectory() as work:
        out = Path(work) / "sbom.json"
        argv = [exe, "-r", "-o", str(out), "--no-install-deps", str(project)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout_s, encoding="utf-8", errors="replace", check=False)
        except subprocess.TimeoutExpired:
            return None, f"cdxgen не уложился в {timeout_s}s"
        except OSError as exc:
            return None, f"cdxgen не запустился: {exc}"

        if not out.exists():
            tail = "\n".join((proc.stderr or proc.stdout or "").strip().splitlines()[-4:])
            return None, f"cdxgen не создал SBOM (код {proc.returncode}): {tail[:300]}"
        try:
            return json.loads(out.read_text(encoding="utf-8")), ""
        except (OSError, json.JSONDecodeError) as exc:
            return None, f"SBOM от cdxgen нечитаем: {exc}"


def read(path: Path) -> tuple[dict | None, str]:
    """An SBOM produced elsewhere — a pipeline stage, another job."""
    try:
        return json.loads(Path(path).read_text(encoding="utf-8")), ""
    except (OSError, json.JSONDecodeError) as exc:
        return None, f"SBOM {path} не прочитан: {exc}"


def components(sbom: dict) -> dict[str, dict]:
    """`bom-ref` -> {ecosystem, name, version, scope}, for the whole document."""
    out: dict[str, dict] = {}

    def walk(items):
        for item in items or []:
            ref = item.get("bom-ref") or item.get("purl") or ""
            ecosystem, name, version = parse_purl(item.get("purl") or "")
            if ref and name:
                out[ref] = {
                    "ecosystem": ecosystem,
                    "name": name,
                    "version": version or str(item.get("version", "")),
                    "dev": str(item.get("scope", "")).lower() == "excluded",
                }
            walk(item.get("components"))

    walk(sbom.get("components"))
    return out


def edges(sbom: dict) -> dict[str, list[str]]:
    """`bom-ref` -> the refs it depends on."""
    return {
        entry.get("ref", ""): list(entry.get("dependsOn") or [])
        for entry in sbom.get("dependencies") or []
        if entry.get("ref")
    }


def root_ref(sbom: dict) -> str:
    """The component the SBOM is about — the project itself."""
    metadata = sbom.get("metadata") or {}
    component = metadata.get("component") or {}
    return component.get("bom-ref") or component.get("purl") or ""
