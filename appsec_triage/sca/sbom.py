"""The dependency graph from cdxgen, for every ecosystem at once.

Writing a lockfile parser per ecosystem does not end: composer, npm, yarn, pnpm,
pip, poetry, uv, go.mod, gradle, each with versions and quirks. cdxgen already
does exactly that and emits CycloneDX, which states both the resolved component
list and the `dependsOn` edges — which is all the graph needs.

Two properties matter for this pipeline and both hold: it reads manifests and
lockfiles rather than installing anything, and it names components by purl, so
`pkg:composer/twig/twig@3.3.8` and `pkg:npm/lodash@4.17.15` come back in one
shape.

A failure here is reported, never smoothed over. Without the graph a transitive
package cannot be told from a direct one, and calling everything direct would
produce upgrade advice that does not work.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import unquote

log = logging.getLogger(__name__)

_TIMEOUT_S = 600

_PURL_ECOSYSTEM = {
    "composer": "composer", "npm": "npm", "pypi": "pypi", "golang": "go",
    "maven": "maven", "nuget": "nuget", "gem": "rubygems", "cargo": "cargo",
}


def available() -> str | None:
    """Path to cdxgen, or None. Absence is a normal state, not an error."""
    return shutil.which("cdxgen")


def parse_purl(purl: str) -> tuple[str, str, str]:
    """(ecosystem, name, version) from a package URL.

    Namespaced names differ per ecosystem — `pkg:composer/twig/twig` is one
    package called `twig/twig`, `pkg:npm/%40scope/pkg` is `@scope/pkg` — and
    losing the namespace was measured to break advisory lookup silently: OSV
    returned nothing for "guzzle" where "guzzlehttp/guzzle" has dozens.
    """
    if not purl.startswith("pkg:"):
        return "", "", ""
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    kind, _, rest = body.partition("/")
    name, _, version = rest.rpartition("@")
    if not name:
        name, version = rest, ""
    return _PURL_ECOSYSTEM.get(kind.lower(), kind.lower()), unquote(name), unquote(version)


def generate(project: Path, *, timeout_s: int = _TIMEOUT_S) -> tuple[dict | None, str]:
    """Run cdxgen over `project`. Returns (sbom, problem).

    `--no-install-deps` is not optional here: the project being scanned is the
    user's checkout, and a tool that installs into it has changed what it was
    asked to describe.
    """
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
