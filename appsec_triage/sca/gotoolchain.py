"""The Go release a project is built with, so its standard library is the one checked.

govulncheck and wolfee judge the standard library by the `go` they run, which is the
image's. A project built with Go 1.26.1 checked with the image's 1.26.5 lost every
stdlib advisory fixed in between — 20 of 28 on gf-multisearch. `GOTOOLCHAIN=go1.26.1`
makes `go` fetch and use the project's release for that one process; it is downloaded
through GOPROXY into the module cache, which dies with the job.
"""

from __future__ import annotations

import functools
import logging
import os
import re
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)

_ARG = re.compile(r"^\s*ARG\s+(\w*GO\w*VERSION)\s*=\s*[\"']?(\d+\.\d+(?:\.\d+)?)", re.MULTILINE | re.IGNORECASE)
_FROM_GO = re.compile(r"^\s*FROM\s+(?:--\S+\s+)*\S*?golang:(\S+)", re.MULTILINE | re.IGNORECASE)
_TOOLCHAIN = re.compile(r"^\s*toolchain\s+go(\d+\.\d+(?:\.\d+)?)\s*$", re.MULTILINE)
_GO = re.compile(r"^\s*go\s+(\d+\.\d+(?:\.\d+)?)\s*$", re.MULTILINE)
_SKIP = {"vendor", "node_modules", "testdata", ".git"}


def _release(version: str) -> str:
    """`1.26` / `1.26.1` as the release name `go` expects: go1.26.0 / go1.26.1 (go1.20 before 1.21)."""
    parts = version.split(".")
    if len(parts) == 2:
        return f"go{version}" if int(parts[1]) < 21 else f"go{version}.0"
    return f"go{version}"


def _dockerfiles(root: Path, module: Path) -> list[Path]:
    """Dockerfiles next to the module first, then at the root and one level below it."""
    found: list[Path] = []
    for base, depth in ((module, 0), (root, 1)):
        for directory, dirs, files in os.walk(base):
            level = len(Path(directory).relative_to(base).parts)
            dirs[:] = [] if level >= depth else sorted(d for d in dirs if d not in _SKIP and not d.startswith("."))
            for name in sorted(files):
                if (name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".Dockerfile")) \
                        and Path(directory) / name not in found:
                    found.append(Path(directory) / name)
    return found


def project_release(root: Path, module: Path | None = None) -> tuple[str, str]:
    """(`go1.X.Y`, where it was read) for the module; ("", "") when nothing says.

    The build image in a Dockerfile says what production runs; then go.mod's
    `toolchain`, then its `go` line — the lowest release the module accepts.
    """
    root, module = Path(root), Path(module or root)
    for dockerfile in _dockerfiles(root, module):
        try:
            text = dockerfile.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        args = {name.upper(): value for name, value in _ARG.findall(text)}
        for tag in _FROM_GO.findall(text):
            tag = re.sub(r"\$\{?(\w+)\}?", lambda m: args.get(m.group(1).upper(), m.group(0)), tag)
            if match := re.match(r"(\d+\.\d+(?:\.\d+)?)", tag):
                return _release(match.group(1)), dockerfile.relative_to(root).as_posix()
    try:
        gomod = (module / "go.mod").read_text(encoding="utf-8", errors="replace")
    except OSError:
        return "", ""
    where = (module / "go.mod").relative_to(root).as_posix()
    if match := _TOOLCHAIN.search(gomod):
        return _release(match.group(1)), f"{where} (toolchain)"
    if match := _GO.search(gomod):
        return _release(match.group(1)), f"{where} (go)"
    return "", ""


@functools.lru_cache(maxsize=1)
def local_release() -> str:
    """The image's own Go release, `go1.X.Y`; "" without a go on PATH."""
    try:
        proc = subprocess.run(["go", "env", "GOVERSION"], capture_output=True, text=True, timeout=60,
                              env={**os.environ, "GOTOOLCHAIN": "local"}, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return proc.stdout.strip() if proc.returncode == 0 else ""


def env_for(root: Path, module: Path | None = None) -> dict[str, str]:
    """`GOTOOLCHAIN` for the project's release when it is not the image's; {} otherwise."""
    release, _ = project_release(root, module)
    if not release or release == local_release():
        return {}
    return {"GOTOOLCHAIN": release}
