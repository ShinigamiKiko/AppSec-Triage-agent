"""Install a project's dependencies from the public registry, at the versions it locks.

The bridge into a parent package reads that package's source, and without an
installed tree it has nothing to read: every transitive finding ends as "the
path could not be checked". Installing on the scan host is not the same as
installing on the developer's machine, though:

* the lock file points at a private proxy the scan host cannot reach — but a
  proxy serves public packages under the same `<name>/-/<name>-<version>.tgz`
  path, so rewriting the host keeps the exact locked version;
* a truly private package is not on the public registry at all — it is dropped,
  named in the result, and the rest still installs;
* a dependency given as a git or file URL is not a registry package and is
  dropped the same way.

Versions must be the locked ones. Findings come from the lock file, and the
bridge checks whether a function is declared in the installed version; a fresh
resolution installs newer code than the one that ships and answers for it.

Everything happens in a copy: the source tree is mounted read-only, and the
project's own `.npmrc`/`.yarnrc` would send the install back to the proxy.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

log = logging.getLogger(__name__)

PUBLIC_REGISTRY = os.environ.get("APPSEC_NPM_REGISTRY", "https://registry.npmjs.org")
_TIMEOUT_S = int(os.environ.get("APPSEC_INSTALL_TIMEOUT_S", "900"))
_ATTEMPTS = int(os.environ.get("APPSEC_INSTALL_ATTEMPTS", "4"))
_YARN = os.environ.get("APPSEC_YARN", "yarn@1.22.22")

_COPY_SKIP = {".git", "node_modules", ".codeql", "coverage", ".nuxt", ".next"}
# Registry configuration of the developer's machine points at the private proxy.
_REGISTRY_CONFIG = (".npmrc", ".yarnrc", ".yarnrc.yml")
_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
# A spec that is not a version range: git, a URL, a local path, a workspace link.
_NOT_REGISTRY = re.compile(r"^(?:git\+|git:|https?:|file:|link:|workspace:|github:|[\w.-]+/[\w.-]+(?:#|$))")
# `<registry prefix>/<name>/-/<file>.tgz` — the tail is the same on any npm registry.
_TARBALL = re.compile(r"(https?://[^\s\"']+?/)((?:@[^/\s\"'@]+/)?[^/\s\"'@]+/-/[^\s\"'#]+\.tgz)")
_MISSING = (
    re.compile(r"404[^\n]*?GET\s+\S+?/((?:@[^/\s]+(?:/|%2[fF]))?[^/\s@]+)(?:\s|$|/-/)"),
    # yarn: `error Error: https://…/@scope/name/-/name-1.0.0.tgz: Request failed "404 Not Found"`,
    # with or without a quote before the URL.
    re.compile(r"https?://[^\s\"]+?/((?:@[^/\s\"]+/)?[^/\s\"@]+)/-/[^\s\"]+\.tgz: Request failed \\?\"404"),
    re.compile(r"\"https?://[^\"]+?/((?:@[^/\"]+(?:/|%2[fF]))?[^/\"@:]+): Not found"),
    re.compile(r"No matching version found for ((?:@[^/\s]+/)?[^@\s]+)@"),
    re.compile(r"Couldn't find package \"((?:@[^/\"]+/)?[^@\"]+)@"),
)


@dataclass(slots=True)
class InstallResult:
    workspace: Path | None = None
    tool: str = ""
    installed: int = 0
    faithful: bool = False          # versions taken from the project's lock file
    dropped: list[str] = field(default_factory=list)
    rewritten: int = 0              # lock entries moved from a private host to the public one
    problem: str = ""

    @property
    def usable(self) -> bool:
        return self.workspace is not None and self.installed > 0


def needs_install(project: Path) -> bool:
    return (project / "package.json").is_file() and not (project / "node_modules").is_dir()


def copy_project(source: Path, workspace: Path) -> None:
    """The source tree minus installed trees, VCS data and registry configuration."""
    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = {n for n in names if n in _COPY_SKIP or n.startswith("appsec-out")}
        if Path(directory) == source:
            skipped |= {n for n in names if n in _REGISTRY_CONFIG}
        return skipped

    if workspace.exists():
        shutil.rmtree(workspace)
    shutil.copytree(source, workspace, ignore=ignore, symlinks=True)


def drop_unregistered(manifest: Path) -> list[str]:
    """Remove dependencies that are not registry packages; name what was removed."""
    data = json.loads(manifest.read_text(encoding="utf-8"))
    dropped: list[str] = []
    for section in _SECTIONS:
        for name, spec in list((data.get(section) or {}).items()):
            if isinstance(spec, str) and _NOT_REGISTRY.match(spec.strip()):
                data[section].pop(name)
                dropped.append(f"{name} ({spec.split('#')[0][:60]})")
    if dropped:
        manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return dropped


def drop_dependency(manifest: Path, package: str) -> bool:
    data = json.loads(manifest.read_text(encoding="utf-8"))
    removed = False
    for section in _SECTIONS:
        if package in (data.get(section) or {}):
            data[section].pop(package)
            removed = True
    if removed:
        manifest.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    return removed


def rewrite_lock(lock: Path, registry: str = PUBLIC_REGISTRY) -> int:
    """Point every tarball at the public registry; the version stays as locked."""
    if not lock.is_file():
        return 0
    text = lock.read_text(encoding="utf-8")
    base = registry.rstrip("/") + "/"
    changed = 0

    def swap(match: re.Match) -> str:
        nonlocal changed
        if match.group(1) != base:
            changed += 1
        return base + match.group(2)

    lock.write_text(_TARBALL.sub(swap, text), encoding="utf-8")
    return changed


def missing_packages(output: str) -> set[str]:
    """Package names the registry answered 404 or "no such version" for."""
    found: set[str] = set()
    for pattern in _MISSING:
        for match in pattern.finditer(output or ""):
            name = unquote(match.group(1)).strip().rstrip("/")
            if name and name not in ("-", "npm"):
                found.add(name)
    return found


def _command(workspace: Path, registry: str) -> tuple[str, list[str]]:
    common_npm = [f"--registry={registry}", "--userconfig", os.devnull,
                  "--ignore-scripts", "--no-audit", "--no-fund", "--legacy-peer-deps"]
    if (workspace / "yarn.lock").is_file():
        # yarn keeps the locked versions; --pure-lockfile tolerates the entries of
        # dropped packages instead of failing like --frozen-lockfile would.
        return "yarn", ["npx", "--yes", f"--registry={registry}", _YARN, "install",
                        "--pure-lockfile", "--ignore-scripts", "--non-interactive",
                        "--ignore-engines", "--network-timeout", "120000",
                        "--registry", registry]
    return "npm", ["npm", "install", *common_npm]


def install(source: Path, workspace: Path, *, registry: str = PUBLIC_REGISTRY,
            attempts: int = _ATTEMPTS, timeout_s: int = _TIMEOUT_S) -> InstallResult:
    """Copy `source` to `workspace` and install its dependencies there."""
    result = InstallResult()
    try:
        copy_project(source, workspace)
    except OSError as exc:
        result.problem = f"копия проекта не создана: {exc}"
        return result

    manifest = workspace / "package.json"
    result.dropped += drop_unregistered(manifest)
    result.rewritten = (rewrite_lock(workspace / "yarn.lock", registry)
                        + rewrite_lock(workspace / "package-lock.json", registry))
    result.faithful = any((workspace / name).is_file() for name in ("yarn.lock", "package-lock.json"))
    result.tool, argv = _command(workspace, registry)
    env = {**os.environ, "npm_config_registry": registry, "YARN_REGISTRY": registry,
           "npm_config_userconfig": os.devnull}

    for attempt in range(1, max(1, attempts) + 1):
        try:
            proc = subprocess.run(argv, cwd=workspace, capture_output=True, text=True,
                                  timeout=timeout_s, env=env, encoding="utf-8", errors="replace",
                                  check=False)
        except subprocess.TimeoutExpired:
            result.problem = f"{result.tool} не уложился в {timeout_s}s"
            break
        except OSError as exc:
            result.problem = f"{result.tool} не запустился: {exc}"
            break
        output = f"{proc.stdout}\n{proc.stderr}"
        if proc.returncode == 0:
            result.problem = ""
            break
        missing = missing_packages(output)
        removable = {name for name in missing if drop_dependency(manifest, name)}
        if not removable:
            lines = output.strip().splitlines()
            # The error line, not the stack trace under it.
            said = [line.strip() for line in lines if re.search(r"\berr(?:or)?\b", line, re.I)
                    and not line.lstrip().startswith("at ")]
            reason = "\n".join(said[:3] or lines[-4:])
            result.problem = f"{result.tool} завершился с кодом {proc.returncode}: {reason[:400]}"
            break
        result.dropped += [f"{name} (нет в публичном реестре)" for name in sorted(removable)]
        log.info("attempt %d: dropped %s, retrying", attempt, ", ".join(sorted(removable)))

    installed = workspace / "node_modules"
    result.installed = sum(1 for _ in installed.iterdir()) if installed.is_dir() else 0
    result.workspace = workspace if result.installed else None
    return result
