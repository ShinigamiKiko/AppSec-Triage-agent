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

Composer works the same way. A private Satis or proxy mirrors public packages as
zip files the scan host cannot fetch, but every locked package also names its
source repository and the exact commit: a GitHub one is fetched from GitHub's own
archive of that commit, a package whose source is on a private host is dropped
and named, and the project's `repositories` stop pointing at the mirror.

Every project in the tree is installed, not only the root: a backend at the root and
a frontend in `frontend/` are two projects with two manifests. Measured on OWASP
Juice Shop, whose Angular app lives in `frontend/`: with only the root installed,
CodeQL resolved `ActivatedRoute` 0 times and `DomSanitizer` once in nine calls — its
Angular model works from those types — and both DOM XSS through
`bypassSecurityTrustHtml` went unreported.
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
_COMPOSER_ATTEMPTS = max(1, min(_ATTEMPTS, 3))
_YARN = os.environ.get("APPSEC_YARN", "yarn@1.22.22")

_COPY_SKIP = {".git", "node_modules", ".codeql", "coverage", ".nuxt", ".next"}
# Where a manifest is not a project that ships: installed trees, build output, tests,
# examples and docs. A nested project deeper than this is somebody's fixture.
_PROJECT_SKIP = {"node_modules", "vendor", "dist", "build", "coverage", "test", "tests", "__tests__",
                 "e2e", "cypress", "fixtures", "testdata", "examples", "example", "docs"}
_MAX_PROJECT_DEPTH = 3
_MAX_PROJECTS = 12
_REGISTRY_CONFIG = (".npmrc", ".yarnrc", ".yarnrc.yml", "auth.json")
_PUBLIC_HOSTS = {"github.com", "api.github.com", "codeload.github.com", "gitlab.com",
                 "bitbucket.org", "repo.packagist.org", "packagist.org"}
_GITHUB_REPO = re.compile(r"github\.com[:/]([^/\s]+)/([^/\s]+?)(?:\.git)?/?$")
_COMPOSER_SECTIONS = ("require", "require-dev")
_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")
_NOT_REGISTRY = re.compile(r"^(?:git\+|git:|https?:|file:|link:|workspace:|github:|[\w.-]+/[\w.-]+(?:#|$))")
_TARBALL = re.compile(r"(https?://[^\s\"']+?/)((?:@[^/\s\"'@]+/)?[^/\s\"'@]+/-/[^\s\"'#]+\.tgz)")
_MISSING = (
    re.compile(r"404[^\n]*?GET\s+\S+?/((?:@[^/\s]+(?:/|%2[fF]))?[^/\s@]+)(?:\s|$|/-/)"),
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
    faithful: bool = False
    dropped: list[str] = field(default_factory=list)
    rewritten: int = 0
    problem: str = ""
    unlocked: list[str] = field(default_factory=list)
    """Projects installed without a lock file: their versions were resolved afresh."""

    @property
    def usable(self) -> bool:
        return self.workspace is not None and self.installed > 0

    def note(self, label: str, problem: str) -> None:
        if problem:
            self.problem = "; ".join(p for p in (self.problem, f"{label}: {problem}" if label else problem) if p)


def projects(root: Path, manifest: str) -> list[Path]:
    """Directories under `root` holding `manifest`, the root first.

    An npm or Yarn workspace root installs its members itself, so a root that
    declares `workspaces` stands for the whole tree.
    """
    root = Path(root)
    found = [root] if (root / manifest).is_file() else []
    if manifest == "package.json" and found and _declares_workspaces(root / manifest):
        return found
    for directory, dirnames, _ in os.walk(root):
        current = Path(directory)
        depth = len(current.relative_to(root).parts)
        dirnames[:] = sorted(d for d in dirnames
                             if d.lower() not in _PROJECT_SKIP and not d.startswith(".")
                             and not d.lower().startswith("appsec-out")
                             and not (current / d).is_symlink() and depth < _MAX_PROJECT_DEPTH)
        if current != root and (current / manifest).is_file():
            found.append(current)
            if len(found) >= _MAX_PROJECTS:
                log.warning("more than %d %s projects under %s; installing the first %d",
                            _MAX_PROJECTS, manifest, root, _MAX_PROJECTS)
                break
    return found


def _declares_workspaces(manifest: Path) -> bool:
    try:
        return bool(json.loads(manifest.read_text(encoding="utf-8")).get("workspaces"))
    except (OSError, ValueError, AttributeError):
        return False


def npm_projects(root: Path) -> list[Path]:
    """Projects under `root` with a package.json and no installed node_modules."""
    return [p for p in projects(root, "package.json") if _needs_npm(p)]


def composer_projects(root: Path) -> list[Path]:
    """Projects under `root` with a composer.lock and no installed vendor/."""
    return [p for p in projects(root, "composer.lock") if _needs_composer(p)]


def needs_install(project: Path) -> bool:
    return bool(npm_projects(project) or composer_projects(project))


def _needs_npm(project: Path) -> bool:
    return (project / "package.json").is_file() and not (project / "node_modules").is_dir()


def composer_vendor(project: Path) -> bool:
    """Whether `project/vendor` is an installed Composer tree (not Go's vendored modules).

    Such a tree holds other projects' lock files and bundled assets — phpunit's jQuery,
    a library's own package-lock.json. Scanned as the project, they become hundreds of
    dependencies it does not have; composer.lock is the project's dependency list.
    """
    return (Path(project) / "vendor" / "composer").is_dir()


def _needs_composer(project: Path) -> bool:
    return (project / "composer.lock").is_file() and not (project / "vendor").is_dir()


def _host(url: str) -> str:
    """The host of an https URL or of an scp-style git address (`git@host:path`)."""
    url = str(url or "")
    if "://" in url:
        return url.split("://", 1)[1].split("/", 1)[0].split("@")[-1].split(":")[0].lower()
    if "@" in url and ":" in url:
        return url.split("@", 1)[1].split(":", 1)[0].lower()
    return ""


def rewrite_composer_lock(lock: Path) -> tuple[int, list[str]]:
    """Point every locked package at a public source; drop those only a private host has.

    Returns (entries rewritten, packages dropped). The locked commit stays: a GitHub
    source is fetched as GitHub's zip of exactly that reference.
    """
    data = json.loads(lock.read_text(encoding="utf-8"))
    rewritten, dropped = 0, []
    for section in ("packages", "packages-dev"):
        kept = []
        for package in data.get(section) or []:
            dist = package.get("dist") or {}
            source = package.get("source") or {}
            reference = source.get("reference") or dist.get("reference")
            if dist.get("type") == "path" or (not dist and not source):
                kept.append(package)
                continue
            if _host(dist.get("url", "")) in _PUBLIC_HOSTS:
                kept.append(package)
                continue
            github = _GITHUB_REPO.search(str(source.get("url") or ""))
            if github and reference:
                package["dist"] = {"type": "zip", "reference": reference, "shasum": "",
                                   "url": f"https://codeload.github.com/{github[1]}/{github[2]}"
                                          f"/legacy.zip/{reference}"}
                rewritten += 1
                kept.append(package)
            elif _host(source.get("url", "")) in _PUBLIC_HOSTS and reference:
                package.pop("dist", None)
                rewritten += 1
                kept.append(package)
            else:
                dropped.append(package.get("name", "?"))
        data[section] = kept
    lock.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")
    return rewritten, dropped


def public_composer_manifest(manifest: Path, dropped: list[str]) -> None:
    """The project's composer.json without the private mirror and the dropped packages."""
    data = json.loads(manifest.read_text(encoding="utf-8"))
    for section in _COMPOSER_SECTIONS:
        for name in dropped:
            (data.get(section) or {}).pop(name, None)
    data.pop("repositories", None)
    manifest.write_text(json.dumps(data, indent=4, ensure_ascii=False), encoding="utf-8")


def _installed_composer(vendor: Path) -> int:
    if not vendor.is_dir():
        return 0
    return sum(1 for owner in vendor.iterdir() if owner.is_dir() and owner.name not in ("bin", "composer")
               for package in owner.iterdir() if package.is_dir())


def copy_project(source: Path, workspace: Path) -> None:
    """The source tree minus VCS data and registry configuration.

    An installed node_modules the project brought — restored from a cache or a build —
    is copied too, like vendor/: left out, it was downloaded again in full whenever only
    the Composer tree was missing. Without one at the root, node_modules directories
    elsewhere are leftovers and stay out.
    """
    skip = _COPY_SKIP - {"node_modules"} if (source / "node_modules").is_dir() else _COPY_SKIP

    def ignore(directory: str, names: list[str]) -> set[str]:
        skipped = {n for n in names if n in skip or n.startswith("appsec-out")}
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
    tools: list[str] = []
    for directory in npm_projects(workspace):
        tools.append(_install_npm(directory, result, registry, attempts, timeout_s,
                                  label=_label(workspace, directory)))
    for directory in composer_projects(workspace):
        _install_composer(directory, result, timeout_s, label=_label(workspace, directory),
                          home_base=workspace)
        tools.append("composer")
    result.tool = "+".join(dict.fromkeys(t for t in tools if t))
    result.faithful = bool(tools) and not result.unlocked
    result.workspace = workspace if result.installed else None
    return result


def _label(workspace: Path, directory: Path) -> str:
    """`frontend/` for a nested project, "" for the root — the prefix of what it reports."""
    relative = directory.relative_to(workspace).as_posix()
    return "" if relative == "." else f"{relative}/"


def _install_composer(workspace: Path, result: InstallResult, timeout_s: int, label: str = "",
                      home_base: Path | None = None) -> None:
    rewritten, dropped = rewrite_composer_lock(workspace / "composer.lock")
    result.rewritten += rewritten
    result.dropped += [f"{label}{name} (исходники только на приватном хосте)" for name in dropped]
    if (workspace / "composer.json").is_file():
        public_composer_manifest(workspace / "composer.json", dropped)
    # Beside the copy, never inside it: a nested project's parent is the scanned tree.
    base = home_base or workspace
    home = base.parent / f".{base.name}-composer-home"
    shutil.rmtree(home, ignore_errors=True)
    env = {**os.environ, "COMPOSER_HOME": str(home), "COMPOSER_NO_INTERACTION": "1",
           "COMPOSER_ALLOW_SUPERUSER": "1", "COMPOSER_NO_AUDIT": "1"}
    if cache := os.environ.get("APPSEC_CACHE_DIR", "").strip():
        env["COMPOSER_CACHE_DIR"] = str(Path(cache) / "composer")
    run = dict(cwd=workspace, capture_output=True, text=True, env=env, encoding="utf-8",
               errors="replace", check=False)
    autoload = workspace / "vendor" / "autoload.php"
    proc = None
    try:
        subprocess.run(["composer", "config", "--global", "audit.block-insecure", "false"],
                       timeout=60, **run)
        for attempt in range(1, _COMPOSER_ATTEMPTS + 1):
            try:
                proc = subprocess.run(["composer", "install", "--no-interaction", "--no-progress",
                                       "--prefer-dist", "--ignore-platform-reqs", "--no-scripts",
                                       "--no-plugins", "--no-dev"], timeout=timeout_s, **run)
            except subprocess.TimeoutExpired:
                proc = None
                log.warning("composer install did not finish in %ds (attempt %d of %d)",
                            timeout_s, attempt, _COMPOSER_ATTEMPTS)
                continue
            if proc.returncode == 0 or autoload.is_file():
                break
            log.warning("composer install failed (attempt %d of %d), trying again: %s", attempt,
                        _COMPOSER_ATTEMPTS, f"{proc.stdout}\n{proc.stderr}".strip().splitlines()[-1:])
    except subprocess.TimeoutExpired:
        result.note(label, "composer config не уложился в 60s")
        return
    except OSError as exc:
        result.note(label, f"composer не запустился: {exc}")
        return
    if proc is None:
        result.installed += _installed_composer(workspace / "vendor")
        result.note(label, f"composer не уложился в {timeout_s}s ни в одной из {_COMPOSER_ATTEMPTS} попыток")
        return
    installed = _installed_composer(workspace / "vendor")
    result.installed += installed
    if proc.returncode != 0:
        lines = f"{proc.stdout}\n{proc.stderr}".strip().splitlines()
        said = [line.strip() for line in lines if re.search(r"\b(?:error|failed|could not)\b", line, re.I)]
        result.note(label, f"composer завершился с кодом {proc.returncode}"
                           f"{f' (поставлено пакетов: {installed})' if installed else ''}: "
                           f"{chr(10).join(said[:3] or lines[-4:])[:400]}")


def _install_npm(workspace: Path, result: InstallResult, registry: str, attempts: int,
                 timeout_s: int, label: str = "") -> str:
    """Install one npm/Yarn project; returns the tool it used."""
    manifest = workspace / "package.json"
    result.dropped += [f"{label}{item}" for item in drop_unregistered(manifest)]
    result.rewritten += (rewrite_lock(workspace / "yarn.lock", registry)
                         + rewrite_lock(workspace / "package-lock.json", registry))
    if not any((workspace / name).is_file() for name in ("yarn.lock", "package-lock.json")):
        result.unlocked.append(label or "./")
    tool, argv = _command(workspace, registry)
    env = {**os.environ, "npm_config_registry": registry, "YARN_REGISTRY": registry,
           "npm_config_userconfig": os.devnull}

    problem = ""
    for attempt in range(1, max(1, attempts) + 1):
        try:
            proc = subprocess.run(argv, cwd=workspace, capture_output=True, text=True,
                                  timeout=timeout_s, env=env, encoding="utf-8", errors="replace",
                                  check=False)
        except subprocess.TimeoutExpired:
            problem = f"{tool} не уложился в {timeout_s}s"
            break
        except OSError as exc:
            problem = f"{tool} не запустился: {exc}"
            break
        output = f"{proc.stdout}\n{proc.stderr}"
        if proc.returncode == 0:
            break
        missing = missing_packages(output)
        removable = {name for name in missing if drop_dependency(manifest, name)}
        if not removable:
            lines = output.strip().splitlines()
            said = [line.strip() for line in lines if re.search(r"\berr(?:or)?\b", line, re.I)
                    and not line.lstrip().startswith("at ")]
            reason = "\n".join(said[:3] or lines[-4:])
            problem = f"{tool} завершился с кодом {proc.returncode}: {reason[:400]}"
            break
        result.dropped += [f"{label}{name} (нет в публичном реестре)" for name in sorted(removable)]
        log.info("attempt %d: dropped %s, retrying", attempt, ", ".join(sorted(removable)))

    result.note(label, problem)
    installed = workspace / "node_modules"
    result.installed += sum(1 for _ in installed.iterdir()) if installed.is_dir() else 0
    return tool
