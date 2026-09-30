"""A package's own source, read from the installed tree and never fetched."""

from __future__ import annotations

import functools
import logging
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_CODE_SUFFIXES = {".php", ".js", ".mjs", ".cjs", ".ts", ".py", ".rb", ".go", ".java"}
_SKIP_PARTS = {"test", "tests", "spec", "specs", "fixtures", "__tests__", "docs",
               "node_modules"}
_MAX_FILES = 4000
_MAX_BYTES = 400_000

_LAYOUTS: dict[str, tuple] = {
    "composer": ("vendor/{name}",),
    "packagist": ("vendor/{name}",),
    "php": ("vendor/{name}",),
    "npm": ("node_modules/{name}",),
    "node": ("node_modules/{name}",),
    "javascript": ("node_modules/{name}",),
    "pypi": ("{venv}/lib/python*/site-packages/{flat}",
             ".venv/lib/python*/site-packages/{flat}",
             "venv/lib/python*/site-packages/{flat}"),
    "python": ("{venv}/lib/python*/site-packages/{flat}",
               ".venv/lib/python*/site-packages/{flat}"),
    "go": ("vendor/{name}", lambda name, version: _go_module_cache_dir(name, version)),
    "golang": ("vendor/{name}", lambda name, version: _go_module_cache_dir(name, version)),
}


def supported(ecosystem: str | None) -> bool:
    return (ecosystem or "").strip().lower() in _LAYOUTS


def _interesting(path: Path) -> bool:
    parts = {p.lower() for p in path.parts}
    if parts & _SKIP_PARTS:
        return False
    return path.suffix.lower() in _CODE_SUFFIXES


def _escape_go_module(name: str) -> str:
    """Go's module-cache spelling: an upper-case letter becomes `!` + its lower."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), name)


def _go_module_cache_dir(name: str, version: str) -> Path | None:
    """The versioned source directory Go already unpacked, or None."""
    if not version:
        return None
    ver = version if version.startswith("v") else f"v{version}"
    candidate = go_mod_cache() / f"{_escape_go_module(name)}@{_escape_go_module(ver)}"
    return candidate if candidate.is_dir() else None


def go_mod_cache() -> Path:
    """Where Go unpacks modules: GOMODCACHE, else what `go env` says, else Go's default."""
    configured = os.environ.get("GOMODCACHE")
    return Path(configured) if configured else _go_env_mod_cache()


@functools.lru_cache(maxsize=1)
def _go_env_mod_cache() -> Path:
    try:
        proc = subprocess.run(["go", "env", "GOMODCACHE"], capture_output=True, text=True, timeout=30,
                              env={**os.environ, "GOTOOLCHAIN": "local"})
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    gopath = (os.environ.get("GOPATH") or "").split(os.pathsep)[0]
    return (Path(gopath) if gopath else Path.home() / "go") / "pkg" / "mod"


def _unescape_go_module(name: str) -> str:
    return re.sub(r"!([a-z])", lambda m: m.group(1).upper(), name)


def _in_go_cache(path: Path | str) -> tuple[Path, tuple[str, ...], int] | None:
    """(cache, parts below it, index of the `module@version` part) for a module file.

    A path relative to the cache (`github.com/jackc/pgx/v5@v5.6.0/pgproto3/bind.go`)
    counts too: that is how a module's files are shown."""
    path = Path(str(path).replace("\\", "/"))
    cache = go_mod_cache()
    parts: tuple[str, ...] = ()
    if path.is_absolute():
        for base in (cache, cache.resolve()):
            try:
                parts, cache = path.relative_to(base).parts, base
                break
            except ValueError:
                continue
    elif path.parts and "." in path.parts[0]:
        parts = path.parts
    if not parts or parts[0] == "cache" or ".." in parts:
        return None
    for index, part in enumerate(parts):
        if "@" in part:
            return cache, parts, index
    return None


def go_module_root(path: Path | str) -> Path | None:
    """The module directory a path in the module cache lies in; None outside the cache."""
    found = _in_go_cache(path)
    return found[0].joinpath(*found[1][:found[2] + 1]) if found else None


def go_module_of(path: Path | str) -> str | None:
    """`module@version` for a file in the module cache; None for anything else."""
    found = _in_go_cache(path)
    return _unescape_go_module("/".join(found[1][:found[2] + 1])) if found else None


def go_cache_path(path: Path | str) -> str | None:
    """A module file's path below the module cache, as it is shown; None for anything else."""
    found = _in_go_cache(path)
    return "/".join(found[1]) if found else None


@dataclass(frozen=True, slots=True)
class GoModule:
    """One module the project requires, as Go selected it."""

    path: str
    version: str
    directory: Path
    note: str = ""

    def label(self, sub: str = "") -> str:
        name = f"{self.path}/{sub}" if sub else self.path
        return " ".join(part for part in (name, self.version, self.note) if part)


@dataclass(slots=True)
class GoLookup:
    """The project's modules a requested name means, or why it means none."""

    modules: list[tuple[GoModule, str]] = field(default_factory=list)
    problem: str = ""
    go_project: bool = False


_GO_SKIP_DIRS = {"vendor", "testdata", "node_modules"}
_GO_REQUIRE = re.compile(r"^(\S+)\s+(v\S+)$")
_GO_MAX_MATCHES = 3


def _go_mod_files(root: Path) -> list[Path]:
    found = []
    for directory, dirs, files in os.walk(root):
        dirs[:] = sorted(d for d in dirs if d not in _GO_SKIP_DIRS and not d.startswith(".")
                         and not d.startswith("appsec-out"))
        if "go.mod" in files:
            found.append(Path(directory) / "go.mod")
    return found


def _go_directive(text: str, keyword: str) -> list[str]:
    """The entries of one go.mod directive, written once or as a block."""
    out, block = [], False
    for raw in text.splitlines():
        line = raw.split("//", 1)[0].strip()
        if block:
            if line == ")":
                block = False
            elif line:
                out.append(line)
            continue
        if line == keyword or not line.startswith(keyword) or line[len(keyword)] not in " \t(":
            continue
        rest = line[len(keyword):].strip()
        if rest == "(":
            block = True
        elif rest:
            out.append(rest)
    return out


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", version.split("-")[0].split("+")[0]))


def _go_sum_versions(path: Path) -> dict[str, str]:
    """The newest version go.sum holds a source hash for, per module."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    versions: dict[str, list[str]] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and not parts[1].endswith("/go.mod"):
            versions.setdefault(parts[0], []).append(parts[1])
    return {module: max(found, key=_version_key) for module, found in versions.items()}


def go_modules(roots) -> tuple[list[GoModule], set[str]]:
    """Every module the project's go.mod files require, with `replace` applied, and the
    project's own module paths."""
    modules, own = _go_modules(tuple(str(Path(root)) for root in roots), str(go_mod_cache()))
    return list(modules), set(own)


@functools.lru_cache(maxsize=8)
def _go_modules(roots: tuple[str, ...], cache_dir: str) -> tuple[tuple[GoModule, ...], tuple[str, ...]]:
    cache = Path(cache_dir)
    found: dict[tuple[str, str], GoModule] = {}
    own: list[str] = []
    for root in roots:
        for gomod in _go_mod_files(Path(root)):
            try:
                text = gomod.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            own.extend(_go_directive(text, "module")[:1])
            replaced: dict[str, list[str]] = {}
            for line in _go_directive(text, "replace"):
                left, arrow, right = line.partition("=>")
                old, new = left.split(), right.split()
                if arrow and old and new:
                    replaced[old[0]] = new
            required: dict[str, tuple[str, str]] = {}
            for line in _go_directive(text, "require"):
                if match := _GO_REQUIRE.match(line):
                    required[match.group(1)] = (match.group(2), "")
            for module, version in _go_sum_versions(gomod.with_name("go.sum")).items():
                required.setdefault(module, (version, "(from go.sum)"))
            for module, (version, note) in required.items():
                new = replaced.get(module)
                if new and new[0].startswith((".", "/")):
                    item = GoModule(module, "", (gomod.parent / new[0]).resolve(), f"(replace => {new[0]})")
                elif new and len(new) > 1:
                    item = GoModule(module, new[1], cache / f"{_escape_go_module(new[0])}@{_escape_go_module(new[1])}",
                                    f"(replace => {new[0]})")
                else:
                    item = GoModule(module, version, cache / f"{_escape_go_module(module)}@{_escape_go_module(version)}",
                                    note)
                found.setdefault((item.path, item.version), item)
    return tuple(found.values()), tuple(own)


def _go_tails(module: str) -> list[str]:
    """The names a module goes by: its path and every tail of it, with and without the
    major-version suffix — `github.com/jackc/pgx/v5`, `jackc/pgx/v5`, `pgx/v5`, `pgx`."""
    parts = module.lower().split("/")
    tails = {"/".join(parts[i:]) for i in range(len(parts))}
    if len(parts) > 1 and re.fullmatch(r"v\d+", parts[-1]):
        bare = parts[:-1]
        tails |= {"/".join(bare[i:]) for i in range(len(bare))}
    return [tail for tail in tails if tail and not re.fullmatch(r"v\d+", tail)]


def go_lookup(roots, requested: str) -> GoLookup:
    """Which of the project's Go modules a name means.

    The full import path, a package inside a module (`…/pgx/v5/pgproto3`), or a short
    name that ends one (`pgx`, `amqp091-go`). The longest match wins; a short name that
    ends several modules means all of them, up to a few."""
    name = requested.strip().strip("/")
    modules, own = go_modules(roots)
    if not modules and not own:
        return GoLookup()
    lowered = name.lower()
    best, matches = 0, []
    for module in modules:
        for tail in _go_tails(module.path):
            if lowered != tail and not lowered.startswith(tail + "/"):
                continue
            sub = name[len(tail):].strip("/")
            if len(tail) > best:
                best, matches = len(tail), [(module, sub)]
            elif len(tail) == best and all(m is not module for m, _ in matches):
                matches.append((module, sub))
    if not matches and "/" not in name:
        worded = [(m, "") for m in modules
                  if lowered in re.split(r"[-_.]", re.sub(r"/v\d+$", "", m.path.lower()).rsplit("/", 1)[-1])]
        if len(worded) == 1:
            matches = worded
    if matches:
        present = [(m, sub) for m, sub in matches[:_GO_MAX_MATCHES] if m.directory.is_dir()]
        missing = [m for m, _ in matches[:_GO_MAX_MATCHES] if not m.directory.is_dir()]
        if not present:
            return GoLookup(problem=(f"{', '.join(m.label() for m in missing)} is a dependency of this project, "
                                     f"but its source is not in the module cache ({go_mod_cache()})"),
                            go_project=True)
        inside = [(m, sub) for m, sub in present if not sub or (m.directory / sub).is_dir()]
        if not inside:
            return GoLookup(problem=f"{present[0][0].label()} has no package directory «{present[0][1]}»",
                            go_project=True)
        return GoLookup(inside, go_project=True)
    if any(lowered == path.lower() or lowered.startswith(path.lower() + "/") for path in own):
        return GoLookup(problem="that is this project's own module — search without `package`", go_project=True)
    if _go_std(name):
        return GoLookup(problem=("a Go standard library package, not a module this project requires; its "
                                 "source is not searched here — the govulncheck call trace is the evidence "
                                 "for the standard library"), go_project=True)
    words = {w for w in re.split(r"[/.\-_]", lowered) if len(w) >= 3} - {"com", "org", "net", "github", "golang"}
    similar = [m.path for m in modules if words and any(w in m.path.lower() for w in words)][:5]
    return GoLookup(problem=(f"no module «{name}» among the {len(modules)} this project depends on"
                             + (f"; similar: {', '.join(similar)}" if similar else "")), go_project=True)


def _go_std(name: str) -> bool:
    """A standard library import path: its directory is in GOROOT/src."""
    goroot = _go_root()
    return bool(goroot and "." not in name.split("/", 1)[0] and (goroot / "src" / name).is_dir())


@functools.lru_cache(maxsize=1)
def _go_root() -> Path | None:
    try:
        proc = subprocess.run(["go", "env", "GOROOT"], capture_output=True, text=True, timeout=30,
                              env={**os.environ, "GOTOOLCHAIN": "local"})
        if proc.returncode == 0 and proc.stdout.strip():
            return Path(proc.stdout.strip())
    except (OSError, subprocess.SubprocessError):
        pass
    return None


def locate(root: Path | str, ecosystem: str | None, name: str,
           version: str = "") -> Path | None:
    """The installed directory for one package, or None when it is not there."""
    key = (ecosystem or "").strip().lower()
    patterns = _LAYOUTS.get(key)
    if not patterns or not name:
        return None

    root = Path(root)
    flat = name.replace("-", "_").lower()
    for pattern in patterns:
        if callable(pattern):
            found = pattern(name, version)
            if found is not None:
                return found
            continue
        template = pattern.format(name=name, flat=flat, venv=".venv")
        if "*" in template:
            for candidate in sorted(root.glob(template)):
                if candidate.is_dir():
                    return candidate
            continue
        candidate = root / template
        if candidate.is_dir():
            return candidate
    return None


def package_source(
    ecosystem: str | None, name: str, version: str = "", root: Path | str | None = None
) -> dict[str, str]:
    """`{path: text}` for an installed package, or empty when it is not installed."""
    if root is None:
        return {}
    directory = locate(root, ecosystem, name, version)
    if directory is None:
        log.debug("%s %s is not installed under %s", ecosystem, name, root)
        return {}

    files: dict[str, str] = {}
    for path in directory.rglob("*"):
        if len(files) >= _MAX_FILES:
            log.debug("stopped reading %s at %d files", directory, _MAX_FILES)
            break
        if not path.is_file() or not _interesting(path.relative_to(directory)):
            continue
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            files[str(path.relative_to(directory))] = path.read_text(
                encoding="utf-8", errors="replace")
        except OSError:
            continue
    return files
