"""Who pulled a vulnerable package in, and what upgrading it actually means."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

from . import sbom as sbom_mod

log = logging.getLogger(__name__)

_MANIFEST = {
    "composer": "composer.json", "packagist": "composer.json", "php": "composer.json",
    "npm": "package.json", "node": "package.json", "javascript": "package.json",
    "pypi": "requirements.txt / pyproject.toml", "python": "requirements.txt / pyproject.toml",
    "go": "go.mod", "golang": "go.mod",
    "maven": "pom.xml", "java": "pom.xml",
    "nuget": "the .csproj", "rubygems": "Gemfile", "cargo": "Cargo.toml",
}

_OVERRIDE = {
    "composer": "явный conflict в composer.json",
    "npm": "overrides в package.json",
    "node": "overrides в package.json",
    "javascript": "overrides в package.json",
    "go": "директива replace в go.mod",
    "golang": "директива replace в go.mod",
    "pypi": "закрепление версии в requirements.txt",
    "python": "закрепление версии в requirements.txt",
}


_SKIP_DIRS = {"node_modules", "vendor", ".git", "dist", "build", ".venv", "venv"}
_MAX_MANIFESTS = 100
_PY_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:[<>=!~\[;].*)?$")


def _manifests(root: Path, name: str) -> list[Path]:
    """Every manifest the project owns, workspaces included, installed trees excluded."""
    found: list[Path] = []
    stack = [root]
    while stack and len(found) < _MAX_MANIFESTS:
        current = stack.pop()
        try:
            entries = list(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_dir():
                if entry.name not in _SKIP_DIRS and not entry.name.startswith("."):
                    stack.append(entry)
            elif entry.name == name:
                found.append(entry)
    return found


def _json_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def declared_dependencies(root: Path) -> tuple[set[str], set[str]] | None:
    """Packages the project's own manifests ask for: (prod, dev), lowercase.

    The SBOM cannot answer this on its own: without an installed tree cdxgen reads
    the lock file, where every resolved package hangs off the root component, and
    then every transitive package looks direct.
    """
    prod: set[str] = set()
    dev: set[str] = set()
    seen_manifest = False

    for path in _manifests(root, "package.json"):
        data = _json_manifest(path)
        if not data:
            continue
        seen_manifest = True
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            prod.update(k.lower() for k in (data.get(section) or {}))
        dev.update(k.lower() for k in (data.get("devDependencies") or {}))

    for path in _manifests(root, "composer.json"):
        data = _json_manifest(path)
        if not data:
            continue
        seen_manifest = True
        prod.update(k.lower() for k in (data.get("require") or {})
                    if "/" in k)
        dev.update(k.lower() for k in (data.get("require-dev") or {}) if "/" in k)

    for path in _manifests(root, "go.mod"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen_manifest = True
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("require "):
                line = line[len("require "):].strip()
            if not line or line.startswith(("//", "module ", "go ", "replace", "exclude", ")", "(")):
                continue
            if "// indirect" in line:
                continue
            parts = line.split()
            if len(parts) >= 2 and "." in parts[0]:
                prod.add(parts[0].lower())

    for path in _manifests(root, "requirements.txt"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        seen_manifest = True
        for line in text.splitlines():
            if line.strip().startswith(("#", "-")):
                continue
            match = _PY_NAME.match(line.split("#")[0])
            if match:
                prod.add(match.group(1).lower())

    if not seen_manifest:
        return None
    return prod, dev


@dataclass(slots=True)
class Node:
    name: str
    version: str = ""
    dev: bool = False
    requires: dict[str, str] = field(default_factory=dict)
    ecosystem: str = ""


@dataclass(slots=True)
class Introduction:
    """One way a package ends up installed."""

    path: list[str]

    @property
    def direct_parent(self) -> str:
        """The package that requires the vulnerable one — the one that calls it."""
        return self.path[-2] if len(self.path) >= 2 else ""

    @property
    def root_requirement(self) -> str:
        """What the project itself asked for, and what it can upgrade."""
        return self.path[0] if self.path else ""

    def describe(self) -> str:
        return " -> ".join(self.path)


@dataclass(slots=True)
class Placement:
    """Where one package sits in the project's dependency graph."""

    package: str
    direct: bool = False
    dev_only: bool = False
    in_graph: bool = False
    introductions: list[Introduction] = field(default_factory=list)
    ecosystem: str = ""
    problem: str = ""

    @property
    def known(self) -> bool:
        return self.direct or bool(self.introductions)

    @property
    def parents(self) -> list[str]:
        seen: list[str] = []
        for intro in self.introductions:
            parent = intro.direct_parent
            if parent and parent not in seen:
                seen.append(parent)
        return seen

    def describe(self) -> str:
        if self.problem:
            return self.problem
        if self.direct:
            return "прямая зависимость проекта"
        if not self.introductions:
            if self.in_graph:
                return ("транзитивная: ни в одном манифесте проекта не объявлена, "
                        "но цепочку установки восстановить нечем — "
                        "в SBOM нет рёбер между пакетами")
            return "пакет не найден в графе зависимостей"
        shortest = min(self.introductions, key=lambda i: len(i.path))
        extra = (f" (и ещё {len(self.introductions) - 1} путь(ей))"
                 if len(self.introductions) > 1 else "")
        return f"транзитивная, приходит через {shortest.describe()}{extra}"

    def upgrade_note(self) -> str:
        """What the developer can actually change, in this ecosystem's terms."""
        key = (self.ecosystem or "").strip().lower()
        manifest = _MANIFEST.get(key, "манифесте проекта")
        if self.direct:
            return f"обновляется напрямую в {manifest}"
        if not self.introductions:
            return (f"в {manifest} не объявлена — обновляется вместе с тем пакетом, "
                    "который её тянет") if self.in_graph else ""
        roots = sorted({i.root_requirement for i in self.introductions if i.root_requirement})
        parents = ", ".join(self.parents[:3])
        override = _OVERRIDE.get(key, f"закрепление версии в {manifest}")
        return (f"версия задана родителем ({parents}); напрямую не обновить — "
                f"нужна новая версия {', '.join(roots[:3])} либо {override}")


def _yarn_v1_nodes(text: str) -> dict[str, Node]:
    """`yarn.lock` v1: one block per resolved version, with its `dependencies:` list.

    Keyed by name, as the rest of the graph is; a package resolved to several
    versions keeps the union of their edges, which is what reachability needs.
    """
    nodes: dict[str, Node] = {}
    current: Node | None = None
    section = ""
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw.startswith(" "):
            spec = raw.rstrip(":").split(",")[0].strip().strip('"')
            name = spec[:spec.rfind("@")] if spec.rfind("@") > 0 else spec
            name = name.lower()
            current = nodes.setdefault(name, Node(name, "", False, {}, "npm"))
            section = ""
            continue
        if current is None:
            continue
        stripped = raw.strip()
        indent = len(raw) - len(raw.lstrip())
        if indent == 2:
            section = stripped.rstrip(":") if stripped.endswith(":") else ""
            if stripped.startswith("version "):
                current.version = current.version or stripped.split(" ", 1)[1].strip('"')
            continue
        if indent >= 4 and section in ("dependencies", "optionalDependencies"):
            dep = stripped.split(" ", 1)[0].strip('"').lower()
            if dep:
                current.requires.setdefault(dep, "")
    return nodes


def _berry_nodes(text: str) -> dict[str, Node]:
    """Yarn 2+ (`__metadata:`), YAML with `name@npm:range` keys."""
    import yaml

    try:
        data = yaml.safe_load(text) or {}
    except yaml.YAMLError:
        return {}
    nodes: dict[str, Node] = {}
    for key, entry in data.items():
        if key == "__metadata" or not isinstance(entry, dict):
            continue
        spec = str(key).split(",")[0].strip()
        name = spec[:spec.rfind("@")] if spec.rfind("@") > 0 else spec
        node = nodes.setdefault(name.lower(), Node(name.lower(), str(entry.get("version", "")), False, {}, "npm"))
        for dep in (entry.get("dependencies") or {}):
            node.requires.setdefault(str(dep).lower(), "")
    return nodes


def _package_lock_nodes(data: dict) -> dict[str, Node]:
    """npm lockfile v2/v3 (`packages`), or v1 (`dependencies`, nested)."""
    nodes: dict[str, Node] = {}
    for key, meta in (data.get("packages") or {}).items():
        if not key or not isinstance(meta, dict):
            continue
        name = (meta.get("name") or key.split("node_modules/")[-1]).lower()
        node = nodes.setdefault(name, Node(name, str(meta.get("version", "")), bool(meta.get("dev")), {}, "npm"))
        for section in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dep in (meta.get(section) or {}):
                node.requires.setdefault(dep.lower(), "")

    def walk(deps: dict) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict):
                continue
            node = nodes.setdefault(name.lower(), Node(name.lower(), str(meta.get("version", "")),
                                                       bool(meta.get("dev")), {}, "npm"))
            for dep in (meta.get("requires") or {}):
                node.requires.setdefault(dep.lower(), "")
            walk(meta.get("dependencies") or {})

    if not nodes:
        walk(data.get("dependencies") or {})
    return nodes


def lockfile_nodes(root: Path) -> dict[str, Node]:
    """Resolved packages and edges straight from the project's lock file, when there is one."""
    root = Path(root)
    lock = root / "yarn.lock"
    if lock.is_file():
        text = lock.read_text(encoding="utf-8", errors="replace")
        return _berry_nodes(text) if "__metadata:" in text else _yarn_v1_nodes(text)
    lock = root / "package-lock.json"
    if lock.is_file():
        try:
            return _package_lock_nodes(json.loads(lock.read_text(encoding="utf-8", errors="replace")))
        except ValueError:
            return {}
    return {}


class DependencyGraph:
    """Resolved packages and their edges, as cdxgen reported them."""

    def __init__(self, nodes: dict[str, Node], roots: set[str], dev_roots: set[str]) -> None:
        self.problem = ""
        self._nodes = nodes
        self._roots = roots
        self._dev_roots = dev_roots
        self._parents: dict[str, set[str]] = {}
        for node in nodes.values():
            for requirement in node.requires:
                self._parents.setdefault(requirement, set()).add(node.name)

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def usable(self) -> bool:
        return bool(self._nodes)

    @classmethod
    def empty(cls) -> DependencyGraph:
        return cls({}, set(), set())

    @classmethod
    def from_project(cls, root: Path | str, document: dict | None = None) -> DependencyGraph:
        """cdxgen, and nothing else — or the SBOM the run already produced."""
        root = Path(root)
        if document is not None:
            graph = cls._from_sbom(document)
            graph.trust_manifests(root)
            graph.adopt_lockfile_edges(root)
            log.info("dependency graph from the run's SBOM: %d components", len(graph))
            return graph
        if not sbom_mod.available():
            if (from_lock := cls.from_lockfile(root)) is not None:
                return from_lock
            graph = cls.empty()
            graph.problem = ("cdxgen не установлен — граф зависимостей построить нечем, "
                             "прямые и транзитивные пакеты не различить")
            log.warning("%s", graph.problem)
            return graph

        document, problem = sbom_mod.generate(root)
        if document is None:
            graph = cls.empty()
            graph.problem = problem
            log.warning("%s", problem)
            return graph

        graph = cls._from_sbom(document)
        if not graph.usable:
            graph.problem = f"cdxgen отработал, но компонентов в SBOM нет ({root})"
            log.warning("%s", graph.problem)
            return graph
        graph.trust_manifests(root)
        graph.adopt_lockfile_edges(root)
        log.info("dependency graph from cdxgen: %d components, %d direct",
                 len(graph), len(graph._roots) + len(graph._dev_roots))
        return graph

    def trust_manifests(self, root: Path) -> None:
        """Let the project's manifests decide which packages are direct.

        cdxgen's root edges are only as good as the tree it read: from a lock file
        alone every package hangs off the root. The manifests say what the project
        actually asked for, so they win whenever they exist.
        """
        declared = declared_dependencies(root)
        if declared is None:
            return
        prod, dev = declared
        if not (prod or dev):
            return
        known_prod = {name for name in prod if name in self._nodes}
        known_dev = {name for name in dev if name in self._nodes} - known_prod
        if not (known_prod or known_dev):
            log.warning("манифесты проекта не пересекаются с SBOM — корни оставлены от cdxgen")
            return
        dropped = len((self._roots | self._dev_roots) - known_prod - known_dev)
        self._roots, self._dev_roots = known_prod, known_dev
        if dropped:
            log.info("корни уточнены по манифестам: %d пакетов переведены в транзитивные",
                     dropped)

    @classmethod
    def from_lockfile(cls, root: Path | str) -> DependencyGraph | None:
        """The graph from the lock file and the manifests alone, without cdxgen."""
        root = Path(root)
        nodes = lockfile_nodes(root)
        declared = declared_dependencies(root)
        if not nodes or declared is None:
            return None
        prod, dev = declared
        graph = cls(nodes, {p for p in prod if p in nodes}, {d for d in dev - prod if d in nodes})
        log.info("dependency graph from the lock file: %d packages", len(graph))
        return graph

    def adopt_lockfile_edges(self, root: Path) -> None:
        """Take the edges from the lock file when the SBOM brought none.

        Without an installed tree cdxgen can hang every package off the root;
        then nothing is transitive and nothing can be told apart as dev-only.
        """
        if any(node.requires for node in self._nodes.values()):
            return
        nodes = lockfile_nodes(root)
        if not nodes:
            return
        for name, node in nodes.items():
            if name in self._nodes:
                self._nodes[name].requires = dict(node.requires)
            else:
                self._nodes[name] = node
        self._parents = {}
        for node in self._nodes.values():
            for requirement in node.requires:
                self._parents.setdefault(requirement, set()).add(node.name)
        log.info("рёбра графа зависимостей взяты из lock-файла (%d пакетов)", len(nodes))

    def _reach(self, starts: set[str]) -> set[str]:
        seen = {s for s in starts if s in self._nodes}
        stack = list(seen)
        while stack:
            for child in self._nodes[stack.pop()].requires:
                if child in self._nodes and child not in seen:
                    seen.add(child)
                    stack.append(child)
        return seen

    def scope(self, package: str) -> str:
        """`runtime` when some production dependency pulls the package in, `dev` when only
        development dependencies do, `unknown` when the graph cannot tell."""
        if not (self._roots or self._dev_roots):
            return "unknown"
        cache = getattr(self, "_scope_cache", None)
        if cache is None:
            cache = (self._reach(self._roots), self._reach(self._dev_roots))
            self._scope_cache = cache
        prod, dev = cache
        key = package.lower()
        if key in prod:
            return "runtime"
        if key in dev:
            return "dev"
        return "unknown"

    def roots_of(self, package: str) -> set[str]:
        """The project's own requirements that lead to `package`."""
        key = package.lower()
        if key in self._roots or key in self._dev_roots:
            return {key}
        found: set[str] = set()
        seen = {key}
        stack = [key]
        while stack:
            for parent in self._parents.get(stack.pop(), ()):
                if parent in seen:
                    continue
                seen.add(parent)
                if parent in self._roots or parent in self._dev_roots:
                    found.add(parent)
                else:
                    stack.append(parent)
        return found


    @classmethod
    def _from_sbom(cls, document: dict) -> DependencyGraph:
        parts = sbom_mod.components(document)
        links = sbom_mod.edges(document)
        root = sbom_mod.root_ref(document)

        nodes: dict[str, Node] = {}
        by_ref: dict[str, str] = {}
        for ref, item in parts.items():
            name = item["name"].lower()
            by_ref[ref] = name
            nodes[name] = Node(name, item["version"], item["dev"], {}, item["ecosystem"])
        for ref, depends in links.items():
            owner = by_ref.get(ref)
            if owner and owner in nodes:
                nodes[owner].requires = {
                    by_ref[d]: "" for d in depends if d in by_ref
                }

        roots = {by_ref[d] for d in links.get(root, ()) if d in by_ref}
        if not roots and root in by_ref:
            roots = set(nodes[by_ref[root]].requires)
        nodes.pop(by_ref.get(root, ""), None)
        roots &= set(nodes)
        dev_roots = {name for name in roots if nodes.get(name) and nodes[name].dev}
        return cls(nodes, roots - dev_roots, dev_roots)

    def version_of(self, package: str) -> str:
        node = self._nodes.get(package.lower())
        return node.version if node else ""

    def dependents(self, package: str) -> list[str]:
        """Installed packages that require `package` and do not run only in development."""
        key = package.lower()
        return sorted(parent for parent in self._parents.get(key, ()) if self.scope(parent) != "dev")

    def placement(self, package: str, max_paths: int = 4) -> Placement:
        """How `package` got here, from every direct requirement that leads to it."""
        key = package.lower()
        if not self._nodes:
            return Placement(package, problem=self.problem or "граф зависимостей не построен")
        if key not in self._nodes:
            return Placement(package, problem=f"{package} нет в SBOM от cdxgen")

        placement = Placement(
            package,
            direct=key in self._roots or key in self._dev_roots,
            in_graph=True,
            dev_only=(self.scope(key) == "dev") if (self._roots or self._dev_roots) else self._nodes[key].dev,
            ecosystem=self._nodes[key].ecosystem,
        )
        if not (self._roots or self._dev_roots):
            placement.problem = ("в SBOM нет рёбер от корневого компонента — "
                                 "прямые зависимости не определить")

        starts = self._roots | self._dev_roots
        seen = {key}
        frontier: list[list[str]] = [[key]]
        for _ in range(12):
            if len(placement.introductions) >= max_paths or not frontier:
                break
            nxt: list[list[str]] = []
            for trail in frontier:
                for parent in sorted(self._parents.get(trail[0], ())):
                    if parent in seen:
                        continue
                    path = [parent, *trail]
                    if parent in starts:
                        placement.introductions.append(Introduction(path))
                        if len(placement.introductions) >= max_paths:
                            break
                    else:
                        nxt.append(path)
                    seen.add(parent)
            frontier = nxt
        return placement
