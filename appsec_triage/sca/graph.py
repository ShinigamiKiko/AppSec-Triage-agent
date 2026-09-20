"""Who pulled a vulnerable package in, and what upgrading it actually means."""

from __future__ import annotations

import logging
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
            return ""
        roots = sorted({i.root_requirement for i in self.introductions if i.root_requirement})
        parents = ", ".join(self.parents[:3])
        override = _OVERRIDE.get(key, f"закрепление версии в {manifest}")
        return (f"версия задана родителем ({parents}); напрямую не обновить — "
                f"нужна новая версия {', '.join(roots[:3])} либо {override}")


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
    def from_project(cls, root: Path | str) -> DependencyGraph:
        """cdxgen, and nothing else."""
        root = Path(root)
        if not sbom_mod.available():
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
        log.info("dependency graph from cdxgen: %d components", len(graph))
        return graph


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
        dev_roots = {name for name in roots if nodes.get(name) and nodes[name].dev}
        return cls(nodes, roots - dev_roots, dev_roots)

    def version_of(self, package: str) -> str:
        node = self._nodes.get(package.lower())
        return node.version if node else ""

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
            dev_only=self._nodes[key].dev,
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
