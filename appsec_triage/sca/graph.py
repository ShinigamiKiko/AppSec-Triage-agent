"""Who pulled a vulnerable package in, and what upgrading it actually means.

A CVE in a transitive dependency is a different problem from a CVE in a direct
one, and reporting them the same way makes both unactionable.

*Nothing in the project calls it.* The application requires `symfony/mailer`;
`egulias/email-validator` arrives underneath it. Searching the application for
the vulnerable function finds nothing, and that absence says nothing at all —
the caller is the intermediate package, not the application.

*Upgrading it is not usually possible on its own.* A transitive version is
pinned by its parent's constraint, so "update to 3.2.1" is advice the developer
cannot follow; what they can do is upgrade the parent, or add an explicit
constraint. Which of those it is depends on the path, so the path has to be
known before anything useful can be said.

The graph comes from cdxgen and from nowhere else. It reads every manifest and
lockfile format there is, states the dependency edges directly, and installs
nothing into the project. A second, hand-written source would cover one
ecosystem, drift from its format, and disagree with the SBOM the rest of the
pipeline already uses — so when cdxgen cannot answer, that is reported rather
than replaced by a worse answer.
"""

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
    ref: str
    name: str
    version: str = ""
    dev: bool = False
    requires: dict[str, str] = field(default_factory=dict)
    ecosystem: str = ""


@dataclass(slots=True)
class Introduction:
    """One way a package ends up installed."""

    path: list[str]
    refs: list[str] = field(default_factory=list)

    @property
    def direct_parent(self) -> str:
        """The package that requires the vulnerable one — the one that calls it."""
        return self.path[-2] if len(self.path) >= 2 else ""

    @property
    def direct_parent_ref(self) -> str:
        return self.refs[-2] if len(self.refs) >= 2 else ""

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
    target_refs: list[str] = field(default_factory=list)

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
        self._by_name: dict[str, list[str]] = {}
        for ref, node in nodes.items():
            self._by_name.setdefault(node.name, []).append(ref)
            for requirement in node.requires:
                self._parents.setdefault(requirement, set()).add(ref)

    def __len__(self) -> int:
        return len(self._nodes)

    @property
    def usable(self) -> bool:
        return bool(self._nodes)

    @classmethod
    def empty(cls) -> "DependencyGraph":
        return cls({}, set(), set())

    @classmethod
    def from_project(cls, root: Path | str) -> "DependencyGraph":
        """cdxgen, and nothing else.

        A second source is a second set of quirks: a hand-written lockfile
        parser covers one ecosystem, drifts from the format, and produces a
        graph that disagrees with the SBOM the rest of the pipeline uses. One
        source means one answer, and when it fails the failure is visible
        instead of being papered over by a worse one.
        """
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
    def from_sbom_file(cls, path: Path | str) -> "DependencyGraph":
        """An SBOM built by an earlier pipeline stage."""
        document, problem = sbom_mod.read(Path(path))
        if document is None:
            log.warning("%s", problem)
            return cls.empty()
        return cls._from_sbom(document)

    @classmethod
    def _from_sbom(cls, document: dict) -> "DependencyGraph":
        parts = sbom_mod.components(document)
        links = sbom_mod.edges(document)
        root = sbom_mod.root_ref(document)

        nodes: dict[str, Node] = {}
        by_ref: dict[str, str] = {}
        for ref, item in parts.items():
            name = item["name"].lower()
            by_ref[ref] = name
            nodes[ref] = Node(ref, name, item["version"], item["dev"], {}, item["ecosystem"])
        for ref, depends in links.items():
            if ref in nodes:
                nodes[ref].requires = {d: "" for d in depends if d in nodes}

        roots = {d for d in links.get(root, ()) if d in nodes}
        if not roots and root in nodes:
            roots = set(nodes[root].requires)
        dev_roots = {ref for ref in roots if nodes[ref].dev}
        return cls(nodes, roots - dev_roots, dev_roots)

    def node(self, ref: str) -> Node | None:
        return self._nodes.get(ref)

    def nodes_for(self, package: str, version: str = "") -> list[Node]:
        nodes = [self._nodes[ref] for ref in self._by_name.get(package.lower(), ())]
        return [node for node in nodes if not version or node.version == version]

    def version_of(self, package: str) -> str:
        nodes = self.nodes_for(package)
        versions = {node.version for node in nodes}
        return next(iter(versions)) if len(versions) == 1 else ""

    def placement(self, package: str, version: str = "") -> Placement:
        """How `package` got here, from every direct requirement that leads to it."""
        key = package.lower()
        if not self._nodes:
            return Placement(package, problem=self.problem or "граф зависимостей не построен")
        targets = self.nodes_for(key, version)
        if not targets:
            return Placement(package, problem=f"{package} нет в SBOM от cdxgen")

        placement = Placement(
            package,
            direct=any(node.ref in self._roots or node.ref in self._dev_roots for node in targets),
            dev_only=all(node.dev for node in targets),
            ecosystem=targets[0].ecosystem,
            target_refs=[node.ref for node in targets],
        )
        if not (self._roots or self._dev_roots):
            placement.problem = ("в SBOM нет рёбер от корневого компонента — "
                                 "прямые зависимости не определить")

        starts = self._roots | self._dev_roots

        def walk(ref: str, reverse_path: list[str]) -> None:
            for parent in sorted(self._parents.get(ref, ())):
                if parent in reverse_path:
                    continue
                path = [*reverse_path, parent]
                if parent in starts:
                    refs = list(reversed(path))
                    placement.introductions.append(Introduction(
                        [self._nodes[item].name for item in refs], refs))
                else:
                    walk(parent, path)

        for target in targets:
            if target.ref not in starts:
                walk(target.ref, [target.ref])
        return placement
