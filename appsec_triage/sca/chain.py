"""Running the four steps for one dependency finding, and saying what happened.

The parts are separately testable and separately fallible, and this is where
that matters: a database outage, a package the registry does not serve, a model
timeout and a missing language server all produce different answers, and the
report has to distinguish them. So every step records why it stopped, and the
rendered section names the failures rather than quietly shortening.

Only one outcome closes a finding without the model: the vulnerable code is not
in what the package manager installs. That rests on the contents of the
published archive, which is a fact. Everything else becomes context the model
weighs — including, deliberately, "nothing here calls it", because most
vulnerable functions are library internals reached through public API.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from . import advisories as adv
from . import conditions as conditions_mod
from . import container as container_mod
from . import exploitability as exploit_mod
from . import presence as presence_mod
from . import reach as reach_mod
from . import receiver as receiver_mod
from . import registries
from .bridge import BridgeResult, find_bridge
from .graph import DependencyGraph, Node, Placement
from .resolve import SymbolResolver, VulnerableSymbol
from .source_cache import PackageSourceCache, SourceSnapshot
from .verdict import CVEDecision, CVEVerdict, decide

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding

log = logging.getLogger(__name__)


@dataclass(slots=True)
class BridgeHop:
    package: str
    version: str
    status: str
    detail: str
    source_url: str = ""
    cache_status: str = ""

    def render(self) -> str:
        identity = f"{self.package}@{self.version}" if self.version else self.package
        source = f"; source={self.source_url}; cache={self.cache_status}" if self.source_url else ""
        return f"{identity}: {self.detail}{source}"


@dataclass(slots=True)
class BridgePath:
    packages: list[str]
    status: str = "unknown"
    hops: list[BridgeHop] = field(default_factory=list)
    targets: list[tuple[str, str]] = field(default_factory=list)
    detail: str = ""

    @property
    def description(self) -> str:
        return " -> ".join(self.packages)


@dataclass(slots=True)
class ChainResult:
    decision: CVEDecision
    symbol: VulnerableSymbol | None = None
    presence: presence_mod.PresenceResult | None = None
    reach: reach_mod.ReachResult | None = None
    problems: list[str] = field(default_factory=list)
    placement: Placement | None = None
    bridge: BridgeResult | None = None
    searched_for: list[str] = field(default_factory=list)
    condition: conditions_mod.Condition | None = None
    exploitability: exploit_mod.Exploitability | None = None
    bridge_paths: list[BridgePath] = field(default_factory=list)
    source_snapshots: list[SourceSnapshot] = field(default_factory=list)

    @property
    def needs_a_person(self) -> bool:
        return self.condition is not None and self.condition.needs_a_person

    @property
    def closes(self) -> bool:
        return self.decision.closes

    def summary(self, dependency=None):
        """The row a report shows, as opposed to the prose a model reads."""
        from ..models import SCASummary

        condition = self.condition
        external = ""
        owner = ""
        if condition is not None:
            from .conditions import ConditionState

            if condition.state is ConditionState.EXTERNAL:
                external = (f"{condition.statement} — искать: "
                            f"{', '.join(condition.tokens[:4]) or 'не определено'}; "
                            f"где: {condition.where or 'окружение и деплой'}")
            elif condition.state is ConditionState.INFRASTRUCTURE:
                external = condition.statement
                owner = condition.where or "владелец системы"

        return SCASummary(
            package=(dependency.package if dependency else "") or "",
            installed_version=(dependency.installed_version if dependency else "") or "",
            placement=self.placement.describe() if self.placement else "",
            upgrade=self.placement.upgrade_note() if self.placement else "",
            symbol=str(self.symbol) if self.symbol else "",
            what_changed=(self.symbol.what_changed if self.symbol else ""),
            outcome=self.decision.verdict.value,
            outcome_note=self.decision.headline,
            call_sites=[str(hit) for hit in (self.presence.hits[:5] if self.presence else [])],
            trace=(self.reach.taint_path if self.reach else ""),
            external=external,
            owner=owner,
            exploitability=(self.exploitability.render() if self.exploitability else ""),
            problems=self.problems[:4],
            resolution_error=(self.symbol.resolution_error if self.symbol else ""),
            dependency_paths=[path.description for path in self.bridge_paths],
            source_url=(self.source_snapshots[0].source_url if self.source_snapshots else ""),
            source_version=(self.source_snapshots[0].version if self.source_snapshots else ""),
            source_cache_status=(self.source_snapshots[0].cache_status if self.source_snapshots else ""),
            source_sha256=(self.source_snapshots[0].archive_sha256 if self.source_snapshots else ""),
            bridge_status=self._bridge_status(),
            bridge_hops=[hop.render() for path in self.bridge_paths for hop in path.hops],
        )

    def _bridge_status(self) -> str:
        statuses = {path.status for path in self.bridge_paths}
        if statuses == {"closed"}:
            return "closed"
        if "reachable" in statuses:
            return "reachable"
        return "unresolved" if statuses else ""

    def render(self) -> str:
        """The section handed to the model, or shown when the model is skipped."""
        lines = ["## Проверка уязвимой функции", "", self.decision.headline, ""]
        if self.exploitability is not None and (rendered := self.exploitability.render()):
            lines.append(f"- эксплуатируемость: {rendered}")
        if self.reach is not None:
            if self.reach.entrypoint:
                lines.append(f"- LSP/route entrypoint: {self.reach.entrypoint}")
            if self.reach.taint_path:
                lines.append(f"- CodeQL targeted dataflow: {self.reach.taint_path}")
            if self.reach.detail:
                lines.append(f"- результат reachability: {self.reach.detail}")
        if self.placement is not None:
            lines.append(f"- положение в графе: {self.placement.describe()}")
            note = self.placement.upgrade_note()
            if note:
                lines.append(f"- что обновлять: {note}")
        if self.bridge is not None and self.bridge.detail:
            lines.append(f"- посредник: {self.bridge.detail}")
        for path in self.bridge_paths:
            lines.append(f"- dependency path [{path.status}]: {path.description}")
            lines.extend(f"  - {hop.render()}" for hop in path.hops)
        if self.searched_for:
            lines.append(f"- искали в коде проекта: {', '.join(self.searched_for)}")
        if self.condition is not None and (rendered := self.condition.render()):
            lines.append(f"- {rendered}")
        for reason in self.decision.reasons:
            lines.append(f"- {reason}")
        if self.decision.evidence:
            lines.append("")
            lines.append("Места вызова:")
            lines.extend(f"- {item}" for item in self.decision.evidence)
        if self.problems:
            lines.append("")
            lines.append("Не удалось выполнить:")
            lines.extend(f"- {item}" for item in self.problems)
        return "\n".join(lines)


class DependencyChain:
    """Steps 1-4 for dependency findings. Constructed once per run."""

    def __init__(
        self,
        client,
        roots: list[Path],
        *,
        lsp: "LSPService | None" = None,
        routes: "RouteIndex | None" = None,
        nvd_api_key: str | None = None,
        deployment=None,
    ) -> None:
        self._client = client
        self._source_cache = PackageSourceCache()
        self._resolver = SymbolResolver(
            client, roots=[Path(r) for r in roots], source_cache=self._source_cache)
        self._roots = [Path(r) for r in roots]
        self._lsp = lsp
        self._routes = routes
        self._nvd_api_key = nvd_api_key
        self._deployment = deployment
        self._advisories: dict[tuple[str, str, str, str], adv.Advisory] = {}
        self._symbols: dict[tuple[str, str, str], VulnerableSymbol] = {}
        self._graphs: dict[str, DependencyGraph] = {}
        self._wirings: dict[str, container_mod.Wiring] = {}
        self._exploit = exploit_mod.ExploitabilityService()
        self.stats = {"resolved": 0, "called": 0, "absent": 0,
                      "not_distributed": 0, "undecided": 0,
                      "source_download_failures": 0, "unresolved_bridges": 0,
                      "successful_closures": 0}

    @staticmethod
    def _identifiers(finding: "Finding") -> list[str]:
        """Whatever names this advisory, best first.

        Scanners report the same flaw under different ids, and the databases are
        keyed differently again — so every id the finding carries is offered and
        the lookup takes the first that answers.
        """
        out: list[str] = []
        for value in (getattr(finding, "rule_id", ""), getattr(finding, "title", "")):
            for token in str(value or "").replace(",", " ").split():
                upper = token.strip().upper().strip("()[]")
                if upper.startswith(("GHSA-", "CVE-")) and upper not in out:
                    out.append(upper)
        url = (finding.dependency.advisory_url or "") if finding.dependency else ""
        for token in url.replace("/", " ").split():
            upper = token.strip().upper()
            if upper.startswith(("GHSA-", "CVE-")) and upper not in out:
                out.append(upper)
        if finding.dependency:
            for alias in finding.dependency.advisory_aliases:
                upper = alias.strip().upper()
                if upper.startswith(("GHSA-", "CVE-")) and upper not in out:
                    out.append(upper)
        out.sort(key=lambda i: not i.startswith("GHSA-"))
        return out

    def _advisory_and_symbol(
        self, finding: "Finding"
    ) -> tuple[adv.Advisory | None, VulnerableSymbol | None, list[str]]:
        dependency = finding.dependency
        if dependency is None:
            return None, None, []
        problems: list[str] = []
        identifiers = self._identifiers(finding)
        key = (identifiers[0] if identifiers else "", dependency.package or "",
               dependency.ecosystem or "", dependency.installed_version or "")
        try:
            advisory = self._advisories.get(key)
            if advisory is None:
                advisory = adv.collect(*key, nvd_api_key=self._nvd_api_key)
                self._advisories[key] = advisory
        except adv.DatabaseUnavailable as exc:
            return None, None, [f"базы уязвимостей недоступны: {exc}"]
        if advisory.problem:
            problems.append(advisory.problem)

        symbol_key = (advisory.advisory_id, dependency.package.lower(),
                      dependency.installed_version or "")
        symbol = self._symbols.get(symbol_key)
        if symbol is None:
            symbol = self._resolver.resolve(advisory, dependency.installed_version or "")
            self._symbols[symbol_key] = symbol
        if symbol.note and not symbol.usable:
            problems.append(symbol.note)
        return advisory, symbol, problems

    def prepare(self, findings: Iterable["Finding"]) -> None:
        """Resolve all CVE symbols and warm exact cdxgen package sources before workers run."""
        grouped: dict[tuple[str, str, str], list["Finding"]] = {}
        for finding in findings:
            dependency = finding.dependency
            if dependency is None or (finding.scanner or "").lower() == "govulncheck":
                continue
            key = ((dependency.ecosystem or "").lower(), dependency.package.lower(),
                   dependency.installed_version or "")
            grouped.setdefault(key, []).append(finding)

        for package_findings in grouped.values():
            for finding in package_findings:
                _advisory, symbol, _problems = self._advisory_and_symbol(finding)
                if symbol is None:
                    continue
                dependency = finding.dependency
                placement = self._placement(
                    dependency.package, dependency.installed_version or "")
                if placement is None:
                    continue
                refs = {
                    ref for introduction in placement.introductions
                    for ref in introduction.refs
                } | set(placement.target_refs)
                for ref in refs:
                    node = self._node(ref)
                    if node is not None:
                        self._resolver.source_snapshot(
                            node.ecosystem, node.name, node.version)

    def stats_snapshot(self) -> dict[str, int]:
        source = self._source_cache.stats()
        return {
            **self.stats,
            "source_packages": source["packages"],
            "source_downloads": source["downloads"],
            "source_cache_hits": source["cache_hits"],
            "source_download_failures": source["failures"],
        }

    def _wiring(self, root: Path):
        """Service configuration, read once per project — it cannot change mid-run."""
        key = str(root)
        if key not in self._wirings:
            wiring = container_mod.load(root)
            self._wirings[key] = wiring
            if wiring.usable:
                log.info("container config at %s: %d classes, %d aliases, %d decorators",
                         root, len(wiring.classes), len(wiring.aliases), len(wiring.decorates))
            elif wiring.problem:
                log.info("container config unavailable at %s: %s", root, wiring.problem)
        return self._wirings[key]

    def _placement(self, package: str, version: str = "") -> Placement | None:
        """Read each project's lockfile once; the graph does not change mid-run."""
        if not package:
            return None
        for root in self._roots:
            key = str(root)
            if key not in self._graphs:
                self._graphs[key] = DependencyGraph.from_project(root)
            placement = self._graphs[key].placement(package, version)
            if placement.known:
                return placement
        return placement if self._roots else None

    def _bridge(
        self, symbol: VulnerableSymbol, placement: Placement | None, dependency
    ) -> tuple[BridgeResult | None, list[tuple[str, str]]]:
        """Does the *direct* dependency use the flaw, and through what?

        The vulnerable package's own code is never read — the advisory and its
        fix already describe the flaw. What is unknown, and what decides the
        finding, is how the direct dependency uses it: an application that
        requires `symfony/mailer` calls `symfony/mailer`, and whether that
        reaches `egulias/email-validator` is a fact about the mailer's code.

        The parent is read from the installed tree only. Not installed means the
        question is open, which is the truth and is reported as such.
        """
        default = [(symbol.function, symbol.klass)]
        if not symbol.function or symbol.not_distributed:
            return None, default

        parents = placement.parents if placement is not None else []
        if placement is not None and placement.direct and not parents:
            return None, default
        if not parents:
            return None, default

        for parent in parents:
            if not registries.supported(dependency.ecosystem or ""):
                continue
            version = self._graph_version(parent)
            source = self._resolver._source_for(
                dependency.ecosystem or "", parent, version)
            if not source:
                return None, default
            bridge = find_bridge(symbol.function, source, parent_package=parent)
            if bridge.closes:
                return bridge, []
            if bridge.public_symbols:
                return bridge, [(s.function, s.klass) for s in bridge.public_symbols[:6]]
            if bridge.calls_it:
                return bridge, default
        return None, default

    def _node(self, ref: str) -> Node | None:
        for graph in self._graphs.values():
            if node := graph.node(ref):
                return node
        return None

    def _recursive_bridges(
        self, symbol: VulnerableSymbol, placement: Placement | None
    ) -> tuple[list[BridgePath], list[SourceSnapshot]]:
        """Walk every cdxgen path from the vulnerable node back to a direct dependency."""
        if placement is None or placement.direct or not symbol.function:
            return [], []
        if not placement.introductions:
            return [BridgePath([], detail=placement.problem or "cdxgen path unavailable")], []

        paths: list[BridgePath] = []
        snapshots: dict[tuple[str, str, str], SourceSnapshot] = {}
        for introduction in placement.introductions:
            path = BridgePath(list(introduction.path))
            targets = [(symbol.function, symbol.klass)]
            for parent_ref in reversed(introduction.refs[:-1]):
                node = self._node(parent_ref)
                if node is None:
                    path.detail = f"cdxgen node {parent_ref} is unavailable"
                    break
                snapshot = self._resolver.source_snapshot(
                    node.ecosystem, node.name, node.version)
                snapshots[(node.ecosystem, node.name, node.version)] = snapshot
                if not snapshot.usable:
                    path.hops.append(BridgeHop(
                        node.name, node.version, "unknown", snapshot.problem,
                        snapshot.source_url, snapshot.cache_status))
                    path.detail = snapshot.problem
                    self.stats["source_download_failures"] += 1
                    break

                results = [
                    find_bridge(function, snapshot.files, parent_package=node.name)
                    for function, _klass in targets
                ]
                calling = [result for result in results if result.calls_it is True]
                if not calling and all(result.calls_it is False for result in results):
                    detail = "; ".join(result.detail for result in results)
                    path.hops.append(BridgeHop(
                        node.name, node.version, "closed", detail,
                        snapshot.source_url, snapshot.cache_status))
                    path.status = "closed"
                    path.detail = detail
                    break
                if not calling:
                    detail = "; ".join(result.detail for result in results)
                    path.hops.append(BridgeHop(
                        node.name, node.version, "unknown", detail,
                        snapshot.source_url, snapshot.cache_status))
                    path.detail = detail
                    break

                public = {
                    (item.function, item.klass)
                    for result in calling for item in result.public_symbols
                }
                detail = "; ".join(result.detail for result in calling)
                if not public:
                    path.hops.append(BridgeHop(
                        node.name, node.version, "unknown",
                        detail + "; public bridge symbol was not established",
                        snapshot.source_url, snapshot.cache_status))
                    path.detail = "parent call exists but no public bridge symbol was established"
                    break
                path.hops.append(BridgeHop(
                    node.name, node.version, "open", detail,
                    snapshot.source_url, snapshot.cache_status))
                targets = sorted(public)
            else:
                path.status = "open"
                path.targets = targets
            paths.append(path)
        return paths, list(snapshots.values())

    def _graph_version(self, package: str) -> str:
        for graph in self._graphs.values():
            version = graph.version_of(package)
            if version:
                return version
        return ""

    def _from_govulncheck(
        self, finding: "Finding", codeql_findings: Iterable["Finding"]
    ) -> ChainResult:
        """Use govulncheck's symbol result directly instead of re-discovering it.

        A completed symbol scan already answered the expensive dependency-specific
        question. Asking a model to infer the function from advisory prose again
        both loses evidence and can contradict the scanner.
        """
        dependency = finding.dependency
        placement = self._placement(
            dependency.package if dependency else "",
            dependency.installed_version if dependency else "",
        )
        if not finding.trace:
            self.stats["absent"] += 1
            return ChainResult(
                CVEDecision(
                    CVEVerdict.NO_VULNERABLE_SYMBOL,
                    "govulncheck завершил symbol-level анализ: уязвимый символ не вызывается",
                    [
                        "пакет присутствует, но source-level call stack к уязвимой функции отсутствует",
                        "это результат govulncheck -scan=symbol, а не неудачный текстовый поиск",
                    ],
                ),
                placement=placement,
                searched_for=["govulncheck -scan=symbol"],
            )

        sink = finding.trace[-1]
        symbol_name = finding.sink or sink.message or "vulnerable symbol"
        function = symbol_name.rsplit(".", 1)[-1].lstrip("*")
        symbol = VulnerableSymbol(
            finding.rule_id or "govulncheck",
            dependency.package if dependency else "",
            function=function,
            confirmed_in_source=True,
            evidence=symbol_name,
            aliases=tuple(dependency.advisory_aliases if dependency else ()),
        )
        app = finding.trace[0]
        hit = presence_mod.Hit(
            app.file_path or finding.code_context.file_path,
            app.line or finding.code_context.start_line or 1,
            app.message or symbol_name,
        )
        presence = presence_mod.PresenceResult(
            presence_mod.SymbolPresence.CALLED,
            symbol_name,
            [hit],
            detail="govulncheck supplied a source-level call stack to the vulnerable symbol",
        )
        reached = None
        codeql_findings = list(codeql_findings)
        if reach_mod.needs_input_path(finding.cwe) or reach_mod.has_taint_path(
            codeql_findings, presence.hits
        ):
            reached = reach_mod.assess(
                presence.hits,
                self._roots[0] if self._roots else Path("."),
                lsp=self._lsp,
                routes=self._routes,
                codeql_findings=codeql_findings,
                client=self._client,
            )
        self.stats["resolved"] += 1
        self.stats["called"] += 1
        return ChainResult(
            decide(symbol, presence, reached, cwe=finding.cwe),
            symbol,
            presence,
            reached,
            placement=placement,
            searched_for=[symbol_name],
        )

    def run(
        self, finding: "Finding", *, codeql_findings: Iterable["Finding"] = ()
    ) -> ChainResult:
        dependency = finding.dependency
        if dependency is None:
            return ChainResult(decide(None, None, None))
        if (finding.scanner or "").lower() == "govulncheck":
            return self._from_govulncheck(finding, codeql_findings)

        identifiers = self._identifiers(finding)
        advisory, symbol, problems = self._advisory_and_symbol(finding)
        if advisory is None or symbol is None:
            self.stats["undecided"] += 1
            return ChainResult(decide(None, None, None), problems=problems)
        if symbol.usable:
            self.stats["resolved"] += 1

        placement = self._placement(
            dependency.package or "", dependency.installed_version or "")

        target_snapshot = self._resolver.source_snapshot(
            dependency.ecosystem or "", dependency.package or "",
            dependency.installed_version or "")
        bridge = None
        bridge_paths, source_snapshots = self._recursive_bridges(symbol, placement)
        all_snapshots = [target_snapshot]
        all_snapshots.extend(
            snapshot for snapshot in source_snapshots
            if (snapshot.ecosystem, snapshot.package, snapshot.version) !=
            (target_snapshot.ecosystem, target_snapshot.package, target_snapshot.version))
        if bridge_paths:
            targets = sorted({target for path in bridge_paths if path.status == "open"
                              for target in path.targets})
            if all(path.status == "closed" for path in bridge_paths):
                self.stats["successful_closures"] += 1
                decision = CVEDecision(
                    CVEVerdict.NO_DEPENDENCY_PATH,
                    "все cdxgen dependency paths разорваны в исходниках parent-пакетов",
                    [f"{path.description}: {path.detail}" for path in bridge_paths],
                )
                return ChainResult(
                    decision, symbol, problems=problems, placement=placement,
                    bridge_paths=bridge_paths, source_snapshots=all_snapshots)
            if any(path.status == "unknown" for path in bridge_paths):
                self.stats["unresolved_bridges"] += 1
                problems.extend(
                    f"unresolved bridge {path.description or dependency.package}: {path.detail}"
                    for path in bridge_paths if path.status == "unknown")
        else:
            targets = [(symbol.function, symbol.klass)]

        found: presence_mod.PresenceResult | None = None
        searched: list[str] = []
        for function, klass in targets:
            searched.append(f"{klass}::{function}" if klass else function)
            for root in self._roots:
                result = presence_mod.find_symbol(
                    root, function=function, klass=klass,
                    file_hint=symbol.file if not function else "",
                    not_distributed=symbol.not_distributed,
                    ecosystem=dependency.ecosystem or "",
                    package=dependency.package or "",
                )
                if found is None or result.found:
                    found = result
                if result.found:
                    break
            if found is not None and found.found:
                break
        if bridge_paths:
            for path in bridge_paths:
                if path.status == "open":
                    path.status = "reachable" if found is not None and found.found else "unknown"
                    if path.status == "unknown":
                        path.detail = "public bridge reached the application boundary, but no call was established"
        if not self._roots:
            problems.append("не задан ни один корень исходников — поиск не выполнялся")

        if found is not None and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
            root = self._roots[0] if self._roots else Path(".")
            resolution = receiver_mod.resolve(
                found, self._lsp, root, symbol.klass, dependency.package or "",
                wiring=self._wiring(root), client=self._client)
            found = resolution.presence
            if resolution.detail and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
                problems.append(f"тип получателя не разрешён: {resolution.detail}")

        reached: reach_mod.ReachResult | None = None
        if (found is not None and found.presence is presence_mod.SymbolPresence.CALLED
                and reach_mod.needs_input_path(finding.cwe)):
            reached = reach_mod.assess(
                found.hits, self._roots[0] if self._roots else Path("."),
                lsp=self._lsp, routes=self._routes, codeql_findings=codeql_findings,
                client=self._client,
            )
            problems.extend(reached.tools_missing)

        condition = conditions_mod.check(
            self._roots, symbol.precondition, list(symbol.precondition_tokens),
            symbol.precondition_where, decidable=symbol.precondition_decidable,
        )
        if (condition.needs_a_person and self._deployment is not None
                and getattr(self._deployment, "usable", False)):
            condition = conditions_mod.check_against_deployment(
                condition, self._deployment, self._client)

        exploit = self._exploit.assess(
            [*identifiers, *advisory.aliases, advisory.advisory_id], advisory.severity)
        problems.extend(exploit.problems)

        used, used_detail = (None, "")
        if self._roots:
            used, used_detail = presence_mod.package_is_used(
                self._roots[0], dependency.ecosystem or "", dependency.package or "")

        result = ChainResult(
            decide(symbol, found, reached, cwe=finding.cwe,
                   dev_only=dependency.dev_only, used=used, used_detail=used_detail,
                   direct=(placement.direct if placement is not None else None),
                   condition=condition),
            symbol, found, reached, problems,
            placement=placement, bridge=bridge, searched_for=searched,
            condition=condition, exploitability=exploit,
            bridge_paths=bridge_paths, source_snapshots=all_snapshots,
        )
        verdict = result.decision.verdict
        if verdict is CVEVerdict.NOT_APPLICABLE:
            self.stats["not_distributed"] += 1
        elif verdict in (CVEVerdict.NO_DIRECT_CALL, CVEVerdict.MENTIONED_ONLY,
                         CVEVerdict.ONLY_IN_TESTS):
            self.stats["absent"] += 1
        elif verdict in (CVEVerdict.ACTUAL, CVEVerdict.PRESENT_UNPROVEN):
            self.stats["called"] += 1
        else:
            self.stats["undecided"] += 1
        return result
