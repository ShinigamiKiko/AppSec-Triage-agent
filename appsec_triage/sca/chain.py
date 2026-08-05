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
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from . import advisories as adv
from . import conditions as conditions_mod
from . import container as container_mod
from . import exploitability as exploit_mod
from . import presence as presence_mod
from . import reach as reach_mod
from . import receiver as receiver_mod
from . import registries
from .bridge import BridgeResult, find_bridge
from .graph import DependencyGraph, Placement
from .resolve import SymbolResolver, VulnerableSymbol
from .verdict import CVEDecision, CVEVerdict, decide

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding

log = logging.getLogger(__name__)


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
        )

    def render(self) -> str:
        """The section handed to the model, or shown when the model is skipped."""
        lines = ["## Проверка уязвимой функции", "", self.decision.headline, ""]
        if self.exploitability is not None and (rendered := self.exploitability.render()):
            lines.append(f"- эксплуатируемость: {rendered}")
        if self.placement is not None:
            lines.append(f"- положение в графе: {self.placement.describe()}")
            note = self.placement.upgrade_note()
            if note:
                lines.append(f"- что обновлять: {note}")
        if self.bridge is not None and self.bridge.detail:
            lines.append(f"- посредник: {self.bridge.detail}")
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
        self._resolver = SymbolResolver(client, roots=[Path(r) for r in roots])
        self._roots = [Path(r) for r in roots]
        self._lsp = lsp
        self._routes = routes
        self._nvd_api_key = nvd_api_key
        self._deployment = deployment
        self._advisories: dict[tuple[str, str, str, str], adv.Advisory] = {}
        self._graphs: dict[str, DependencyGraph] = {}
        self._wirings: dict[str, container_mod.Wiring] = {}
        self._exploit = exploit_mod.ExploitabilityService()
        self.stats = {"resolved": 0, "called": 0, "absent": 0,
                      "not_distributed": 0, "undecided": 0}

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
        out.sort(key=lambda i: not i.startswith("GHSA-"))
        return out

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

    def _placement(self, package: str) -> Placement | None:
        """Read each project's lockfile once; the graph does not change mid-run."""
        if not package:
            return None
        for root in self._roots:
            key = str(root)
            if key not in self._graphs:
                self._graphs[key] = DependencyGraph.from_project(root)
            placement = self._graphs[key].placement(package)
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

        for parent in parents[:2]:
            if not registries.supported(dependency.ecosystem or ""):
                continue
            version = self._graph_version(parent)
            source = self._resolver._source_for(  # noqa: SLF001 - one reuse point per run
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

    def _graph_version(self, package: str) -> str:
        for graph in self._graphs.values():
            version = graph.version_of(package)
            if version:
                return version
        return ""

    def run(
        self, finding: "Finding", *, codeql_findings: Iterable["Finding"] = ()
    ) -> ChainResult:
        dependency = finding.dependency
        if dependency is None:
            return ChainResult(decide(None, None, None))

        problems: list[str] = []
        identifiers = self._identifiers(finding)

        key = (identifiers[0] if identifiers else "", dependency.package or "",
               dependency.ecosystem or "", dependency.installed_version or "")
        try:
            if key in self._advisories:
                advisory = self._advisories[key]
            else:
                advisory = adv.collect(*key, nvd_api_key=self._nvd_api_key)
                self._advisories[key] = advisory
        except adv.DatabaseUnavailable as exc:
            problems.append(f"базы уязвимостей недоступны: {exc}")
            self.stats["undecided"] += 1
            return ChainResult(decide(None, None, None), problems=problems)
        if advisory.problem:
            problems.append(advisory.problem)

        symbol = self._resolver.resolve(advisory, dependency.installed_version or "")
        if symbol.note and not symbol.usable:
            problems.append(symbol.note)
        if symbol.usable:
            self.stats["resolved"] += 1

        placement = self._placement(dependency.package or "")

        bridge, targets = self._bridge(symbol, placement, dependency)
        if bridge is not None and bridge.detail and bridge.calls_it is None:
            problems.append(bridge.detail)

        found: presence_mod.PresenceResult | None = None
        searched: list[str] = []
        if bridge is not None and bridge.closes:
            found = presence_mod.PresenceResult(
                presence_mod.SymbolPresence.ABSENT, str(symbol), detail=bridge.detail)
            targets = []
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
