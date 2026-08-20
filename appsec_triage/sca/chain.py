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
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

from . import advisories as adv
from . import conditions as conditions_mod
from . import container as container_mod
from . import exploitability as exploit_mod
from . import exploitable as exploitable_mod
from . import codeql_reach
from . import govulncheck as govulncheck_mod
from . import unreached as unreached_mod
from . import presence as presence_mod
from . import reach as reach_mod
from . import receiver as receiver_mod
from . import registries
from .bridge import BridgeResult, BridgeSymbol, BridgeWalk, walk_bridge
from .graph import DependencyGraph, Placement
from .resolve import SymbolResolver, VulnerableSymbol
from .verdict import CVEDecision, CVEVerdict, decide

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding

log = logging.getLogger(__name__)

# Every namespace an advisory id can live in. Recognising only GHSA and CVE was
# measured: a Go finding carries a `GO-` id and nothing else, so no identifier
# was extracted, the per-run memo key collapsed to the empty string, and one
# lookup's answer was handed to all fourteen x/crypto findings — each reported
# under its own id with another advisory's conclusion.
_ID_PREFIXES = ("GHSA-", "CVE-", "GO-", "PYSEC-", "RUSTSEC-", "GMS-",
                "BIT-", "DRUPAL-", "MAL-", "OSV-", "RHSA-", "USN-")

# Which CodeQL database answers for a package ecosystem's first-party code.
_CODEQL_LANGUAGE = {
    "go": "go", "golang": "go",
    "npm": "javascript", "node": "javascript", "javascript": "javascript",
    "pypi": "python", "python": "python", "pip": "python",
}


def _pairs(symbols: list[BridgeSymbol], limit: int = 6) -> list[tuple[str, str]]:
    """The (function, class) form the first-party search takes."""
    return [(s.function, s.klass) for s in symbols[:limit]]


def _walk_as_bridge(walk: BridgeWalk) -> BridgeResult:
    """Express a multi-hop walk in the one-hop result the rest of the chain reads.

    The extra a walk carries — how many hops, how much confidence is left — is
    folded into the detail string, so a two-hop path reads as a two-hop path in
    the report rather than as a bare "reached". The symbols are passed through as
    the walk built them: rebuilding them from names alone defaulted every one to
    `visibility="public"`, which made `callable_from_outside` true by
    construction and lost the file and line the search had already found.
    """
    detail = walk.detail
    if walk.hops > 1:
        detail = f"{detail} [{walk.hops} шага, уверенность {walk.confidence}]"
    if walk.closed:
        return BridgeResult(calls_it=False, detail=detail)
    if walk.unknown or not walk.targets:
        return BridgeResult(calls_it=None, detail=detail)
    return BridgeResult(calls_it=True, symbols=list(walk.targets), detail=detail)


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
    dataflow: "codeql_reach.Reached | None" = None
    """Where user input enters, when CodeQL found a path to the call site.

    On the result rather than only in the decision, because a verdict that rests
    on a trace the report does not print cannot be checked by the person reading
    it — the third time in this chain that evidence reached the conclusion and
    not the page.
    """
    reachability: "govulncheck_mod.Verdict | None" = None
    """The call-graph verdict, when a report supplied one.

    Kept on the result so the report can print the frames the decision rests on:
    a trace that reaches the verdict but not the page leaves a closure or a
    confirmation the reviewer has no way to check.
    """
    matched_symbol: str = ""
    """The candidate that actually matched, when several were searched.

    An advisory lists many entry points into one flaw, and the report used to
    name the first of them whatever matched: two findings were closed as "the
    method name matched but the receiver is another type" while naming
    `Backend::Receive`, which matched nothing — the reviewer cannot check a
    closure against a name that never appears in the code.
    """
    audit: str = ""
    """What checked this closure, in one line for the report row.

    A closure by a mechanical fact never reaches the model, so its audit leaves
    no trace in the model-facing prose — the only place it can be seen is a
    field the summary carries. Same lesson as `dataflow` and `reachability`
    above: a check that reached the verdict but not the page cannot be checked.
    """

    @property
    def needs_a_person(self) -> bool:
        return self.condition is not None and self.condition.needs_a_person

    @property
    def closes(self) -> bool:
        return self.decision.closes

    def _evidence(self) -> list[str]:
        """The locations behind the verdict, strongest source first.

        A dataflow answer names where the input enters and where it lands; a
        call-graph answer names its frames; otherwise the call sites the text
        search found. Whichever decided the finding is what the report shows.
        """
        if self.dataflow is not None:
            return [f"{self.dataflow.source_file}:{self.dataflow.source_line} (источник)",
                    f"{self.dataflow.file}:{self.dataflow.line} (вызов)"]
        if self.reachability is not None and self.reachability.reachable:
            return list(self.reachability.trace[:6])
        return [str(hit) for hit in (self.presence.hits[:5] if self.presence else [])]

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
            symbol=self.matched_symbol or (str(self.symbol) if self.symbol else ""),
            what_changed=(self.symbol.what_changed if self.symbol else ""),
            outcome=self.decision.verdict.value,
            outcome_note=self.decision.headline,
            call_sites=self._evidence(),
            trace=(self.dataflow.render() if self.dataflow is not None
                   else self.reachability.render() if self.reachability is not None
                   else (self.reach.taint_path if self.reach else "")),
            external=external,
            owner=owner,
            exploitability=(self.exploitability.render() if self.exploitability else ""),
            audit=self.audit,
            problems=self.problems[:4],
        )

    def render(self) -> str:
        """The section handed to the model, or shown when the model is skipped."""
        lines = ["## Проверка уязвимой функции", "", self.decision.headline, ""]
        if self.symbol is not None:
            lines += [
                "Контекст advisory (это описание CVE, не verdict по проекту):",
                f"- пакет: {self.symbol.package or 'не указан'}",
                f"- источник контекста: {self.symbol.source_stage or 'не указан'}",
                f"- символ из advisory/fix: {self.symbol}",
            ]
            if self.symbol.file:
                lines.append(f"- файл в пакете: {self.symbol.file}")
            if self.symbol.what_changed:
                lines.append(f"- изменение в fix: {self.symbol.what_changed}")
            if self.symbol.evidence:
                lines.append(f"- evidence: {self.symbol.evidence}")
            if self.symbol.precondition:
                lines.append(f"- условие эксплуатации: {self.symbol.precondition}")
            if self.symbol.required_actions:
                lines.append(f"- требуемые действия: {'; '.join(self.symbol.required_actions[:8])}")
            if self.symbol.advisory_context:
                lines.append(f"- дополнительные замечания advisory: {self.symbol.advisory_context}")
            candidates = [
                f"{klass}::{function}" if klass else function
                for function, klass in self.symbol.candidates
                if function
            ]
            candidates = list(self.symbol.search_targets) or candidates
            if candidates:
                lines.append(f"- искать в коде проекта: {', '.join(candidates[:12])}")
            lines.append("")
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
        reachability=None,
        codeql_databases: "dict[str, Path] | None" = None,
    ) -> None:
        self._client = client
        self._resolver = SymbolResolver(client, roots=[Path(r) for r in roots])
        self._roots = [Path(r) for r in roots]
        self._lsp = lsp
        self._routes = routes
        self._nvd_api_key = nvd_api_key
        self._deployment = deployment
        # A call-graph report, when the pipeline produced one. Optional by
        # design: without it the chain answers exactly as it did before.
        self._reachability = reachability
        # CodeQL databases the SAST phase built, by language. Queried for the
        # dataflow question SARIF cannot answer: does user input reach the line
        # where a vulnerable library function is called.
        self._databases = {str(k).lower(): Path(v)
                           for k, v in (codeql_databases or {}).items()}
        self._dataflow: dict[tuple[str, tuple], codeql_reach.Answer] = {}
        # Findings are triaged in parallel, and CodeQL keeps a disk cache per
        # database that concurrent query processes fight over: measured, the
        # first query answered and the next four died with "Error initializing
        # the IMB disk cache". One query at a time, and the memo is consulted
        # inside the lock so identical work started by several threads is done
        # once rather than queued.
        self._dataflow_lock = threading.Lock()
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
                if upper.startswith(_ID_PREFIXES) and upper not in out:
                    out.append(upper)
        url = (finding.dependency.advisory_url or "") if finding.dependency else ""
        for token in url.replace("/", " ").split():
            upper = token.strip().upper()
            if upper.startswith(_ID_PREFIXES) and upper not in out:
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
    ) -> tuple[BridgeResult | None, list[tuple[str, str]], str]:
        """Does the *direct* dependency use the flaw, and through what?

        The vulnerable package's own code is never read — the advisory and its
        fix already describe the flaw. What is unknown, and what decides the
        finding, is how the direct dependency uses it: an application that
        requires `symfony/mailer` calls `symfony/mailer`, and whether that
        reaches `egulias/email-validator` is a fact about the mailer's code.

        The parent is read from the installed tree only. Not installed means the
        question is open, which is the truth and is reported as such.

        Returns the bridge, what to search for in first-party code, and the
        direct dependency the walk actually went through — the caller needs that
        last one to ask "is it used" about the package the application names,
        and re-deriving it there let the two disagree.
        """
        # An advisory that lists its symbols usually lists several entry points
        # into the same flaw, and any one of them being called is the answer.
        default = list(symbol.candidates) or [(symbol.function, symbol.klass)]
        # No symbol to walk from, nothing installed to read, or a package the
        # application calls directly — for a direct dependency the vulnerable
        # function is searched in first-party code as-is. A package that is both
        # direct and transitive must not be closed on a transitive path when a
        # direct call path exists: that is a false negative, and it was measured
        # (eight x/crypto findings wrongly closed as "not reached").
        if (not symbol.function or symbol.not_distributed
                or placement is None or not placement.introductions
                or placement.direct
                or not registries.supported(dependency.ecosystem or "")):
            return None, default, ""

        ecosystem = dependency.ecosystem or ""

        def source_of(package: str) -> dict[str, str]:
            return self._resolver._source_for(  # noqa: SLF001 - one reuse point per run
                ecosystem, package, self._graph_version(package))

        # The intermediate packages between the flaw and the application, nearest
        # the flaw first. The shortest introduction is the most direct path and
        # the one to try; deeper alternatives cost more hops for weaker evidence.
        best: tuple[BridgeWalk, str] | None = None
        for intro in sorted(placement.introductions, key=lambda i: len(i.path))[:2]:
            chain_pkgs = list(reversed(intro.path[:-1]))
            if not chain_pkgs:
                continue
            walk = walk_bridge(symbol.function, chain_pkgs, source_of)
            through = intro.root_requirement
            if walk.closed:
                return _walk_as_bridge(walk), [], through
            if walk.targets and not walk.unknown:
                return _walk_as_bridge(walk), _pairs(walk.targets), through
            best = best or (walk, through)

        if best is None:
            return None, default, ""
        walk, through = best
        return _walk_as_bridge(walk), (_pairs(walk.targets) or default), through

    def _dataflow_for(self, found, dependency):
        """Whether user input reaches these call sites, or a problem string.

        Memoised per (language, call sites): several advisories for one package
        land on the same lines, and a query evaluation is seconds against a
        database that took minutes to build — but it is still not free.
        """
        language = _CODEQL_LANGUAGE.get((dependency.ecosystem or "").strip().lower())
        database = self._databases.get(language or "")
        if database is None:
            return None

        sites = sorted({(hit.file, hit.line) for hit in found.hits[:12]})
        if not sites:
            return None

        key = (language, tuple(sites))
        with self._dataflow_lock:
            answer = self._dataflow.get(key)
            if answer is None:
                answer = codeql_reach.run(database, language, sites)
                self._dataflow[key] = answer
        if answer.problem:
            return f"поток данных не проверен: {answer.problem}"
        return answer.verdict(sites)

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

        # Asked first, because a call graph settles the question the rest of the
        # chain spends its effort approximating. It covers Go only, so for every
        # other ecosystem this is simply None and nothing changes.
        reachability = None
        if self._reachability is not None and self._reachability.usable:
            reachability = self._reachability.lookup(
                finding.rule_id or "", *identifiers)

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
        if symbol.precondition_problem:
            # Visible on purpose: a condition was proposed and thrown out, which
            # a reviewer should be able to tell apart from one never considered.
            problems.append(symbol.precondition_problem)
        if symbol.usable:
            self.stats["resolved"] += 1

        # A call graph proves the path exists; it cannot see the values passed
        # along it. So when it reports a hit, the source at those frames is read
        # and judged — the step that separates "reached" from "can actually fire
        # here", and the one whose absence made an HTTP/2 flaw look live in code
        # that speaks plain HTTP to a link-local address.
        call_site = None
        if reachability is not None and reachability.reachable and self._roots:
            call_site = exploitable_mod.assess(
                reachability, self._roots[0], advisory, self._client)
            if call_site.detail and not call_site.lowers:
                problems.append(call_site.detail)

        # The opposite answer is a claim too, and it closes far more findings
        # than the positive one proves. It is checked for the calls a static
        # graph cannot resolve — reflection, plugins, generated code — and for
        # nothing else, because re-deriving the graph with weaker tools would
        # only add noise. This can reopen a closure; it can never deepen one.
        graph_audit = None
        if reachability is not None and not reachability.reachable and self._roots:
            graph_audit = unreached_mod.audit(
                reachability, self._roots[0], advisory, symbol, self._client)
            if graph_audit.detail and not graph_audit.reopens:
                problems.append(graph_audit.detail)

        placement = self._placement(dependency.package or "")

        bridge, targets, walked_through = self._bridge(symbol, placement, dependency)
        if bridge is not None and bridge.detail and bridge.calls_it is None:
            problems.append(bridge.detail)

        found: presence_mod.PresenceResult | None = None
        searched: list[str] = []
        if bridge is not None and bridge.closes:
            found = presence_mod.PresenceResult(
                presence_mod.SymbolPresence.ABSENT, str(symbol), detail=bridge.detail)
            targets = []
        matched_symbol = ""
        for function, klass in targets:
            label = f"{klass}::{function}" if klass else function
            searched.append(label)
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
                    # Remember which of the listed entry points actually matched:
                    # the report has to name the one a reviewer can look up.
                    matched_symbol = label
                    break
            if found is not None and found.found:
                break
        if not self._roots:
            problems.append("не задан ни один корень исходников — поиск не выполнялся")

        receiver_disproved = False
        if found is not None and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
            root = self._roots[0] if self._roots else Path(".")
            # Where the flawed package lives on disk, so a resolved definition can
            # be tested for landing inside it rather than compared by name.
            package_dir = registries.locate(
                root, dependency.ecosystem or "", dependency.package or "",
                dependency.installed_version or "")
            resolution = receiver_mod.resolve(
                found, self._lsp, root, symbol.klass, dependency.package or "",
                wiring=self._wiring(root), client=self._client, package_dir=package_dir)
            receiver_disproved = resolution.disproved
            found = resolution.presence
            if resolution.detail and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
                problems.append(f"тип получателя не разрешён: {resolution.detail}")

        # Ask the database the SAST phase left behind whether user input reaches
        # the line where the vulnerable function is called. This is the question
        # SARIF is silent on: a call into a dependency is not a flaw CodeQL
        # reports, so the paths it publishes never cover these lines.
        dataflow = None
        if found is not None and found.presence is presence_mod.SymbolPresence.CALLED:
            dataflow = self._dataflow_for(found, dependency)
            if dataflow is not None and isinstance(dataflow, str):
                problems.append(dataflow)
                dataflow = None

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

        # For a transitive flaw the bridge reached through a parent, "is it used"
        # is a question about the parent, not the buried package: the application
        # imports go-ldap, never go-ntlmssp, so checking the latter's name always
        # says "absent" and would bury a real path. The package to ask about is
        # the one the walk actually went through.
        used_package = dependency.package or ""
        if bridge is not None and bridge.calls_it and bridge.symbols and walked_through:
            used_package = walked_through

        # Both scans walk the whole first-party tree, and `decide` reads neither
        # once an earlier fact has settled the finding — so they are skipped when
        # one has.
        direct = placement.direct if placement is not None else None
        settled_earlier = receiver_disproved or bool(dependency.dev_only)

        # The path-level question is asked whenever the advisory names its import
        # paths — not only for the functionless ones. A named symbol still has to
        # live in a package the project actually imports, and checking that is
        # what tells a real call from a collision on a common function name.
        package_used, package_used_detail = (None, "")
        if self._roots and symbol.package_paths and not settled_earlier:
            package_used, package_used_detail = presence_mod.import_path_used(
                self._roots[0], dependency.ecosystem or "", symbol.package_paths)

        # The module-wide scan is the coarser form of the same question, so it is
        # skipped only where the path-level answer will settle the finding: on a
        # direct dependency. For a transitive one the path check cannot conclude
        # anything and the module scan still has work to do.
        path_decides = bool(direct and symbol.package_paths and package_used is not None)
        used, used_detail = (None, "")
        if self._roots and not settled_earlier and not path_decides:
            used, used_detail = presence_mod.package_is_used(
                self._roots[0], dependency.ecosystem or "", used_package)

        # The mechanical closures are checked the same way the call-graph one is,
        # each against its own failure mode: a dev-only flag that a production
        # file imports anyway, an import path the text search would miss because
        # it is aliased or built from a string, a receiver the language server
        # pinned while the real call goes through an interface. Only the closure
        # actually about to fire is audited — auditing hypotheticals would spend
        # calls on branches the finding never takes.
        # Not gated on the call graph. A closure by absent import rests on its
        # own fact — the import path is not in the tree — and that fact has its
        # own blind spot whether or not govulncheck also spoke. The one case the
        # graph does settle is `not_reached`; there the closure is the graph's
        # own and `graph_audit` already checked it, so it is skipped here.
        closure_audit = None
        graph_closes = reachability is not None and not reachability.reachable
        if self._roots and not graph_closes:
            if dependency.dev_only:
                closure_kind, claim = "not_shipped", (
                    f"пакет {dependency.package} помечен в SBOM как нужный только "
                    "для сборки или тестов")
            elif package_used is False:
                closure_kind, claim = "unused", (
                    f"путь импорта {', '.join(symbol.package_paths[:3])} не найден "
                    "в дереве проекта")
            elif used is False:
                closure_kind, claim = "unused", (
                    f"пакет {used_package} не найден в дереве проекта")
            elif receiver_disproved:
                closure_kind, claim = "wrong_receiver", (
                    f"языковой сервер разрешил все вызовы {symbol} вне пакета "
                    f"{dependency.package}")
            else:
                closure_kind, claim = "", ""
            if closure_kind:
                closure_audit = unreached_mod.audit_closure(
                    closure_kind, claim, self._roots[0], advisory, symbol, self._client)
                if closure_audit.detail and not closure_audit.reopens:
                    problems.append(closure_audit.detail)

        result = ChainResult(
            decide(symbol, found, reached, cwe=finding.cwe,
                   closure_audit=closure_audit,
                   dev_only=dependency.dev_only, used=used, used_detail=used_detail,
                   package_used=package_used, package_used_detail=package_used_detail,
                   receiver_disproved=receiver_disproved,
                   reachability=reachability, call_site=call_site,
                   graph_audit=graph_audit,
                   dataflow=dataflow,
                   input_driven=(reach_mod.needs_input_path(finding.cwe)
                                 or any(reach_mod.needs_input_path(c)
                                        for c in advisory.cwe_ids) or None),
                   direct=direct,
                   condition=condition),
            symbol, found, reached, problems,
            placement=placement, bridge=bridge, searched_for=searched,
            condition=condition, exploitability=exploit,
            matched_symbol=matched_symbol, reachability=reachability,
            dataflow=(dataflow if dataflow not in (None, False) else None),
        )
        # Whichever audit ran against this closure names itself on the row, so the
        # report shows a checked closure as checked. A closure by a mechanical
        # fact never reaches the model, so this field is the only place its audit
        # can surface — the prose it would otherwise go into is never rendered.
        checked = closure_audit or graph_audit
        if checked is not None:
            result.audit = checked.render()

        verdict = result.decision.verdict
        if verdict is CVEVerdict.NOT_APPLICABLE:
            self.stats["not_distributed"] += 1
        elif verdict in (CVEVerdict.NO_DIRECT_CALL, CVEVerdict.MENTIONED_ONLY,
                         CVEVerdict.ONLY_IN_TESTS, CVEVerdict.NOT_REACHED):
            self.stats["absent"] += 1
        elif verdict in (CVEVerdict.ACTUAL, CVEVerdict.PRESENT_UNPROVEN):
            self.stats["called"] += 1
        else:
            self.stats["undecided"] += 1
        return result
