"""Stateful orchestration for one dependency finding."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import TYPE_CHECKING

from .. import advisories as adv
from .. import codeql_agent, codeql_reach, components as components_mod, conditions as conditions_mod, llm_advisory
from .. import exploitable as exploitable_mod, govulncheck as govulncheck_mod
from .. import presence as presence_mod, reach as reach_mod, receiver as receiver_mod
from .. import registries, unreached as unreached_mod
from .helpers import _finding_call_site, _needs_llm_advisory, _render_finding_trace
from .models import ChainResult
from .support import ChainSupport
from ..verdict import CVEVerdict, decide

if TYPE_CHECKING:
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding


class DependencyChain(ChainSupport):
    """Steps 1-4 for dependency findings. Constructed once per run."""

    def run(self, finding: Finding, *, codeql_findings: Iterable[Finding] = ()) -> ChainResult:
        dependency = finding.dependency
        if dependency is None:
            return ChainResult(decide(None, None, None))
        problems: list[str] = []
        identifiers = self._identifiers(finding)
        reachability = None
        if self._reachability is not None and self._reachability.usable:
            reachability = self._reachability.lookup(finding.rule_id or "", *identifiers)
        if reachability is None and dependency.reachability in {"reachable", "unreachable"}:
            position = _finding_call_site(finding, dependency)
            # Finding traces are source-first; Verdict.trace follows the
            # govulncheck convention and keeps the vulnerable frame first.
            trace = [
                step.message or (f"{step.file_path}:{step.line}" if step.line else step.file_path)
                for step in reversed(finding.trace)
                if step.file_path
            ]
            sites = [
                (step.file_path, step.line)
                for step in finding.trace
                if step.file_path and step.line and step.line > 0
            ]
            if position and not sites:
                sites = [position]
            if not trace and position:
                trace = [f"{position[0]}:{position[1]}"]
            reachability = govulncheck_mod.Verdict(
                advisory_id=finding.rule_id or identifiers[0],
                reach=(govulncheck_mod.Reach.CALLED if dependency.reachability == "reachable"
                       else govulncheck_mod.Reach.IMPORTED),
                trace=trace,
                sites=sites,
            )
        elif reachability is not None and reachability.reachable and not reachability.sites:
            # The external govulncheck index may preserve the call-graph verdict
            # without positional frames. Wolfee still carries those positions,
            # and CodeQL needs them to ask the dataflow question.
            sites = [
                (step.file_path, step.line)
                for step in finding.trace
                if step.file_path and step.line and step.line > 0
            ]
            position = _finding_call_site(finding, dependency)
            if position and position not in sites:
                sites.append(position)
            reachability.sites.extend(sites)

        key = (identifiers[0] if identifiers else "", dependency.package or "",
               dependency.ecosystem or "", dependency.installed_version or "")
        try:
            advisory = self._advisories.get(key)
            if advisory is None:
                advisory = adv.collect(*key, nvd_api_key=self._nvd_api_key)
                self._advisories[key] = advisory
        except adv.DatabaseUnavailable as exc:
            problems.append(f"базы уязвимостей недоступны: {exc}")
            self.stats["undecided"] += 1
            return ChainResult(decide(None, None, None), problems=problems)
        if advisory.problem:
            problems.append(advisory.problem)

        # A component the platform does not run settles the finding before any
        # search, so neither the symbol lookup nor CodeQL is spent on it.
        exclusion = components_mod.classify(advisory, self._deployment, self._client, self._roots)
        if exclusion is not None:
            self.stats["out_of_scope"] += 1
            return ChainResult(exclusion.decision(), problems=problems, route="excluded",
                               audit=exclusion.render())

        context_parts = []
        if trace_context := _render_finding_trace(finding):
            context_parts.append(trace_context)
        if reachability is not None and reachability.reachable:
            if rendered := reachability.render():
                context_parts.append(f"Wolfee reachability:\n{rendered}")
        trace_dataflow = None
        dataflow_status = ""
        # Every question put to CodeQL for this finding, by whom, and its answer.
        codeql_calls: list[str] = []
        if reachability is not None and reachability.reachable and reachability.sites:
            trace_dataflow = self._dataflow_for(None, dependency, reachability.sites, record=codeql_calls,
                                                asked_by="цепочка (позиции из графа вызовов)")
            if isinstance(trace_dataflow, codeql_reach.Reached):
                dataflow_status = trace_dataflow.render()
                context_parts.append(trace_dataflow.render())
            elif trace_dataflow is False:
                dataflow_status = "CodeQL: ни одна проверенная позиция не получает пользовательский ввод."
                context_parts.append(dataflow_status)
            elif isinstance(trace_dataflow, str):
                dataflow_status = trace_dataflow
        dataflow_context = "\n\n".join(context_parts)
        if _needs_llm_advisory(advisory) and reachability is not None and reachability.reachable:
            context = llm_advisory.lookup(
                self._client, finding.rule_id or identifiers[0], dependency.package or "",
                dependency.installed_version or "", dataflow_context=dataflow_context or "")
            if context:
                advisory.details = context
                advisory.summary = ""
            else:
                problems.append("внешние базы не дали описания advisory; LLM fallback недоступен")

        symbol = self._resolver.resolve(advisory, dependency.installed_version or "")
        if symbol.note and not symbol.usable:
            problems.append(symbol.note)
        if symbol.precondition_problem:
            problems.append(symbol.precondition_problem)
        if symbol.usable:
            self.stats["resolved"] += 1

        call_site = None
        if reachability is not None and reachability.reachable and self._roots:
            def query_dataflow(sites):
                answer = self._dataflow_for(None, dependency, sites, record=codeql_calls,
                                            asked_by="модель (шаг эксплуатируемости)")
                if isinstance(answer, codeql_reach.Reached):
                    return answer.render()
                if answer is False:
                    return "CodeQL: проверенные позиции не имеют пути от пользовательского ввода."
                return "CodeQL dataflow не проверен: база или запрос недоступны."
            call_site = exploitable_mod.assess(
                reachability, self._roots[0], advisory, self._client,
                dataflow_context=dataflow_context, dataflow_query=query_dataflow)
            if call_site.detail and not call_site.lowers:
                problems.append(call_site.detail)

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
        found = None
        searched: list[str] = []
        if bridge is not None and bridge.closes:
            found = presence_mod.PresenceResult(
                presence_mod.SymbolPresence.ABSENT, str(symbol), detail=bridge.detail)
            targets = []
        matched_symbol = ""
        receiver_class = symbol.klass
        api_answer = None
        api_package = (walked_through if bridge is not None and bridge.calls_it and walked_through
                       else dependency.package or "")
        seen: set[str] = set()

        def search(pairs, *, lead: bool) -> None:
            """Look for the first of `pairs` this code calls.

            CodeQL's API graph goes first wherever a database for the language
            exists: it resolves the call to the package's own export and answers
            the dataflow question in the same pass. When it finds no call, the
            text search still runs — a dynamic `require` or a bundler shim is
            invisible to the graph, and its silence must not hide a call that is
            written in the file. `lead` marks names the model supplied: searched,
            never trusted to close anything.
            """
            nonlocal found, matched_symbol, receiver_class, api_answer
            if self._uses_psalm(dependency):
                # PHP names from a fix diff carry no class; the installed package says which.
                pairs = self._qualify_php_pairs(api_package, pairs)
            fresh = []
            for function, klass in pairs:
                klass = (klass or "").lstrip("\\")
                label = f"{klass}::{function}" if klass else function
                if label and label not in seen:
                    seen.add(label)
                    fresh.append((function, klass))
                    searched.append(f"{label} (публичный вход, назван моделью)" if lead else label)
            if not fresh:
                return
            answer = (None if symbol.not_distributed and not lead
                      else self._codeql_api_for(dependency, api_package, fresh, record=codeql_calls))
            if answer is not None and not answer.usable:
                problems.append(f"{self._engine_name(dependency)} не ответил, искали по тексту: {answer.problem}")
            elif answer is not None:
                for function, klass in fresh:
                    label = f"{klass}::{function}" if klass else function
                    result = answer.presence(label)
                    if result.found:
                        found, matched_symbol, receiver_class, api_answer = result, label, klass, answer
                        return
            for function, klass in fresh:
                label = f"{klass}::{function}" if klass else function
                # The class-bound text search matches a short class name, not a namespace path.
                short_class = klass.rpartition("\\")[2]
                for root in self._roots:
                    result = presence_mod.find_symbol(
                        root, function=function, klass=short_class,
                        file_hint="" if lead or function else symbol.file,
                        not_distributed=False if lead else symbol.not_distributed,
                        ecosystem=dependency.ecosystem or "", package=dependency.package or "")
                    if found is None or result.found:
                        found = result
                    if result.found:
                        matched_symbol, receiver_class = label, short_class
                        return

        # The model questions CodeQL first, wherever a database exists: it knows
        # which exports lead to the flaw and reacts to what comes back. A call or a
        # path it finds is a fact of the database; a miss on its names is not, so
        # the chain's deterministic search still runs when it finds nothing.
        model_reached = None
        if (self._client is not None and self._codeql_api_available(dependency)
                and not (bridge is not None and bridge.closes) and not symbol.not_distributed):
            engine = self._engine_name(dependency)
            asker = f"модель (запрос к {engine})"
            investigation = codeql_agent.investigate(
                self._client, advisory, symbol, api_package, engine=engine,
                ask_functions=lambda pairs: self._codeql_api_for(
                    dependency, api_package, pairs, record=codeql_calls, asked_by=asker),
                ask_sites=lambda sites: self._dataflow_for(
                    None, dependency, sites, record=codeql_calls, asked_by=asker))
            model_reached = investigation.reached
            if investigation.found is not None:
                found, matched_symbol, receiver_class, api_answer = (
                    investigation.found, investigation.label, investigation.klass, investigation.answer)
                searched.append(f"{investigation.label} (запрошено моделью через {engine})")
            elif investigation.detail:
                problems.append(f"исследование через {engine}: {investigation.detail}")

        if found is None or not found.found:
            search(targets, lead=False)

        # A fix corrects the function whose body was wrong, and in a library that
        # is usually a private helper no application calls: on a seeded project
        # js-yaml's code injection resolved to `storeMappingPair`, the search
        # missed it while `yaml.load(req.body)` sat in the handler, and the call
        # site never got its dataflow question. For a direct dependency that miss
        # is expected rather than informative, so the public entry points above
        # the helper are searched too. They are named by the model and stay
        # leads: a hit opens the finding, a miss closes nothing.
        if (found is not None and found.presence is presence_mod.SymbolPresence.ABSENT
                and not (bridge is not None and bridge.closes)
                and placement is not None and placement.direct
                and symbol.usable and not symbol.named_by_model and not symbol.listed_in_advisory):
            entry = self._resolver._last_resort(advisory, dependency.installed_version or "")
            if entry is not None:
                search(entry.candidates, lead=True)

        if not self._roots:
            problems.append("не задан ни один корень исходников — поиск не выполнялся")

        receiver_disproved = False
        if found is not None and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
            root = self._roots[0] if self._roots else Path(".")
            package_dir = registries.locate(
                root, dependency.ecosystem or "", dependency.package or "",
                dependency.installed_version or "")
            resolution = receiver_mod.resolve(
                found, self._lsp, root, receiver_class, dependency.package or "",
                wiring=self._wiring(root), client=self._client, package_dir=package_dir)
            receiver_disproved = resolution.disproved
            found = resolution.presence
            if resolution.detail and found.presence is presence_mod.SymbolPresence.CALL_UNCONFIRMED:
                problems.append(f"тип получателя не разрешён: {resolution.detail}")

        dataflow = None
        if api_answer is not None and matched_symbol:
            # The call was resolved by CodeQL, which asked the dataflow question
            # in the same pass: its path, or its "no path", is the answer.
            dataflow = api_answer.dataflow(matched_symbol)
        elif found is not None and found.presence is presence_mod.SymbolPresence.CALLED:
            dataflow = self._dataflow_for(found, dependency, record=codeql_calls,
                                          asked_by="цепочка (найденные вызовы)")
            if isinstance(dataflow, str):
                problems.append(dataflow)
                dataflow = None
        if isinstance(model_reached, codeql_reach.Reached) and not isinstance(dataflow, codeql_reach.Reached):
            # A path CodeQL traced for a query the model chose is still CodeQL's path.
            dataflow = model_reached
        if isinstance(trace_dataflow, codeql_reach.Reached):
            dataflow = trace_dataflow
        elif trace_dataflow is False and dataflow is None:
            dataflow = False
            dataflow_status = "CodeQL: ни одна проверенная позиция не получает пользовательский ввод."
        elif isinstance(dataflow, str):
            dataflow_status = dataflow
        elif dataflow is False and not dataflow_status:
            dataflow_status = "CodeQL: ни одна проверенная позиция не получает пользовательский ввод."
        reached = None
        # Once CodeQL has answered the dataflow question, a second answer written
        # by the model reading the file would only compete with the real path.
        if (found is not None and found.presence is presence_mod.SymbolPresence.CALLED
                and reach_mod.needs_input_path(finding.cwe) and dataflow is None):
            reached = reach_mod.assess(
                found.hits, self._roots[0] if self._roots else Path("."), lsp=self._lsp,
                routes=self._routes, codeql_findings=codeql_findings, client=self._client)
            problems.extend(reached.tools_missing)

        condition = conditions_mod.check(
            self._roots, symbol.precondition, list(symbol.precondition_tokens),
            symbol.precondition_where, decidable=symbol.precondition_decidable)
        if condition.needs_a_person and self._deployment is not None and getattr(self._deployment, "usable", False):
            condition = conditions_mod.check_against_deployment(condition, self._deployment, self._client)
        exploit = self._exploit.assess(
            [*identifiers, *advisory.aliases, advisory.advisory_id], advisory.severity)
        problems.extend(exploit.problems)

        used_package = dependency.package or ""
        if bridge is not None and bridge.calls_it and bridge.symbols and walked_through:
            used_package = walked_through
        direct = placement.direct if placement is not None else None
        settled_earlier = receiver_disproved or bool(dependency.dev_only)
        package_used, package_used_detail = None, ""
        if self._roots and symbol.package_paths and not settled_earlier:
            package_used, package_used_detail = presence_mod.import_path_used(
                self._roots[0], dependency.ecosystem or "", symbol.package_paths)
        path_decides = bool(direct and symbol.package_paths and package_used is not None)
        used, used_detail, test_only = None, "", False
        if self._roots and not settled_earlier and not path_decides:
            used, used_detail, test_only = self._package_usage(dependency, used_package, record=codeql_calls)

        input_driven = (reach_mod.needs_input_path(finding.cwe)
                        or any(reach_mod.needs_input_path(c) for c in advisory.cwe_ids) or None)
        closure_audit = None
        graph_closes = reachability is not None and not reachability.reachable
        if self._roots and not graph_closes:
            if dependency.dev_only:
                closure_kind, claim = "not_shipped", (
                    f"пакет {dependency.package} помечен в SBOM как нужный только для сборки или тестов")
            elif used is False and test_only and direct:
                closure_kind, claim = "test_only", f"пакет {used_package} импортируется только в тестовом коде"
            elif (reachability is None and dataflow is False and input_driven
                    and not receiver_disproved):
                closure_kind, claim = "no_input_path", (
                    f"CodeQL не нашёл пути от пользовательского ввода к вызову {symbol}")
            elif package_used is False:
                closure_kind, claim = "unused", (
                    f"путь импорта {', '.join(symbol.package_paths[:3])} не найден в дереве проекта")
            elif used is False:
                closure_kind, claim = "unused", f"пакет {used_package} не найден в дереве проекта"
            elif receiver_disproved:
                closure_kind, claim = "wrong_receiver", (
                    f"языковой сервер разрешил все вызовы {symbol} вне пакета {dependency.package}")
            else:
                closure_kind, claim = "", ""
            if closure_kind:
                closure_audit = unreached_mod.audit_closure(
                    closure_kind, claim, self._roots[0], advisory, symbol, self._client)
                if closure_audit.detail and not closure_audit.reopens:
                    problems.append(closure_audit.detail)

        # Which machinery the verdict actually rests on, for the report and the bench.
        if reachability is not None:
            route = "callgraph"
        elif api_answer is not None and api_answer.engine == "psalm":
            route = "psalm"
        elif api_answer is not None or isinstance(dataflow, codeql_reach.Reached) or dataflow is False:
            route = "psalm" if getattr(dataflow, "engine", "") == "Psalm" else "codeql"
        elif symbol.usable:
            route = "text"
        elif symbol.package_paths:
            route = "package"
        elif symbol.precondition:
            route = "condition"
        else:
            route = "unknown"

        result = ChainResult(
            decide(symbol, found, reached, cwe=finding.cwe, closure_audit=closure_audit,
                   dev_only=dependency.dev_only, used=used, used_detail=used_detail, test_only=test_only,
                   package_used=package_used, package_used_detail=package_used_detail,
                   receiver_disproved=receiver_disproved, reachability=reachability,
                   call_site=call_site, graph_audit=graph_audit, dataflow=dataflow,
                   input_driven=input_driven,
                   direct=direct, condition=condition),
            symbol, found, reached, problems, placement=placement, bridge=bridge,
            searched_for=searched, condition=condition, exploitability=exploit,
             matched_symbol=matched_symbol, reachability=reachability,
             dataflow=(dataflow if dataflow not in (None, False) else None),
             dataflow_status=dataflow_status, route=route, codeql_calls=codeql_calls)
        checked = closure_audit or graph_audit
        if checked is not None:
            result.audit = checked.render()
        verdict = result.decision.verdict
        if verdict is CVEVerdict.NOT_APPLICABLE:
            self.stats["not_distributed"] += 1
        elif verdict in (CVEVerdict.NO_DIRECT_CALL, CVEVerdict.MENTIONED_ONLY,
                         CVEVerdict.ONLY_IN_TESTS, CVEVerdict.NOT_REACHED, CVEVerdict.ONLY_TEST_IMPORT):
            self.stats["absent"] += 1
        elif verdict in (CVEVerdict.ACTUAL, CVEVerdict.PRESENT_UNPROVEN):
            self.stats["called"] += 1
        else:
            self.stats["undecided"] += 1
        return result
