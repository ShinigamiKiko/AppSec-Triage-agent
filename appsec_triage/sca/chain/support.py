"""State and reusable operations for dependency-chain orchestration."""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from .. import advisories as adv
from .. import codeql_api, codeql_reach, container as container_mod, exploitability as exploit_mod, psalm_api
from .. import presence as presence_mod, registries
from ..bridge import BridgeResult, BridgeWalk, walk_bridge
from ..graph import DependencyGraph, Placement
from .helpers import _CODEQL_LANGUAGE, _ID_PREFIXES, _pairs, _walk_as_bridge
from ..resolve import SymbolResolver, VulnerableSymbol

log = logging.getLogger(__name__)


class ChainSupport:
    def __init__(self, client, roots, *, lsp=None, routes=None, nvd_api_key=None,
                 deployment=None, reachability=None, codeql_databases=None,
                 codeql_binary: str = "codeql", psalm_binary: str | None = None,
                 parallel_llm: int = 2) -> None:
        self._client = client
        self._resolver = SymbolResolver(client, roots=[Path(r) for r in roots])
        self._roots = [Path(r) for r in roots]
        self._lsp = lsp
        self._routes = routes
        self._nvd_api_key = nvd_api_key
        self._deployment = deployment
        self._reachability = reachability
        self._databases = {str(k).lower(): Path(v)
                           for k, v in (codeql_databases or {}).items()}
        self._codeql_binary = codeql_binary
        self._psalm_binary = psalm_binary
        self._parallel_llm = max(1, parallel_llm)
        self._dataflow: dict[tuple[str, tuple], codeql_reach.Answer] = {}
        self._api_answers: dict[tuple[str, tuple], codeql_api.ApiAnswer] = {}
        self._import_answers: dict[tuple[str, str], codeql_api.ImportAnswer] = {}
        self._dataflow_lock = threading.Lock()
        self._pending: dict[tuple[int, object], threading.Event] = {}
        self._advisories: dict[tuple[str, str, str, str], adv.Advisory] = {}
        self._graphs: dict[str, DependencyGraph] = {}
        self._wirings: dict[str, container_mod.Wiring] = {}
        self._exploit = exploit_mod.ExploitabilityService()
        self._symbols: dict[tuple[str, str], object] = {}
        self._batched: dict[tuple[str, str], tuple[codeql_api.ApiAnswer, frozenset[str]]] = {}
        self.stats = {"resolved": 0, "called": 0, "absent": 0,
                      "not_distributed": 0, "undecided": 0, "out_of_scope": 0,
                      "unaudited_closures": 0, "version_unaffected": 0}

    @staticmethod
    def _identifiers(finding) -> list[str]:
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

    def _bridge(self, symbol: VulnerableSymbol, placement: Placement | None, dependency):
        default = list(symbol.candidates) or [(symbol.function, symbol.klass)]
        if (not symbol.function or symbol.not_distributed or placement is None
                or not placement.introductions or placement.direct
                or not registries.supported(dependency.ecosystem or "")):
            return None, default, ""
        ecosystem = dependency.ecosystem or ""

        def source_of(package: str) -> dict[str, str]:
            return self._resolver._source_for(ecosystem, package, self._graph_version(package))

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

    def _once(self, cache: dict, key, compute):
        """(value, was_cached): run `compute` once per key without holding the lock while it runs."""
        token = (id(cache), key)
        while True:
            with self._dataflow_lock:
                if key in cache:
                    return cache[key], True
                pending = self._pending.get(token)
                if pending is None:
                    pending = self._pending[token] = threading.Event()
                    break
            pending.wait()
        try:
            value = compute()
            with self._dataflow_lock:
                cache[key] = value
            return value, False
        finally:
            with self._dataflow_lock:
                self._pending.pop(token, None)
            pending.set()

    def _package_usage(self, dependency, package: str, *,
                       record: list[str] | None = None) -> tuple[bool | None, str, bool]:
        """(used, detail, test_only): is the package imported by production code, not only by tests."""
        root = self._roots[0]
        ecosystem = dependency.ecosystem or ""
        text_used, text_detail, text_test_only = presence_mod.package_usage(root, ecosystem, package)
        language = _CODEQL_LANGUAGE.get(ecosystem.strip().lower())
        if not package or language not in codeql_api.SUPPORTED or language not in self._databases:
            return text_used, text_detail, text_test_only

        answer, cached = self._once(self._import_answers, (language, package), lambda: codeql_api.run_imports(
            self._databases[language], package, root, binary=self._codeql_binary))
        if record is not None:
            outcome = (f"не выполнен: {answer.problem}" if answer.problem else
                       f"рабочий код: {', '.join(str(h) for h in answer.production[:4]) or 'нет'}; "
                       f"тесты: {', '.join(str(h) for h in answer.tests[:4]) or 'нет'}")
            entry = (f"цепочка → CodeQL импорты пакета {package}: {outcome}"
                     f"{' (ответ из кэша прогона)' if cached else ''}")
            record.append(entry)
            log.info("codeql call: %s", entry)

        if answer.problem:
            return text_used, text_detail, text_test_only
        if answer.production:
            return True, (f"CodeQL: {package} импортируется в рабочем коде: "
                          f"{', '.join(str(h) for h in answer.production[:3])}"), False
        if text_used:
            return True, (f"CodeQL не нашёл импорта {package} в рабочем коде, но {text_detail} — "
                          "считается используемым (динамический require CodeQL не видит)"), False
        if answer.tests:
            return False, (f"CodeQL: {package} импортируется только в тестовом коде: "
                           f"{', '.join(str(h) for h in answer.tests[:3])}"), True
        return False, f"CodeQL: импортов {package} нет; {text_detail}", text_test_only

    def _uses_psalm(self, dependency) -> bool:
        return ((dependency.ecosystem or "").strip().lower() in psalm_api.SUPPORTED_ECOSYSTEMS
                and bool(self._psalm_binary) and bool(self._roots)
                and (self._roots[0] / "vendor" / "autoload.php").is_file())

    def _qualify_php_pairs(self, package: str, pairs) -> list[tuple[str, str]]:
        """Give each bare or short PHP method name the fully qualified classes that declare it."""
        pairs = list(pairs)
        bare = [function for function, klass in pairs if function and (not klass or "\\" not in klass)]
        declared = psalm_api.qualify(self._roots[0], package, bare) if bare and self._roots else {}
        out: list[tuple[str, str]] = []
        for function, klass in pairs:
            classes = declared.get(function) or []
            if klass and "\\" not in klass:
                classes = [fqcn for fqcn in classes if fqcn.rpartition("\\")[2] == klass]
            if (not klass or "\\" not in klass) and classes:
                out.extend((function, fqcn) for fqcn in classes if (function, fqcn) not in out)
            elif (function, klass) not in out:
                out.append((function, klass))
        return out

    def _engine_name(self, dependency) -> str:
        return psalm_api.ENGINE if self._uses_psalm(dependency) else "CodeQL"

    def _api_hint(self, dependency, package: str) -> str:
        """The installed PHP package's public methods, for the model's choice of questions."""
        if not self._uses_psalm(dependency) or not self._roots:
            return ""
        return psalm_api.public_api(self._roots[0], package)

    def _codeql_api_available(self, dependency) -> bool:
        """Whether an engine this chain may query answers for the dependency's language: a CodeQL database for JavaScript, Psalm with an installed vendor tree for PHP."""
        if self._uses_psalm(dependency):
            return True
        language = _CODEQL_LANGUAGE.get((dependency.ecosystem or "").strip().lower())
        return bool(self._roots) and language in codeql_api.SUPPORTED and language in self._databases

    def _psalm_api_for(self, dependency, package: str, pairs, *, record: list[str] | None,
                       asked_by: str) -> codeql_api.ApiAnswer | None:
        targets = tuple(sorted({codeql_api.Target(package, function, (klass or "").lstrip("\\"))
                                for function, klass in pairs if function},
                               key=lambda t: (t.klass, t.function)))
        if not targets:
            return None
        answer, cached = self._once(self._api_answers, ("php", targets), lambda: psalm_api.run(
            self._roots[0], list(targets), binary=self._psalm_binary))
        if record is not None:
            outcome = (f"не выполнен: {answer.problem}" if answer.problem else "; ".join(
                f"{t.label}: вызовов {len(answer.calls.get(t.label, []))}, "
                + (answer.reached[t.label].render() if t.label in answer.reached else "пути от ввода нет")
                for t in targets))
            entry = (f"{asked_by} → Psalm (типы и taint) пакета {package} ({', '.join(t.label for t in targets)}): "
                     f"{outcome}{' (ответ из кэша прогона)' if cached else ''}")
            record.append(entry)
            log.info("psalm call: %s", entry)
        return answer

    def _advisory_for(self, finding, dependency):
        """The advisory for this finding, fetched once per package and version."""
        identifiers = self._identifiers(finding)
        key = (identifiers[0] if identifiers else "", dependency.package or "",
               dependency.ecosystem or "", dependency.installed_version or "")
        advisory, _ = self._once(self._advisories, key,
                                 lambda: adv.collect(*key, nvd_api_key=self._nvd_api_key))
        return advisory

    def _resolve_symbol(self, advisory, version: str):
        """The vulnerable symbol for this advisory, resolved once per run."""
        key = (str(getattr(advisory, "advisory_id", "") or ""), version or "")
        symbol, _ = self._once(self._symbols, key, lambda: self._resolver.resolve(advisory, version))
        return symbol

    def _imports_absent(self, language: str, package: str) -> bool:
        """CodeQL resolved no import of this package anywhere in the project."""
        if not package or language not in codeql_api.SUPPORTED or language not in self._databases:
            return False
        answer, _ = self._once(self._import_answers, (language, package), lambda: codeql_api.run_imports(
            self._databases[language], package, self._roots[0], binary=self._codeql_binary))
        return answer.usable and not answer.sites

    def _codeql_api_for(self, dependency, package: str, pairs, *,
                        record: list[str] | None = None,
                        asked_by: str = "цепочка") -> codeql_api.ApiAnswer | None:
        """CodeQL's answer for these functions of `package`, or None when it cannot be asked."""
        if self._uses_psalm(dependency):
            return self._psalm_api_for(dependency, package, pairs, record=record, asked_by=asked_by)
        language = _CODEQL_LANGUAGE.get((dependency.ecosystem or "").strip().lower())
        database = self._databases.get(language or "")
        if database is None or language not in codeql_api.SUPPORTED or not self._roots or not package:
            return None
        targets = tuple(sorted({codeql_api.Target(package, function, klass or "")
                                for function, klass in pairs if function},
                               key=lambda t: (t.function, t.klass)))
        if not targets:
            return None
        if self._imports_absent(language, package):
            if record is not None:
                entry = (f"{asked_by} → CodeQL API пакета {package} "
                         f"({', '.join(t.label for t in targets)}): не запрошен — импортов пакета нет, "
                         "вызову неоткуда взяться")
                record.append(entry)
                log.info("codeql call skipped: %s", entry)
            return codeql_api.ApiAnswer()
        batched = self._batched.get((language, package))
        if batched is not None:
            shared, covered = batched
            labels = [t.label for t in targets]
            if all(label in covered for label in labels):
                if record is not None:
                    entry = (f"{asked_by} → CodeQL API пакета {package} ({', '.join(labels)}): "
                             + "; ".join(f"{label}: вызовов {len(shared.calls.get(label, []))}"
                                         for label in labels)
                             + " (из общего запроса прогона)")
                    record.append(entry)
                    log.info("codeql call: %s", entry)
                return shared
        answer, cached = self._once(self._api_answers, (language, targets), lambda: codeql_api.run(
            database, list(targets), self._roots[0], binary=self._codeql_binary))
        if record is not None:
            outcome = (f"не выполнен: {answer.problem}" if answer.problem else "; ".join(
                f"{t.label}: вызовов {len(answer.calls.get(t.label, []))}, "
                + (answer.reached[t.label].render() if t.label in answer.reached else "пути от ввода нет")
                for t in targets))
            entry = (f"{asked_by} → CodeQL API пакета {package} ({', '.join(t.label for t in targets)}): "
                     f"{outcome}{' (ответ из кэша прогона)' if cached else ''}")
            record.append(entry)
            log.info("codeql call: %s", entry)
        return answer

    def _dataflow_for(self, found, dependency, sites=None, *,
                      record: list[str] | None = None, asked_by: str = "цепочка"):
        language = _CODEQL_LANGUAGE.get((dependency.ecosystem or "").strip().lower())
        database = self._databases.get(language or "")
        if database is None:
            if record is not None:
                record.append(f"{asked_by} → CodeQL недоступен: нет базы для языка {language or dependency.ecosystem}")
            return None
        sites = sorted(sites or {(hit.file, hit.line) for hit in found.hits[:12]})
        if self._roots:
            root = self._roots[0]
            sites = [
                site for site in sites
                if (Path(site[0]) if Path(site[0]).is_absolute() else root / site[0]).is_file()
            ]
        if not sites:
            return None
        answer, cached = self._once(self._dataflow, (language, tuple(sites)), lambda: codeql_reach.run(
            database, language, sites, binary=self._codeql_binary))
        verdict = None if answer.problem else answer.verdict(sites)
        if record is not None:
            outcome = (f"не выполнен: {answer.problem}" if answer.problem
                       else verdict.render() if isinstance(verdict, codeql_reach.Reached)
                       else "путь от пользовательского ввода не найден" if verdict is False
                       else "позиции не оценены")
            entry = (f"{asked_by} → CodeQL, позиции {', '.join(f'{f}:{l}' for f, l in sites)}: "
                     f"{outcome}{' (ответ из кэша прогона)' if cached else ''}")
            record.append(entry)
            log.info("codeql call: %s", entry)
        if answer.problem:
            return f"поток данных не проверен: {answer.problem}"
        return verdict

    def _graph_version(self, package: str) -> str:
        for graph in self._graphs.values():
            version = graph.version_of(package)
            if version:
                return version
        return ""
