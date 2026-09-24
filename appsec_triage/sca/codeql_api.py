"""CodeQL answers the dependency questions about the vulnerable function itself."""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..testpaths import is_test
from .codeql_reach import _DIALECTS, Reached, query_flags, run_codeql
from .presence import Hit, PresenceResult, SymbolPresence

log = logging.getLogger(__name__)

_TIMEOUT_S = 1800
SUPPORTED = frozenset({"javascript", "go"})
_MESSAGE_PREFIX = "reaches "

_CALLS_QUERY = """/**
 * @name Calls of a vulnerable dependency function
 * @kind table
 * @id wolfee/sca-api-calls
 */
import javascript

@CALLS@
from DataFlow::CallNode c, string label
where vulnerableCall(c, label)
select c.getFile().getRelativePath() as path, c.getStartLine() as line, label
"""

_PATH_QUERY = """/**
 * @name User input reaching a vulnerable dependency function
 * @kind path-problem
 * @problem.severity warning
 * @id wolfee/sca-api-reach
 */
import javascript

@HELPERS@
@CALLS@
module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::CallNode c |
      vulnerableCall(c, _) and n.asExpr() = argumentPart(c.getAnArgument().asExpr()))
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, DataFlow::CallNode c, string label
where
  Flow::flowPath(source, sink) and
  vulnerableCall(c, label) and
  sink.getNode().asExpr() = argumentPart(c.getAnArgument().asExpr())
select sink.getNode(), source, sink, "reaches " + label
"""


_IMPORTS_QUERY = """/**
 * @name Imports of dependency packages
 * @kind table
 * @id wolfee/sca-api-imports
 */
import javascript

external predicate wantedPackage(string name);

from DataFlow::ModuleImportNode n, string path, string pkg
where
  wantedPackage(pkg) and path = n.getPath() and
  (path = pkg or path.prefix(pkg.length() + 1) = pkg + "/")
select n.getFile().getRelativePath() as file, n.getStartLine() as line, pkg
"""


# The functions asked about arrive as rows of `target(package, function, class, label)`,
# so the query text — and therefore its compiled form — is the same for every question.
_JS_CALL_PREDICATE = """external predicate target(string pkg, string fn, string klass, string label);

predicate vulnerableCall(DataFlow::CallNode c, string label) {
  exists(string pkg, string fn, string klass | target(pkg, fn, klass, label) |
    klass = "" and
    (
      c = API::moduleImport(pkg).getMember(fn).getACall()
      or
      // Per-method packages: `require('lodash/template')`.
      c = API::moduleImport(pkg + "/" + fn).getACall()
    )
    or
    klass = "@default" and
    (
      // The package is the function: `module.exports = serveStatic`, called as
      // `serveStatic(...)` after `require('serve-static')`.
      c = API::moduleImport(pkg).getACall()
      or
      // The same through a default import: `import serveStatic from 'serve-static'`.
      c = API::moduleImport(pkg).getMember("default").getACall()
    )
    or
    klass != "" and klass != "@default" and
    (
      c = API::moduleImport(pkg).getMember(klass).getInstance().getMember(fn).getACall()
      or
      c = API::moduleImport(pkg).getMember(klass).getMember(fn).getACall()
    )
  )
}
"""

_GO_CALL_PREDICATE = """external predicate target(string pkg, string fn, string klass, string label);

predicate vulnerableCall(DataFlow::CallNode c, string label) {
  exists(string pkg, string fn, string klass | target(pkg, fn, klass, label) |
    klass != "" and
    exists(Method m, string p |
      m = c.getTarget() and m.hasQualifiedName(p, klass, fn) and inModule(p, pkg)
    )
    or
    klass = "" and
    exists(Function f, string p |
      f = c.getTarget() and not f instanceof Method and
      f.hasQualifiedName(p, fn) and inModule(p, pkg)
    )
  )
}
"""


@dataclass(frozen=True, slots=True)
class Target:
    """One vulnerable function, named the way the application imports it."""

    package: str
    function: str
    klass: str = ""

    @property
    def label(self) -> str:
        return f"{self.klass}::{self.function}" if self.klass else self.function


def _ql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "") + '"'


DEFAULT_EXPORT = "@default"
_JS_NAME = r"[A-Za-z_$][\w$]*"
_REEXPORT = re.compile(r"""\bmodule\s*\.\s*exports\s*=\s*require\s*\(\s*['"](\.{1,2}/[^'"]+)['"]\s*\)""")
_ESM_DEFAULT = re.compile(
    rf"\bexport\s+default\s+(?:async\s+)?(?:function\s*\*?\s*|class\s+)?({_JS_NAME})|"
    rf"\bexports\s*\.\s*default\s*=\s*({_JS_NAME})\s*(?:;|$)|"
    rf"\bexport\s*\{{[^}}]*?\b({_JS_NAME})\s+as\s+default\b", re.MULTILINE)


def _entry_files(directory: Path) -> list[Path]:
    """The files `require(pkg)` and `import … from pkg` resolve to."""
    try:
        manifest = json.loads((directory / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        manifest = {}
    wanted: list[str] = []
    exports = manifest.get("exports")
    if isinstance(exports, dict):
        exports = exports.get(".", exports)
    if isinstance(exports, str):
        wanted.append(exports)
    elif isinstance(exports, dict):
        for condition in ("require", "node", "import", "default"):
            value = exports.get(condition)
            if isinstance(value, dict):
                value = value.get("default")
            if isinstance(value, str):
                wanted.append(value)
    for key in ("main", "module"):
        if isinstance(manifest.get(key), str):
            wanted.append(manifest[key])
    wanted.append("index.js")
    found: list[Path] = []
    for rel in wanted:
        for candidate in (directory / rel, directory / f"{rel}.js", directory / rel / "index.js"):
            if candidate.is_file() and candidate not in found:
                found.append(candidate)
                break
    return found


def _package_as_name(package: str) -> str:
    """`serve-static` -> `serveStatic`, `@scope/cookie-parser` -> `cookieParser`."""
    parts = [p for p in re.split(r"[-_.]", package.rsplit("/", 1)[-1]) if p]
    return parts[0] + "".join(p[:1].upper() + p[1:] for p in parts[1:]) if parts else ""


def default_exports(root: Path | str, package: str) -> set[str] | None:
    """Names the package's entry file exports as the module itself; None when not installed.

    Calling such a package calls that function: `serveStatic(...)` after
    `import serveStatic from 'serve-static'` is a call of the module, not of a member
    named `serveStatic`, and an API-graph query for the member never sees it.
    """
    from . import declarations as decl
    from . import registries

    directory = registries.locate(Path(root), "npm", package, "")
    if directory is None:
        return None
    names: set[str] = set()
    files = _entry_files(directory)
    seen: set[Path] = set()
    while files:
        entry = files.pop(0)
        if entry in seen or len(seen) > 4:
            continue
        seen.add(entry)
        try:
            text = entry.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        names |= decl.default_export_names(text)
        names |= {name for match in _ESM_DEFAULT.finditer(text) for name in match.groups() if name}
        # `module.exports = require('./lib/express')`: the export lives one file further.
        for rel in _REEXPORT.findall(text):
            target = (entry.parent / rel).resolve()
            for candidate in (target, target.with_suffix(".js"), target / "index.js"):
                if candidate.is_file():
                    files.append(candidate)
                    break
    return names


def target_rows(targets: list[Target], language: str = "javascript",
                defaults: dict[str, set[str] | None] | None = None) -> list[tuple[str, str, str, str]]:
    """Rows for the `target` external predicate.

    A function that is the package's default export is asked a second time in the
    form the application calls it — the module itself — under the same label.
    Where the package is not installed, its name is the only hint: `serve-static`
    exports `serveStatic` by the convention nearly every such package follows.
    """
    rows = []
    for target in targets:
        klass = target.klass
        if language == "go":
            klass = klass.lstrip("*").split(".")[-1]
        rows.append((target.package, target.function, klass, target.label))
        if language != "javascript" or klass or defaults is None:
            continue
        # Calling the module calls its default export whatever it is called inside;
        # the package name is how applications and advisories name it.
        known = defaults.get(target.package) or set()
        is_default = (target.function in known
                      or target.function == _package_as_name(target.package))
        if is_default:
            rows.append((target.package, target.function, DEFAULT_EXPORT, target.label))
    return rows


def call_predicate(targets: list[Target] | None = None, language: str = "javascript") -> str:
    """`vulnerableCall(c, label)`, driven by the `target` rows rather than inlined names."""
    return _GO_CALL_PREDICATE if language == "go" else _JS_CALL_PREDICATE


_GO_MODULE_PREDICATE = """bindingset[path, mod]
predicate inModule(string path, string mod) {
  path = mod or path.prefix(mod.length() + 1) = mod + "/"
}
"""

_GO_CALLS_QUERY = """/**
 * @name Calls of a vulnerable dependency function
 * @kind table
 * @id wolfee/sca-api-calls-go
 */
import go

""" + _GO_MODULE_PREDICATE + """
@CALLS@
from DataFlow::CallNode c, string label
where vulnerableCall(c, label)
select c.asExpr().getFile().getRelativePath() as path, c.asExpr().getLocation().getStartLine() as line, label
"""

_GO_PATH_QUERY = """/**
 * @name User input reaching a vulnerable dependency function
 * @kind path-problem
 * @problem.severity warning
 * @id wolfee/sca-api-reach-go
 */
import go

""" + _GO_MODULE_PREDICATE + """
@CALLS@
/** Where untrusted data enters a vulnerable call: an argument, or the receiver of a method. */
predicate enters(DataFlow::Node n, DataFlow::CallNode c) {
  n = c.getAnArgument() or n = c.getReceiver()
}

module Cfg implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { n instanceof RemoteFlowSource }

  predicate isSink(DataFlow::Node n) {
    exists(DataFlow::CallNode c | vulnerableCall(c, _) and enters(n, c))
  }
}

module Flow = TaintTracking::Global<Cfg>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, DataFlow::CallNode c, string label
where
  Flow::flowPath(source, sink) and
  vulnerableCall(c, label) and
  enters(sink.getNode(), c)
select sink.getNode(), source, sink, "reaches " + label
"""

_GO_IMPORTS_QUERY = """/**
 * @name Imports of a dependency package
 * @kind table
 * @id wolfee/sca-api-imports-go
 */
import go

""" + _GO_MODULE_PREDICATE + """
external predicate wantedPackage(string name);

from ImportSpec s, string pkg
where wantedPackage(pkg) and inModule(s.getPath(), pkg)
select s.getFile().getRelativePath() as file, s.getLocation().getStartLine() as line, pkg
"""


def database_language(database: Path | str) -> str:
    """The language a CodeQL database was built for, read from its own metadata."""
    import re

    try:
        text = (Path(database) / "codeql-database.yml").read_text(encoding="utf-8")
    except OSError:
        return ""
    match = re.search(r'^primaryLanguage:\s*"?([A-Za-z]+)"?\s*$', text, re.M)
    return match.group(1).lower() if match else ""


def _queries(language: str) -> tuple[str, str]:
    """(calls query, path query) for a language, with `@CALLS@` left to fill."""
    if language == "go":
        return _GO_CALLS_QUERY, _GO_PATH_QUERY
    return _CALLS_QUERY, _PATH_QUERY.replace("@HELPERS@", _DIALECTS["javascript"]["helpers"])


def _location(location: dict) -> tuple[str, int, str] | None:
    physical = location.get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    line = (physical.get("region") or {}).get("startLine")
    if not uri or not isinstance(line, int):
        return None
    return uri, line, ((location.get("message") or {}).get("text") or "")


def parse_paths(document: dict) -> dict[str, Reached]:
    """The first path CodeQL reported per function, source first."""
    found: dict[str, Reached] = {}
    for run_ in document.get("runs") or []:
        for result in run_.get("results") or []:
            text = (result.get("message") or {}).get("text") or ""
            label = text[len(_MESSAGE_PREFIX):] if text.startswith(_MESSAGE_PREFIX) else text
            sink = _location((result.get("locations") or [{}])[0])
            if sink is None or label in found:
                continue
            steps: list[tuple[str, int, str]] = []
            for flow in (result.get("codeFlows") or [])[:1]:
                for thread in (flow.get("threadFlows") or [])[:1]:
                    for step in thread.get("locations") or []:
                        if (where := _location(step.get("location") or {})) is not None:
                            steps.append(where)
            source = steps[0] if steps else sink
            found[label] = Reached(
                sink[0], sink[1], source[0], source[1],
                steps=[f"{file}:{line} {expression}".strip() for file, line, expression in steps],
            )
    return found


@dataclass(slots=True)
class ApiAnswer:
    """What CodeQL established about these functions in one database."""

    calls: dict[str, list[Hit]] = field(default_factory=dict)
    reached: dict[str, Reached] = field(default_factory=dict)
    problem: str = ""
    engine: str = "codeql"

    @property
    def usable(self) -> bool:
        return not self.problem

    @property
    def engine_name(self) -> str:
        return "Psalm" if self.engine == "psalm" else "CodeQL"

    def presence(self, label: str) -> PresenceResult:
        hits = self.calls.get(label) or []
        how = "по типам PHP" if self.engine == "psalm" else "по API пакета"
        if not hits:
            return PresenceResult(SymbolPresence.ABSENT, label,
                                  detail=f"{self.engine_name} не нашёл вызовов {label} {how}")
        return PresenceResult(SymbolPresence.CALLED, label, hits,
                              detail=f"вызов {label} разрешён {self.engine_name} {how}, а не совпадением имени")

    def dataflow(self, label: str) -> Reached | bool | None:
        """`Reached` with CodeQL's path, False when the calls exist and none is reached, None when this answer says nothing about the function."""
        if self.problem:
            return None
        if label in self.reached:
            return self.reached[label]
        return False if self.calls.get(label) else None


def _hit(root: Path, file: str, line: int) -> Hit:
    try:
        lines = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        text = ""
    return Hit(file, line, text, in_tests=is_test(file))


def _codeql(argv: list[str], timeout_s: float, what: str) -> tuple[str, str]:
    """(stdout, problem) — problem empty when the command succeeded."""
    try:
        proc = run_codeql(argv, capture_output=True, text=True, timeout=timeout_s,
                              encoding="utf-8", errors="replace", check=False)
    except subprocess.TimeoutExpired:
        return "", f"{what}: CodeQL не уложился в {timeout_s}с"
    except OSError as exc:
        return "", f"{what}: codeql не запустился: {exc}"
    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or "").strip().splitlines()[-4:])
        return "", f"{what}: CodeQL завершился с ошибкой: {tail[:300]}"
    return proc.stdout, ""


@dataclass(slots=True)
class ImportAnswer:
    """Where the application imports a package, split into production and test code."""

    sites: list[Hit] = field(default_factory=list)
    problem: str = ""

    @property
    def usable(self) -> bool:
        return not self.problem

    @property
    def production(self) -> list[Hit]:
        return [hit for hit in self.sites if not hit.in_tests]

    @property
    def tests(self) -> list[Hit]:
        return [hit for hit in self.sites if hit.in_tests]


def imports_query(language: str = "javascript") -> str:
    """The package itself and any subpath of it (`lodash/template`), for every wanted package."""
    return _GO_IMPORTS_QUERY if language == "go" else _IMPORTS_QUERY


def _source_prefix(database: Path) -> list[str]:
    """`--source-location-prefix` so interpreted paths come out relative, as `analyze` gave them."""
    import re

    try:
        text = (database / "codeql-database.yml").read_text(encoding="utf-8")
    except OSError:
        return []
    match = re.search(r'^sourceLocationPrefix:\s*"?([^"\n]+?)"?\s*$', text, re.M)
    if not match:
        return []
    archive = next((c for c in (database / "src.zip", database / "src") if c.exists()), None)
    if archive is None:
        return []
    return [f"--source-archive={archive}", f"--source-location-prefix={match.group(1)}"]


def _database_problem(database: Path) -> tuple[str, str]:
    """(language, problem) for a database about to be queried."""
    if not (database / "codeql-database.yml").is_file():
        return "", f"база CodeQL не найдена или недостроена: {database}"
    language = database_language(database)
    if language not in SUPPORTED:
        return language, f"запросы для языка {language or 'неизвестен'} не написаны"
    return language, ""


def run_imports_many(database: Path | str, packages: list[str], root: Path | str, *,
                     binary: str = "codeql", timeout_s: float = _TIMEOUT_S) -> dict[str, ImportAnswer]:
    """Every import of every one of `packages`, in one query.

    One question per package was 43 compilations and 43 evaluations at the
    start of a 43-package run — 12 to 23 minutes before the first verdict.
    """
    from .codeql_runner import query_file, write_external

    wanted = sorted({p for p in packages if p})
    if not wanted:
        return {}
    database = Path(database)
    language, problem = _database_problem(database)
    if problem:
        return {p: ImportAnswer(problem=problem) for p in wanted}
    query = query_file(language, imports_query(language))
    with tempfile.TemporaryDirectory(prefix="sca-imports-") as work:
        work_dir = Path(work)
        rows = write_external(work_dir, "wantedPackage", [(p,) for p in wanted])
        results = work_dir / "imports.bqrs"
        _, problem = _codeql([binary, "query", "run", *query_flags(), f"--database={database}",
                              f"--external=wantedPackage={rows}",
                              f"--output={results}", str(query)], timeout_s, "поиск импортов")
        if problem:
            return {p: ImportAnswer(problem=problem) for p in wanted}
        decoded, problem = _codeql([binary, "bqrs", "decode", "--format=csv", "--no-titles",
                                    str(results)], 180, "чтение импортов")
        if problem:
            return {p: ImportAnswer(problem=problem) for p in wanted}

    answers = {p: ImportAnswer() for p in wanted}
    seen: set[tuple[str, str, int]] = set()
    for row in csv.reader(io.StringIO(decoded)):
        if len(row) < 3 or row[2] not in answers:
            continue
        try:
            site = (row[2], row[0], int(row[1]))
        except ValueError:
            continue
        if site not in seen:
            seen.add(site)
            answers[row[2]].sites.append(_hit(Path(root), row[0], int(row[1])))
    log.info("codeql imports: %d package(s) in one query, %d imported", len(wanted),
             sum(1 for a in answers.values() if a.sites))
    return answers


def run_imports(database: Path | str, package: str, root: Path | str, *,
                binary: str = "codeql", timeout_s: float = _TIMEOUT_S) -> ImportAnswer:
    """Every import of `package` in this database, as positions in the project."""
    if not package:
        return ImportAnswer(problem="пакет не указан")
    return run_imports_many(database, [package], root, binary=binary, timeout_s=timeout_s)[package]


def run(database: Path | str, targets: list[Target], root: Path | str, *,
        binary: str = "codeql", timeout_s: float = _TIMEOUT_S) -> ApiAnswer:
    """Find the calls of these functions and the paths from user input into them."""
    from .codeql_runner import query_file, write_external

    targets = [t for t in targets if t.package and t.function]
    if not targets:
        return ApiAnswer(problem="нет функций для поиска")
    database = Path(database)
    language, problem = _database_problem(database)
    if problem:
        return ApiAnswer(problem=problem)
    calls = call_predicate(targets, language)
    calls_query, path_query = _queries(language)
    calls_file = query_file(language, calls_query.replace("@CALLS@", calls))
    reach_file = query_file(language, path_query.replace("@CALLS@", calls))
    with tempfile.TemporaryDirectory(prefix="sca-api-") as work:
        work_dir = Path(work)
        defaults = ({package: default_exports(root, package)
                     for package in {t.package for t in targets if not t.klass}}
                    if language == "javascript" else None)
        rows = write_external(work_dir, "target", target_rows(targets, language, defaults))
        external = f"--external=target={rows}"
        results, reach_bqrs, sarif = work_dir / "calls.bqrs", work_dir / "reach.bqrs", work_dir / "reach.sarif"

        _, problem = _codeql([binary, "query", "run", *query_flags(), f"--database={database}",
                              external, f"--output={results}", str(calls_file)], timeout_s, "поиск вызовов")
        if problem:
            return ApiAnswer(problem=problem)
        decoded, problem = _codeql([binary, "bqrs", "decode", "--format=csv", "--no-titles",
                                    str(results)], 180, "чтение вызовов")
        if problem:
            return ApiAnswer(problem=problem)

        answer = ApiAnswer()
        root = Path(root)
        for row in csv.reader(io.StringIO(decoded)):
            if len(row) < 3:
                continue
            try:
                answer.calls.setdefault(row[2], []).append(_hit(root, row[0], int(row[1])))
            except ValueError:
                continue

        if answer.calls:
            # `query run` + `bqrs interpret` is what `database analyze` does inside,
            # but it takes the external predicate and keeps the compiled query cached.
            _, problem = _codeql([binary, "query", "run", *query_flags(), f"--database={database}",
                                  external, f"--output={reach_bqrs}", str(reach_file)],
                                 timeout_s, "поиск пути")
            if problem:
                return ApiAnswer(problem=problem)
            _, problem = _codeql([binary, "bqrs", "interpret", "--format=sarif-latest",
                                  "-t=kind=path-problem", f"-t=id=wolfee/sca-api-reach-{language}",
                                  *_source_prefix(database),
                                  f"--output={sarif}", str(reach_bqrs)], 300, "чтение пути")
            if problem:
                return ApiAnswer(problem=problem)
            try:
                document = json.loads(sarif.read_text(encoding="utf-8"))
            except (OSError, ValueError) as exc:
                return ApiAnswer(problem=f"трасса CodeQL не прочитана: {exc}")
            answer.reached = parse_paths(document)

    log.info("codeql api: %s", ", ".join(
        f"{t.label}: {len(answer.calls.get(t.label, []))} calls, "
        f"{'reached' if t.label in answer.reached else 'not reached'}" for t in targets))
    return answer
