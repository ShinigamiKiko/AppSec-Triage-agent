"""CodeQL answers the dependency questions about the vulnerable function itself.

A text search finds `yaml.load(` and stops there. It cannot tell a call into the
package from a call on anything else named `load`, and it says nothing about
what flows into the call — so the trace was left to the model reading the file.
Asked through the API graph instead, CodeQL resolves the call to the package's
own export — through `require`, destructuring and reassignment — and the same
database then answers whether untrusted input reaches the arguments, with the
path step by step.

Measured on seeded projects before this was wired in: the call to `js-yaml.load`
was found in a helper module two calls below the request handler, with an
eight-step path across both files; a `load` of a shipped config file came back
called and unreached; an options object carrying `req.body.variable` into
`_.template` came back reached.

Only JavaScript has an API graph checked against a real database here. Other
languages keep the text search and the site-based query in `codeql_reach`, and
a language is added the same way that one was: against a database, with a
reachable and an unreachable call.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..testpaths import is_test
from .codeql_reach import _DIALECTS, Reached
from .presence import Hit, PresenceResult, SymbolPresence

log = logging.getLogger(__name__)

_TIMEOUT_S = 1800
SUPPORTED = frozenset({"javascript"})
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
 * @name Imports of a dependency package
 * @kind table
 * @id wolfee/sca-api-imports
 */
import javascript

from DataFlow::ModuleImportNode n, string path
where path = n.getPath() and (path = @PACKAGE@ or path.prefix(@LENGTH@) = @PREFIX@)
select n.getFile().getRelativePath() as file, n.getStartLine() as line
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


def call_predicate(targets: list[Target]) -> str:
    """`vulnerableCall(c, label)` for every shape the package is imported in."""
    clauses = []
    for target in targets:
        package, function = _ql_string(target.package), _ql_string(target.function)
        if target.klass:
            # Only this class's methods. A module-level shape here matched every
            # `load` the package exports when the advisory named `Type::load` —
            # measured on a seeded database — and a class-method flaw would then
            # open on any same-named call.
            klass = f"API::moduleImport({package}).getMember({_ql_string(target.klass)})"
            shapes = [f"{klass}.getInstance().getMember({function}).getACall()",
                      f"{klass}.getMember({function}).getACall()"]
        else:
            shapes = [
                f"API::moduleImport({package}).getMember({function}).getACall()",
                # Per-method packages: `require('lodash/template')`.
                f"API::moduleImport({_ql_string(target.package + '/' + target.function)}).getACall()",
            ]
        alternatives = "\n    or ".join(f"c = {shape}" for shape in shapes)
        clauses.append(f"  label = {_ql_string(target.label)} and (\n    {alternatives}\n  )")
    return ("predicate vulnerableCall(DataFlow::CallNode c, string label) {\n"
            + "\n  or\n".join(clauses) + "\n}\n")


def _location(location: dict) -> tuple[str, int, str] | None:
    physical = location.get("physicalLocation") or {}
    uri = (physical.get("artifactLocation") or {}).get("uri")
    line = (physical.get("region") or {}).get("startLine")
    if not uri or not isinstance(line, int):
        return None
    return uri, line, ((location.get("message") or {}).get("text") or "")


def parse_paths(document: dict) -> dict[str, Reached]:
    """The first path CodeQL reported per function, source first.

    A path whose source is the argument itself — `yaml.load(req.body)` — has no
    intermediate nodes, and CodeQL writes no `codeFlows` for it. That is still a
    reached call, with the source at the call site.
    """
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
    """Which analyser answered: `codeql` (API graph) or `psalm` (PHP types)."""

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
        """`Reached` with CodeQL's path, False when the calls exist and none is
        reached, None when this answer says nothing about the function."""
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
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s,
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
    """Where the application imports a package, split into production and test code.

    An import CodeQL resolved is a real `require`/`import` — never a comment, a
    string or a changelog line — and the test split comes from the same list the
    prompts carry (`testpaths`)."""

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


def imports_query(package: str) -> str:
    """The package itself and any subpath of it (`lodash/template`), nothing that merely starts alike."""
    prefix = package + "/"
    return (_IMPORTS_QUERY.replace("@PACKAGE@", _ql_string(package))
            .replace("@PREFIX@", _ql_string(prefix)).replace("@LENGTH@", str(len(prefix))))


def run_imports(database: Path | str, package: str, root: Path | str, *,
                binary: str = "codeql", timeout_s: float = _TIMEOUT_S) -> ImportAnswer:
    """Every import of `package` in this database, as positions in the project."""
    if not package:
        return ImportAnswer(problem="пакет не указан")
    database = Path(database)
    if not (database / "codeql-database.yml").is_file():
        return ImportAnswer(problem=f"база CodeQL не найдена или недостроена: {database}")
    with tempfile.TemporaryDirectory(prefix="sca-imports-") as work:
        pack = Path(work)
        (pack / "qlpack.yml").write_text(
            "name: wolfee/sca-imports\nversion: 0.0.1\n"
            "dependencies:\n  codeql/javascript-all: \"*\"\n", encoding="utf-8")
        (pack / "imports.ql").write_text(imports_query(package), encoding="utf-8")
        results = pack / "imports.bqrs"
        _, problem = _codeql([binary, "query", "run", f"--database={database}",
                              f"--output={results}", str(pack / "imports.ql")], timeout_s, "поиск импортов")
        if problem:
            return ImportAnswer(problem=problem)
        decoded, problem = _codeql([binary, "bqrs", "decode", "--format=csv", "--no-titles",
                                    str(results)], 180, "чтение импортов")
        if problem:
            return ImportAnswer(problem=problem)

    answer = ImportAnswer()
    seen: set[tuple[str, int]] = set()
    for row in csv.reader(io.StringIO(decoded)):
        if len(row) < 2:
            continue
        try:
            site = (row[0], int(row[1]))
        except ValueError:
            continue
        if site not in seen:
            seen.add(site)
            answer.sites.append(_hit(Path(root), *site))
    return answer


def run(database: Path | str, targets: list[Target], root: Path | str, *,
        binary: str = "codeql", timeout_s: float = _TIMEOUT_S) -> ApiAnswer:
    """Find the calls of these functions and the paths from user input into them."""
    targets = [t for t in targets if t.package and t.function]
    if not targets:
        return ApiAnswer(problem="нет функций для поиска")
    database = Path(database)
    if not (database / "codeql-database.yml").is_file():
        return ApiAnswer(problem=f"база CodeQL не найдена или недостроена: {database}")

    calls = call_predicate(targets)
    with tempfile.TemporaryDirectory(prefix="sca-api-") as work:
        pack = Path(work)
        (pack / "qlpack.yml").write_text(
            "name: wolfee/sca-api\nversion: 0.0.1\n"
            "dependencies:\n  codeql/javascript-all: \"*\"\n", encoding="utf-8")
        (pack / "calls.ql").write_text(_CALLS_QUERY.replace("@CALLS@", calls), encoding="utf-8")
        (pack / "reach.ql").write_text(
            _PATH_QUERY.replace("@HELPERS@", _DIALECTS["javascript"]["helpers"]).replace("@CALLS@", calls),
            encoding="utf-8")
        results, sarif = pack / "calls.bqrs", pack / "reach.sarif"

        _, problem = _codeql([binary, "query", "run", f"--database={database}",
                              f"--output={results}", str(pack / "calls.ql")], timeout_s, "поиск вызовов")
        if problem:
            return ApiAnswer(problem=problem)
        decoded, problem = _codeql([binary, "bqrs", "decode", "--format=csv", "--no-titles",
                                    str(results)], 180, "чтение вызовов")
        if problem:
            return ApiAnswer(problem=problem)
        _, problem = _codeql([binary, "database", "analyze", str(database), str(pack / "reach.ql"),
                              "--format=sarif-latest", f"--output={sarif}", "--rerun"],
                             timeout_s, "поиск пути")
        if problem:
            return ApiAnswer(problem=problem)
        try:
            document = json.loads(sarif.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            return ApiAnswer(problem=f"трасса CodeQL не прочитана: {exc}")

    answer = ApiAnswer()
    root = Path(root)
    for row in csv.reader(io.StringIO(decoded)):
        if len(row) < 3:
            continue
        try:
            answer.calls.setdefault(row[2], []).append(_hit(root, row[0], int(row[1])))
        except ValueError:
            continue
    answer.reached = parse_paths(document)
    log.info("codeql api: %s", ", ".join(
        f"{t.label}: {len(answer.calls.get(t.label, []))} calls, "
        f"{'reached' if t.label in answer.reached else 'not reached'}" for t in targets))
    return answer
