"""Does attacker-controlled input reach the line where a dependency is called."""

from __future__ import annotations

import csv
import io
import logging
import os
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_THREADS = os.environ.get("APPSEC_CODEQL_THREADS", "0")
_RAM_MB = os.environ.get("APPSEC_CODEQL_RAM_MB", "6000")


def query_flags() -> list[str]:
    """What an evaluating command may use."""
    return [f"--threads={_THREADS}", f"--ram={_RAM_MB}"]


_DATABASE_LOCKS: dict[str, threading.Lock] = {}
_DATABASE_LOCKS_GUARD = threading.Lock()


def _database_of(argv: list[str]) -> str | None:
    """The database an invocation opens, or None when it opens none (`bqrs decode`)."""
    for index, arg in enumerate(argv):
        if arg.startswith("--database="):
            return arg.split("=", 1)[1]
        if arg == "analyze" and index + 1 < len(argv) and argv[index - 1:index] == ["database"]:
            return argv[index + 1]
    return None


def database_lock(database: str | Path) -> threading.Lock:
    key = str(Path(database).resolve())
    with _DATABASE_LOCKS_GUARD:
        return _DATABASE_LOCKS.setdefault(key, threading.Lock())


def run_codeql(argv: list[str], **kwargs) -> subprocess.CompletedProcess:
    """`subprocess.run` for a CodeQL command, holding its database's lock while it runs."""
    database = _database_of(argv)
    if database is None:
        return subprocess.run(argv, **kwargs)
    with database_lock(database):
        return subprocess.run(argv, **kwargs)

_TIMEOUT_S = 1800

_DIALECTS = {
    "go": {
        "imports": "import go\nimport semmle.go.security.FlowSources",
        "helpers": "",
        "source": "n instanceof UntrustedFlowSource",
        "call": "CallExpr",
        "argument": "n.asExpr() = c.getAnArgument()",
    },
    "javascript": {
        "imports": "import javascript",
        "helpers": (
            "Expr argumentPart(Expr argument) {\n"
            "  result = argument\n"
            "  or result = argumentPart(argument).(ObjectExpr).getAProperty().getInit()\n"
            "  or result = argumentPart(argument).(ArrayExpr).getAnElement()\n"
            "}\n"
        ),
        "source": "n instanceof RemoteFlowSource",
        "call": "CallExpr",
        "argument": "n.asExpr() = argumentPart(c.getAnArgument())",
    },
}

_QUERY = """/**
 * @name User input reaching a dependency call site
 * @description Whether a remote flow source reaches a call this triage asked about.
 * @kind table
 * @id wolfee/sca-reach
 */
{imports}

{helpers}
predicate target(string path, int line) {{
{targets}
}}

module Cfg implements DataFlow::ConfigSig {{
  predicate isSource(DataFlow::Node n) {{ {source} }}

  predicate isSink(DataFlow::Node n) {{
    exists({call} c |
      {argument} and
      target(c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine())
    )
  }}
}}

module Flow = TaintTracking::Global<Cfg>;

from DataFlow::Node source, DataFlow::Node sink, {call} c
where
  Flow::flow(source, sink) and
  {argument_sink} and
  target(c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine())
select
  c.getLocation().getFile().getRelativePath() as path,
  c.getLocation().getStartLine() as line,
  source.getLocation().getFile().getRelativePath() as source_path,
  source.getLocation().getStartLine() as source_line
"""

_EVALUATED_QUERY = """/**
 * @name CodeQL call sites evaluated for SCA reachability
 * @description Call sites that exist in the CodeQL database and were eligible for the query.
 * @kind table
 * @id wolfee/sca-reach-evaluated
 */
{imports}

predicate target(string path, int line) {{
{targets}
}}

from {call} c
where
  target(c.getLocation().getFile().getRelativePath(), c.getLocation().getStartLine()) and
  exists(c.getAnArgument())
select
  c.getLocation().getFile().getRelativePath() as path,
  c.getLocation().getStartLine() as line
"""


@dataclass(slots=True)
class Reached:
    """One call site the query proved reachable, and where the input enters."""

    file: str
    line: int
    source_file: str = ""
    source_line: int = 0
    steps: list[str] = field(default_factory=list)
    engine: str = "CodeQL"

    @property
    def site(self) -> tuple[str, int]:
        return (self.file, self.line)

    def render(self) -> str:
        head = (f"{self.engine}: пользовательский ввод из {self.source_file}:{self.source_line} "
                f"доходит до {self.file}:{self.line}")
        if len(self.steps) > 1:
            return f"{head}; трасса {self.engine}: {' → '.join(self.steps[:12])}"
        return head


@dataclass(slots=True)
class Answer:
    """What the query established for the whole batch of call sites."""

    asked: set[tuple[str, int]] = field(default_factory=set)
    evaluated: set[tuple[str, int]] = field(default_factory=set)
    reached: dict[tuple[str, int], Reached] = field(default_factory=dict)
    problem: str = ""

    @property
    def usable(self) -> bool:
        return not self.problem

    def verdict(self, sites: list[tuple[str, int]]) -> Reached | None | bool:
        """`Reached` when input arrives, False when it provably does not, None when this batch never asked about these sites."""
        if self.problem:
            return None
        hit = next((self.reached[s] for s in sites if s in self.reached), None)
        if hit is not None:
            return hit
        return False if any(s in self.evaluated for s in sites) else None


def _predicate(sites: list[tuple[str, int]]) -> str:
    clauses = [f'  path = "{file}" and line = {line}'
               for file, line in sorted(sites)]
    return "\n  or\n".join(clauses)


def run(database: Path | str, language: str, sites: list[tuple[str, int]],
        *, binary: str = "codeql", timeout_s: int = _TIMEOUT_S) -> Answer:
    """Ask one database which of these call sites user input reaches."""
    wanted = sorted({(str(f), int(l)) for f, l in sites if f and l})
    if not wanted:
        return Answer(problem="нет мест вызова для проверки")

    dialect = _DIALECTS.get((language or "").strip().lower())
    if dialect is None:
        return Answer(problem=f"запрос достижимости для языка {language!r} не написан")

    database = Path(database)
    if not (database / "codeql-database.yml").is_file():
        return Answer(problem=f"база CodeQL не найдена или недостроена: {database}")

    query = _QUERY.format(
        imports=dialect["imports"], helpers=dialect["helpers"],
        source=dialect["source"], call=dialect["call"],
        argument=dialect["argument"],
        argument_sink=dialect["argument"].replace("n.", "sink."),
        targets=_predicate(wanted),
    )

    with tempfile.TemporaryDirectory(prefix="sca-reach-") as work:
        pack = Path(work)
        (pack / "qlpack.yml").write_text(
            f"name: wolfee/sca-reachability\nversion: 0.0.1\n"
            f"dependencies:\n  codeql/{language}-all: \"*\"\n", encoding="utf-8")
        query_file = pack / "reach.ql"
        query_file.write_text(query, encoding="utf-8")
        evaluated_file = pack / "evaluated.ql"
        evaluated_file.write_text(_EVALUATED_QUERY.format(
            imports=dialect["imports"], call=dialect["call"], targets=_predicate(wanted)
        ), encoding="utf-8")
        results = pack / "results.bqrs"
        evaluated_results = pack / "evaluated.bqrs"

        argv = [binary, "query", "run", *query_flags(), f"--database={database}",
                f"--output={results}", str(query_file)]
        try:
            proc = run_codeql(argv, capture_output=True, text=True,
                                  timeout=timeout_s, encoding="utf-8", errors="replace", check=False)
        except subprocess.TimeoutExpired:
            return Answer(problem=f"запрос CodeQL не уложился в {timeout_s}с")
        except OSError as exc:
            return Answer(problem=f"codeql не запустился: {exc}")
        if proc.returncode != 0:
            tail = "\n".join((proc.stderr or "").strip().splitlines()[-4:])
            return Answer(problem=f"запрос CodeQL не выполнился: {tail[:300]}")

        try:
            evaluated_proc = run_codeql(
                [binary, "query", "run", *query_flags(), f"--database={database}",
                 f"--output={evaluated_results}", str(evaluated_file)],
                capture_output=True, text=True, timeout=timeout_s,
                encoding="utf-8", errors="replace", check=False,
            )
        except subprocess.TimeoutExpired:
            return Answer(problem=f"проверка позиций CodeQL не уложилась в {timeout_s}с")
        except OSError as exc:
            return Answer(problem=f"codeql не запустился для проверки позиций: {exc}")
        if evaluated_proc.returncode != 0:
            tail = "\n".join((evaluated_proc.stderr or "").strip().splitlines()[-4:])
            return Answer(problem=f"проверка позиций CodeQL не выполнилась: {tail[:300]}")

        decode = [binary, "bqrs", "decode", "--format=csv", "--no-titles", str(results)]
        try:
            decoded = run_codeql(decode, capture_output=True, text=True,
                timeout=180, encoding="utf-8", errors="replace", check=False)
        except (subprocess.TimeoutExpired, OSError) as exc:
            return Answer(problem=f"результат CodeQL не прочитан: {exc}")
        if decoded.returncode != 0:
            return Answer(problem="результат CodeQL не прочитан: bqrs decode отказал")

        evaluated_decode = run_codeql(
            [binary, "bqrs", "decode", "--format=csv", "--no-titles", str(evaluated_results)],
            capture_output=True, text=True, timeout=180,
            encoding="utf-8", errors="replace", check=False,
        )
        if evaluated_decode.returncode != 0:
            return Answer(problem="позиции CodeQL не прочитаны: bqrs decode отказал")

    answer = Answer(asked=set(wanted))
    for row in csv.reader(io.StringIO(evaluated_decode.stdout)):
        if len(row) < 2:
            continue
        try:
            answer.evaluated.add((row[0], int(row[1])))
        except ValueError:
            continue
    for row in csv.reader(io.StringIO(decoded.stdout)):
        if len(row) < 4:
            continue
        try:
            found = Reached(row[0], int(row[1]), row[2], int(row[3]))
        except ValueError:
            continue
        answer.reached.setdefault(found.site, found)

    log.info("codeql reachability: %d of %d call sites reached",
             len(answer.reached), len(answer.asked))
    return answer
