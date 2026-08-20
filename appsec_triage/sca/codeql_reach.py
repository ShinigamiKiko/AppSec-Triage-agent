"""Does attacker-controlled input reach the line where a dependency is called.

This is the question SARIF cannot answer. A SARIF report carries the paths
CodeQL already judged to be flaws, and a call into a library is not one of them —
`ldap.DialURL(url)` is ordinary code to a security suite. So the report is silent
about exactly the lines a dependency triage cares about, and the only way to ask
is to query the database directly.

The database is the one the SAST phase built and no longer throws away. Building
it costs minutes; querying it costs seconds, and both phases run in the same
container against the same source tree, so the answer is about the code that was
actually scanned.

One query per run, not one per finding: every call site of every advisory goes
into a single generated predicate, the query is evaluated once, and the reachable
subset comes back. A project with sixty dependency findings would otherwise pay
sixty query evaluations for one database.

Go and JavaScript are implemented. The dataflow libraries name their sources
differently in each language — `UntrustedFlowSource` in Go, `RemoteFlowSource`
in JavaScript — and a guessed query compiles into either an error or, worse, an
empty result that reads as "not reachable". So a language is added only after
its query has been run against a real database and shown to separate a reachable
call site from an unreachable one; a language without an entry here is reported
as unsupported rather than answered with silence.
"""

from __future__ import annotations

import csv
import io
import logging
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

_TIMEOUT_S = 900

# Per language: the imports and the two expressions that differ. Absent means
# the language is not supported, which is reported rather than guessed at.
_DIALECTS = {
    "go": {
        "imports": "import go\nimport semmle.go.security.FlowSources",
        "source": "n instanceof UntrustedFlowSource",
        "call": "CallExpr",
        "argument": "n.asExpr() = c.getAnArgument()",
    },
    # Checked against a real database rather than assumed to mirror Go: the
    # source class has a different name, and the taint had to survive a closure
    # and an event handler — `req.on('data') -> body -> JSON.parse -> merge` —
    # which it does. The call and argument shapes turn out to be the same.
    "javascript": {
        "imports": "import javascript",
        "source": "n instanceof RemoteFlowSource",
        "call": "CallExpr",
        "argument": "n.asExpr() = c.getAnArgument()",
    },
}

_QUERY = """/**
 * @name User input reaching a dependency call site
 * @description Whether a remote flow source reaches a call this triage asked about.
 * @kind table
 * @id wolfee/sca-reach
 */
{imports}

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


@dataclass(slots=True)
class Reached:
    """One call site the query proved reachable, and where the input enters."""

    file: str
    line: int
    source_file: str = ""
    source_line: int = 0

    @property
    def site(self) -> tuple[str, int]:
        return (self.file, self.line)

    def render(self) -> str:
        return (f"CodeQL: пользовательский ввод из {self.source_file}:{self.source_line} "
                f"доходит до {self.file}:{self.line}")


@dataclass(slots=True)
class Answer:
    """What the query established for the whole batch of call sites.

    `asked` is what went in and `reached` is what came back; a site in `asked`
    and absent from `reached` was examined and no path was found. `problem` being
    set means the query did not run at all — then nothing was examined, and the
    difference between those two states is the whole point of this class.
    """

    asked: set[tuple[str, int]] = field(default_factory=set)
    reached: dict[tuple[str, int], Reached] = field(default_factory=dict)
    problem: str = ""

    @property
    def usable(self) -> bool:
        return not self.problem

    def verdict(self, sites: "list[tuple[str, int]]") -> "Reached | None | bool":
        """`Reached` when input arrives, False when it provably does not, None
        when this batch never asked about these sites."""
        if self.problem:
            return None
        hit = next((self.reached[s] for s in sites if s in self.reached), None)
        if hit is not None:
            return hit
        return False if any(s in self.asked for s in sites) else None


def _predicate(sites: "list[tuple[str, int]]") -> str:
    clauses = [f'  path = "{file}" and line = {line}'
               for file, line in sorted(sites)]
    return "\n  or\n".join(clauses)


def run(database: Path | str, language: str, sites: "list[tuple[str, int]]",
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
        imports=dialect["imports"], source=dialect["source"], call=dialect["call"],
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
        results = pack / "results.bqrs"

        argv = [binary, "query", "run", f"--database={database}",
                f"--output={results}", str(query_file)]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=timeout_s, encoding="utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            return Answer(problem=f"запрос CodeQL не уложился в {timeout_s}с")
        except OSError as exc:
            return Answer(problem=f"codeql не запустился: {exc}")
        if proc.returncode != 0:
            tail = "\n".join((proc.stderr or "").strip().splitlines()[-4:])
            return Answer(problem=f"запрос CodeQL не выполнился: {tail[:300]}")

        decode = [binary, "bqrs", "decode", "--format=csv", "--no-titles", str(results)]
        try:
            decoded = subprocess.run(decode, capture_output=True, text=True,
                                     timeout=120, encoding="utf-8", errors="replace")
        except (subprocess.TimeoutExpired, OSError) as exc:
            return Answer(problem=f"результат CodeQL не прочитан: {exc}")
        if decoded.returncode != 0:
            return Answer(problem="результат CodeQL не прочитан: bqrs decode отказал")

    answer = Answer(asked=set(wanted))
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
