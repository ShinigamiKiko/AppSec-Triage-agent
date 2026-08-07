"""Targeted Go taint query seeded by govulncheck application call sites."""

from __future__ import annotations

import json
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..ingest.govulncheck import parse as parse_govulncheck


@dataclass(frozen=True, slots=True)
class Target:
    file_path: str
    line: int


def targets_from_report(path: Path) -> list[Target]:
    targets = {
        Target(finding.trace[0].file_path.replace("\\", "/"), finding.trace[0].line)
        for finding in parse_govulncheck(path)
        if finding.trace and finding.trace[0].file_path and finding.trace[0].line
    }
    return sorted(targets, key=lambda target: (target.file_path, target.line))


def _ql_string(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "") + '"'


def render_query(targets: list[Target]) -> str:
    clauses = "\n    or ".join(
        "(call.getFile().getRelativePath() = "
        f"{_ql_string(target.file_path)} and call.getLocation().getStartLine() = {target.line})"
        for target in targets
    ) or "false"
    return f'''/**
 * @name User-controlled input reaching a govulncheck call site
 * @description Tracks active remote-flow sources to exact application call sites reported by govulncheck.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision high
 * @id go/govulncheck-targeted-taint
 * @tags security
 *       external/cwe/cwe-020
 */

import go

predicate isGovulncheckCall(CallExpr call) {{
  {clauses}
}}

module GovulncheckTargetConfig implements DataFlow::ConfigSig {{
  additional predicate isFiberInput(DataFlow::Node source) {{
    exists(DataFlow::CallNode call |
      call.getTarget().(Method).hasQualifiedName(
        ["github.com/gofiber/fiber/v2", "github.com/gofiber/fiber/v3"],
        "Ctx",
        ["Body", "FormValue", "Get", "Params", "Query"]
      ) and source = call
    )
    or
    exists(DataFlow::CallNode call |
      call.getTarget().(Method).hasQualifiedName(
        ["github.com/gofiber/fiber/v2", "github.com/gofiber/fiber/v3"],
        "Bind",
        ["Body", "Form", "Header", "Query", "URI"]
      ) and source = call.getAnArgument()
    )
  }}

  predicate isSource(DataFlow::Node source) {{
    source instanceof ActiveThreatModelSource or isFiberInput(source)
  }}

  predicate isSink(DataFlow::Node sink) {{
    exists(CallExpr call |
      isGovulncheckCall(call) and sink.asExpr() = call.getAnArgument()
    )
  }}
}}

module GovulncheckTargetFlow = TaintTracking::Global<GovulncheckTargetConfig>;
import GovulncheckTargetFlow::PathGraph

from GovulncheckTargetFlow::PathNode source, GovulncheckTargetFlow::PathNode sink
where GovulncheckTargetFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "User-controlled input reaches this govulncheck application call site from $@.",
  source.getNode(), "this remote-flow source"
'''


def analyze(
    executable: str,
    database: Path,
    govulncheck_report: Path,
    output: Path,
    *,
    timeout_s: float,
) -> tuple[dict | None, str | None]:
    targets = targets_from_report(govulncheck_report)
    if not targets:
        return None, None

    pack = output.parent / ".codeql-targeted-go-pack"
    shutil.rmtree(pack, ignore_errors=True)
    pack.mkdir(parents=True)
    (pack / "qlpack.yml").write_text(
        "name: appsec-triage/govulncheck-targeted\n"
        "version: 0.0.0\n"
        "library: false\n"
        "dependencies:\n"
        "  codeql/go-all: '*'\n",
        encoding="utf-8",
    )
    query = pack / "GovulncheckTargeted.ql"
    query.write_text(render_query(targets), encoding="utf-8")
    try:
        proc = subprocess.run(
            [
                executable,
                "database",
                "analyze",
                str(database),
                f"path:{query}",
                "--format=sarif-latest",
                f"--output={output}",
                "--rerun",
            ],
            capture_output=True,
            text=True,
            timeout=timeout_s,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
    except subprocess.TimeoutExpired:
        return None, f"targeted CodeQL timed out after {timeout_s}s"
    except OSError as exc:
        return None, f"targeted CodeQL could not start: {exc}"
    finally:
        shutil.rmtree(pack, ignore_errors=True)

    if proc.returncode != 0:
        tail = "\n".join((proc.stderr or "").strip().splitlines()[-8:])
        return None, f"targeted CodeQL exited {proc.returncode}: {tail[:500]}"
    try:
        return json.loads(output.read_text(encoding="utf-8")), None
    except (OSError, ValueError) as exc:
        return None, f"targeted CodeQL produced unreadable SARIF: {exc}"
    finally:
        output.unlink(missing_ok=True)
