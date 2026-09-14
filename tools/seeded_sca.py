"""Run the seeded SCA corpus: one tiny project per case, the answer known by construction.

Each case is benched on its own source root, because the dependency chain asks
project-wide questions — is the package used, is it a dev dependency — and two
cases sharing a tree would answer each other's. The CodeQL database is built
here rather than by a full SAST scan, and recorded in the manifest the chain
reads, so the dataflow question runs exactly as it does after `scan`.

Usage, from the repository root (WSL):

    python3 tools/seeded_sca.py [--only CASE ...] [--record] [-p deepseek]

Exit code 1 when a vulnerable case was closed as a false positive.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CASES = ROOT / "samples" / "sca-seeded"
MANIFEST = ".codeql-databases.json"


def build_database(codeql: str, project: Path, scan_dir: Path) -> str:
    """Empty string when the database is ready, otherwise what went wrong."""
    database = scan_dir / ".codeql-db-javascript"
    scan_dir.mkdir(parents=True, exist_ok=True)
    if not any(p.suffix in {".js", ".mjs", ".cjs", ".ts"} for p in project.rglob("*")
               if "node_modules" not in p.parts):
        # Only a JavaScript database is built here; other cases run without one,
        # exactly as a project with no CodeQL database would.
        (scan_dir / MANIFEST).unlink(missing_ok=True)
        return ""
    if not (database / "codeql-database.yml").is_file():
        proc = subprocess.run(
            [codeql, "database", "create", str(database), "--language=javascript-typescript",
             "--build-mode=none", f"--source-root={project}", "--overwrite"],
            capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            return "\n".join((proc.stderr or "").strip().splitlines()[-4:])
    (scan_dir / MANIFEST).write_text(json.dumps({"javascript": str(database)}), encoding="utf-8")
    return ""


def classify(truth: str, predicted: str) -> str:
    if predicted == truth:
        return "ok"
    if predicted == "unknown":
        return "abstained"
    if truth == "confirmed":
        return "DANGEROUS"
    return "false alarm"


def run_case(case: Path, args, tapes: Path, record: bool) -> dict:
    out = Path(args.out) / case.name
    out.mkdir(parents=True, exist_ok=True)
    finding = json.loads((case / "finding.jsonl").read_text(encoding="utf-8").splitlines()[0])
    row = {"case": case.name, "label": finding["label"], "predicted": None,
           "outcome": None, "note": "", "result": "error"}

    if problem := build_database(os.path.expanduser(args.codeql), case / "project", out / "scan"):
        row["note"] = f"codeql: {problem}"
        return row

    command = [sys.executable, "-m", "appsec_triage.cli", "bench", str(case / "finding.jsonl"),
               "--source-root", str(case / "project"), "--resolve-symbols",
               "--scan-dir", str(out / "scan"), "--http-cassette", str(tapes),
               "-p", args.provider, "-o", str(out)]
    # PHP has no CodeQL: resolving which class a call belongs to is the language
    # server's job there, so PHP cases run with it. Other cases keep it off, as
    # their numbers were taken.
    is_php = any(p.suffix == ".php" for p in (case / "project").rglob("*") if "vendor" not in p.parts)
    if not is_php:
        command.append("--no-lsp")
    if record:
        command.append("--record")
    with open(out / "bench.log", "w", encoding="utf-8") as log:
        proc = subprocess.run(command, cwd=ROOT, stdout=log, stderr=subprocess.STDOUT, check=False)
    verdicts = out / f"verdicts-{args.provider}.jsonl"
    if proc.returncode != 0 or not verdicts.is_file():
        row["note"] = f"bench exited {proc.returncode}, see {out / 'bench.log'}"
        return row

    record_ = json.loads(verdicts.read_text(encoding="utf-8").splitlines()[0])
    sca = record_.get("sca") or {}
    row.update(predicted=record_["verdict"]["verdict"], outcome=sca.get("outcome"),
               note=sca.get("outcome_note") or record_["verdict"].get("reason", "")[:160])
    row["result"] = classify(row["label"], row["predicted"])
    return row


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--only", nargs="+", help="case directory names")
    parser.add_argument("-p", "--provider", default="deepseek")
    parser.add_argument("-o", "--out", default=str(ROOT / "out" / "seeded-sca"))
    parser.add_argument("--codeql", default="~/tools/codeql/codeql")
    parser.add_argument("--record", action="store_true",
                        help="refresh the tapes from the network (default: only when there are none)")
    args = parser.parse_args()

    tapes = CASES / "tapes"
    record = args.record or not any(tapes.glob("*.json"))
    cases = sorted(p for p in CASES.iterdir() if (p / "finding.jsonl").is_file())
    if args.only:
        cases = [p for p in cases if p.name in set(args.only)]
    print(f"{len(cases)} case(s), tapes {'recording' if record else 'replaying'} at {tapes}", file=sys.stderr)

    rows = []
    for case in cases:
        print(f"  … {case.name}", file=sys.stderr, flush=True)
        rows.append(run_case(case, args, tapes, record))

    width = max(len(r["case"]) for r in rows) if rows else 10
    for r in rows:
        print(f"{r['result']:<11} {r['case']:<{width}}  label={r['label']:<14} "
              f"predicted={str(r['predicted']):<14} chain={r['outcome']}  {r['note']}")
    totals = {k: sum(1 for r in rows if r["result"] == k)
              for k in ("ok", "abstained", "false alarm", "DANGEROUS", "error")}
    print("\n" + " · ".join(f"{k} {v}" for k, v in totals.items()))
    Path(args.out).mkdir(parents=True, exist_ok=True)
    (Path(args.out) / "summary.json").write_text(
        json.dumps({"totals": totals, "cases": rows}, indent=2, ensure_ascii=False), encoding="utf-8")
    return 1 if totals["DANGEROUS"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
