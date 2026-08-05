"""Where two runs of the same code on the same input disagree.

The one question no other tool here answers. `measure.py` describes a run;
this compares two, which is what decides whether the agent may gate anything.
A verdict that moves between identical runs is not a verdict, it is a coin
toss with a rationale attached.

    python3 tools/compare_runs.py out/runA out/runB

Both directories are expected to hold one subdirectory per project, each with a
`verdicts-*.jsonl` — the layout `tools/nightly.sh` produces.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def _load(path: Path) -> dict:
    return {
        r["finding_id"]: r
        for r in (json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip())
    }


def _verdicts(run: Path) -> dict[str, Path]:
    """project -> verdicts file, whatever the provider was called."""
    out = {}
    for candidate in sorted(run.glob("*/verdicts-*.jsonl")):
        out[candidate.parent.name] = candidate
    return out


def compare(a_root: Path, b_root: Path) -> int:
    a_runs, b_runs = _verdicts(a_root), _verdicts(b_root)
    shared_projects = sorted(set(a_runs) & set(b_runs))
    if not shared_projects:
        print(f"no project appears in both {a_root} and {b_root}", file=sys.stderr)
        return 2

    total_diff = 0
    for project in shared_projects:
        a, b = _load(a_runs[project]), _load(b_runs[project])
        shared = set(a) & set(b)
        diffs = [k for k in shared if a[k]["verdict"]["verdict"] != b[k]["verdict"]["verdict"]]
        bands = [
            k for k in shared
            if a[k]["verdict"]["verdict"] == b[k]["verdict"]["verdict"]
            and a[k]["verdict"].get("confidence_band") != b[k]["verdict"].get("confidence_band")
        ]
        total_diff += len(diffs)

        print(f"\n=== {project}")
        print(f"  findings           {len(a)} vs {len(b)}, {len(shared)} shared")
        if set(a) != set(b):
            print(f"  ! {len(set(a) ^ set(b))} finding(s) appear in only one run — the inputs differ")
        print(f"  verdict differs    {len(diffs)}")
        print(f"  certainty moved    {len(bands)}")
        for k in diffs:
            va, vb = a[k]["verdict"], b[k]["verdict"]
            print(f"\n  {a[k].get('cwe')} {a[k]['file_path'].split('/')[-1]}:{a[k].get('start_line')}")
            print(f"    A: {va['verdict']:15} band={va.get('confidence_band')}  {(va.get('reason') or '')[:120]}")
            print(f"    B: {vb['verdict']:15} band={vb.get('confidence_band')}  {(vb.get('reason') or '')[:120]}")

    print(f"\ntotal verdict differences: {total_diff}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(__doc__)
        raise SystemExit(2)
    raise SystemExit(compare(Path(sys.argv[1]), Path(sys.argv[2])))
