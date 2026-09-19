"""Scanner and combined scan/triage commands."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ... import scanners
from ...scanners import tools as scanner_tools
from ...scanners.selection import scanners_for_target
from ..common import run_triage


def cmd_sbom(args: argparse.Namespace) -> int:
    from ...sca import discover as discover_mod
    target = Path(args.target).resolve()
    out_path = Path(args.out)
    result = discover_mod.discover(target, sbom_path=Path(args.sbom) if args.sbom else None, limit=args.limit or 0)
    payload = [json.loads(f.model_dump_json(exclude_none=True)) for f in result.findings]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"→ пакетов опрошено: {result.packages_checked}", file=sys.stderr)
    print(f"→ находок: {len(result.findings)} -> {out_path}", file=sys.stderr)
    for problem in result.problems[:10]: print(f"  ! {problem}", file=sys.stderr)
    if result.problems: print(f"  ! всего проблем: {len(result.problems)} — эти пакеты не проверены, а не признаны чистыми", file=sys.stderr)
    return 0 if result.usable else 2


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out_dir = Path(args.out)
    chosen = args.scanner or scanners_for_target(target)
    if not chosen:
        print("error: no usable scanner — run `appsec-triage scanners` to see why", file=sys.stderr)
        return 2
    print(f"→ scanning {target} with: {', '.join(chosen)}", file=sys.stderr)
    results = scanners.scan_all(target, chosen, out_dir, on_start=lambda n: print(f"  … {n}", end="", file=sys.stderr, flush=True))
    for r in results:
        status = f"{r.findings} finding(s) in {r.duration_s:.0f}s" if r.ok else f"FAILED: {r.error}"
        print(f"\r  {'✓' if r.ok else '✗'} {r.scanner:<10} {status}", file=sys.stderr)
    manifest = scanners.write_manifest(target, results, out_dir)
    print(f"→ manifest: {manifest}", file=sys.stderr)
    for r in results:
        if r.ok and r.output_path: print(r.output_path)
    return 0 if any(r.ok for r in results) else 1


def cmd_run(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out = Path(args.out).resolve()
    scan_dir = out / "scans"
    if out.is_relative_to(target):
        relative = out.relative_to(target)
        scanner_tools.exclude_directory(relative.parts[0])
        print(f"→ каталог вывода {relative.parts[0]}/ внутри цели — исключён из скана", file=sys.stderr)
    if cmd_scan(argparse.Namespace(target=target, out=scan_dir, scanner=args.scanner)) != 0: return 1
    reports = [p for p in scan_dir.iterdir() if p.suffix in (".json", ".sarif") and p.name != "scan-manifest.json"]
    if not reports:
        print("error: scanners produced no readable report", file=sys.stderr)
        return 1
    wolfee_report = scan_dir / "wolfee.sarif.json"
    if not getattr(args, "no_deps", False) and not wolfee_report.is_file():
        deps_file = scan_dir / "dependencies.json"
        if cmd_sbom(argparse.Namespace(target=target, out=deps_file, sbom=getattr(args, "sbom", None), limit=0)) != 0:
            print("  ! зависимости не разобраны — триаж пойдёт только по находкам сканеров", file=sys.stderr)
    args.scan_dir = scan_dir
    return run_triage(args, scan_dir, out, [target])
