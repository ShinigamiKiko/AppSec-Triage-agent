"""Argument parser construction."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..diagnostics import cmd_doctor
from .commands import bench, misc, reports, scan, triage


def _triage_options(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--provider", help="provider profile name (configs/providers/<name>.yaml)")
    p.add_argument("-o", "--out", default="out")
    p.add_argument("--prompt-pack", dest="prompt_pack")
    p.add_argument("--config", type=Path)
    p.add_argument("--workers", type=int)
    p.add_argument("--limit", type=int)
    p.add_argument("--govulncheck", dest="govulncheck", type=Path)
    p.add_argument("--resolve-symbols", dest="resolve_symbols", action="store_true")
    p.add_argument("--no-lsp", action="store_true")
    p.add_argument("--fail-on", choices=["none", "confirmed", "review"], default="none")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="appsec-triage", description="LLM triage for SAST findings")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("triage", help="triage a findings file or directory")
    t.add_argument("input"); _triage_options(t)
    t.add_argument("--reuse"); t.add_argument("--redo")
    t.add_argument("--source-root", action="append", default=[]); t.add_argument("--lsp-config", type=Path)
    t.add_argument("--scan-dir", type=Path); t.set_defaults(func=triage.cmd_triage)
    b = sub.add_parser("bench", help="score providers against a labelled corpus")
    b.add_argument("corpus"); b.add_argument("-p", "--providers", nargs="+"); b.add_argument("-o", "--out", default="out/bench")
    b.add_argument("--config", type=Path); b.add_argument("--limit", type=int); b.add_argument("--source-root", action="append", default=[]); b.add_argument("--no-lsp", action="store_true")
    b.add_argument("--resolve-symbols", dest="resolve_symbols", action="store_true"); b.add_argument("--scan-dir", type=Path)
    b.add_argument("--http-cassette", type=Path, help="pin SCA database lookups to this directory"); b.add_argument("--record", action="store_true", help="fill the cassette from the network instead of replaying it")
    b.set_defaults(func=bench.cmd_bench)
    sc = sub.add_parser("scan", help="run the scanners against a source tree")
    sc.add_argument("target"); sc.add_argument("-s", "--scanner", action="append"); sc.add_argument("-o", "--out", default="out/scans"); sc.set_defaults(func=scan.cmd_scan)
    r = sub.add_parser("run", help="scan a source tree and triage the findings in one pass")
    r.add_argument("target"); r.add_argument("-s", "--scanner", action="append"); _triage_options(r)
    r.add_argument("--lsp-config", type=Path); r.add_argument("--sbom", type=Path); r.add_argument("--no-deps", action="store_true"); r.set_defaults(func=scan.cmd_run)
    v = sub.add_parser("variants"); v.add_argument("verdicts"); v.add_argument("-f", "--findings"); v.add_argument("--source-root", action="append"); v.add_argument("-o", "--out"); v.set_defaults(func=reports.cmd_variants)
    q = sub.add_parser("queue"); q.add_argument("verdicts"); q.add_argument("-f", "--findings"); q.add_argument("-b", "--budget", type=float); q.add_argument("--no-cluster", action="store_true"); q.add_argument("--config", type=Path); q.add_argument("-o", "--out"); q.set_defaults(func=reports.cmd_queue)
    s = sub.add_parser("sbom"); s.add_argument("target"); s.add_argument("-o", "--out", required=True); s.add_argument("--sbom"); s.add_argument("--limit", type=int); s.set_defaults(func=scan.cmd_sbom)
    sub.add_parser("scanners").set_defaults(func=misc.cmd_scanners)
    sub.add_parser("providers").set_defaults(func=misc.cmd_providers)
    sub.add_parser("prompts").set_defaults(func=misc.cmd_prompts)
    sub.add_parser("doctor").set_defaults(func=cmd_doctor)
    return p
