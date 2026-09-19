"""Benchmark command."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from ...config import load_lsp_config, load_pipeline_config
from ...evals.runner import BenchSetupError, run_bench
from ...sca import cassette
from ..common import progress


def cmd_bench(args: argparse.Namespace) -> int:
    cfg = load_pipeline_config(args.config)
    cfg.lsp = load_lsp_config()
    if os.environ.get("NVD_API_KEY"): cfg.nvd_api_key = os.environ["NVD_API_KEY"]
    if getattr(args, "http_cassette", None):
        os.environ[cassette.DIR_ENV] = str(args.http_cassette)
        os.environ[cassette.MODE_ENV] = "record" if args.record else "replay"
    elif getattr(args, "record", False):
        print("error: --record needs --http-cassette <dir>", file=sys.stderr)
        return 2
    try:
        results = run_bench(corpus=Path(args.corpus), providers=args.providers or [cfg.provider], cfg=cfg, out_dir=Path(args.out), limit=args.limit, progress=progress, source_roots=[Path(r) for r in args.source_root], no_lsp=args.no_lsp, resolve_symbols=args.resolve_symbols, scan_dir=args.scan_dir)
    except BenchSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if results.get("materialized_corpus"): print(f"→ corpus materialized into {results['source_roots'][0]}", file=sys.stderr)
    if not results.get("lsp"): print("  ! bench ran without language servers: dataflow numbers are conservative, not comparable with resolver-backed runs", file=sys.stderr)
    if results.get("dependency_findings") and not results.get("sca_chain"): print("  ! dependency findings benched without --resolve-symbols: SCA numbers score the bare model, not the chain", file=sys.stderr)
    if results.get("sca_chain") and not results["http_cassette"]["dir"]: print("  ! SCA chain ran against live databases: numbers are not reproducible, use --http-cassette", file=sys.stderr)
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0
