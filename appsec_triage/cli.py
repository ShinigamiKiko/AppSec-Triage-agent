"""CLI: triage · bench · providers · prompts · doctor."""

from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import sys
import time
from pathlib import Path

from . import ingest, prioritize, review as review_mod, reuse as reuse_mod, scanners
from .config import (
    ConfigError,
    load_lsp_config,
    list_providers,
    list_scanners,
    load_pipeline_config,
    load_provider_config,
)
from .evals.runner import BenchSetupError, run_bench
from .context.source import SourceResolver
from .lsp.service import LSPService
from .llm.factory import build_client
from .pipeline import TriagePipeline
from .prompts import registry
from . import coverage as coverage_report
from .diagnostics import cmd_doctor
from .report import audit, html
from .scanners.selection import scanners_for_target, usable_scanners


_PROGRESS_STATE: dict[str, float] = {}


def _progress(done: int, total: int) -> None:
    """Carriage-return bar for a terminal, plus a real line every minute.

    The bar alone is invisible in a background run: `\r` never terminates a line,
    so the log file stays empty until the process exits. On an hour-long run that
    is indistinguishable from a hang — it was taken for one three times before
    this was fixed. The periodic line costs nothing and answers the question.
    """
    now = time.monotonic()
    started = _PROGRESS_STATE.setdefault("started", now)

    filled = int(28 * done / total) if total else 28
    print(f"\r  [{'█' * filled}{'·' * (28 - filled)}] {done}/{total}", end="", file=sys.stderr, flush=True)

    elapsed = now - started
    if done == total or now - _PROGRESS_STATE.get("last_line", 0.0) >= 60:
        _PROGRESS_STATE["last_line"] = now
        eta = (elapsed / done) * (total - done) if done else 0.0
        tail = " · finished" if done == total else f" · ~{eta / 60:.0f} min left"
        print(f"\n  {done}/{total} done · {elapsed / 60:.0f} min elapsed{tail}", file=sys.stderr, flush=True)


def _gate_count(fail_on: str, counts: dict[str, int]) -> int | None:
    """How many findings trip the `--fail-on` CI gate, or None when the gate is off.

    `confirmed` counts confirmed vulns; `review` also counts `unknown`, since an
    abstention is precisely a finding a human still has to resolve. Closed
    (false_positive) verdicts never gate — that is the noise the tool removed.
    A return of 0 means the gate is on but clean.
    """
    if fail_on == "none":
        return None
    return {
        "confirmed": counts["confirmed"],
        "review": counts["confirmed"] + counts["unknown"],
    }[fail_on]


def _run_triage(args: argparse.Namespace, findings_path: Path, out: Path, source_roots: list[Path]) -> int:
    """Shared by `triage` and the second half of `run`."""
    cfg = load_pipeline_config(args.config)
    if getattr(args, "provider", None):
        cfg.provider = args.provider
    if getattr(args, "prompt_pack", None):
        cfg.prompt_pack = args.prompt_pack
    if getattr(args, "workers", None):
        cfg.max_workers = args.workers
    if getattr(args, "resolve_symbols", False):
        cfg.resolve_vulnerable_symbols = True
    if os.environ.get("NVD_API_KEY"):
        cfg.nvd_api_key = os.environ["NVD_API_KEY"]

    provider_cfg = load_provider_config(cfg.provider)
    if provider_cfg.leaves_the_perimeter:
        cfg.redact_secrets = True
    findings = ingest.load(findings_path)
    if getattr(args, "limit", None):
        findings = findings[: args.limit]

    print(f"→ {len(findings)} finding(s) · provider {provider_cfg.name} ({provider_cfg.model})", file=sys.stderr)
    if cfg.redact_secrets:
        print(
            "→ hosted provider: high-entropy literals are replaced by a description of their "
            "shape before the prompt leaves this machine",
            file=sys.stderr,
        )

    reuse_plan = None
    if getattr(args, "reuse", None):
        reuse_plan = reuse_mod.plan(
            findings,
            Path(args.reuse),
            reuse_mod.parse_redo(getattr(args, "redo", None)),
            current_model=provider_cfg.model,
            current_prompt_pack=cfg.prompt_pack,
        )
        findings = reuse_plan.fresh
        print(
            f"→ reusing {len(reuse_plan.reused)} verdict(s), re-triaging {len(findings)}"
            f" · {reuse_plan.counts}",
            file=sys.stderr,
        )
        if reuse_plan.stale_provenance:
            print(
                f"  ! {reuse_plan.stale_provenance} reused verdict(s) came from different inputs "
                "— the report mixes provenance",
                file=sys.stderr,
            )

    source = SourceResolver(source_roots) if source_roots else None
    if source:
        print(f"→ widening code context from {source.stats()['roots']} source root(s)", file=sys.stderr)

    symbols = None
    lsp_cfg = load_lsp_config(getattr(args, "lsp_config", None))
    cfg.lsp = lsp_cfg
    if lsp_cfg.enabled and source_roots and not getattr(args, "no_lsp", False):
        symbols = LSPService(lsp_cfg, source_roots)
        print("→ language servers enabled (definitions and reachability)", file=sys.stderr)

    required_present = sorted(
        {
            lang
            for f in findings
            if (lang := lsp_cfg.language_for(f.code_context.file_path)) and lang in lsp_cfg.required_languages
        }
    )
    if required_present:
        langs = ", ".join(required_present)
        if symbols is None:
            if getattr(args, "no_lsp", False):
                print(
                    f"  ! {langs} findings present with --no-lsp: dataflow closures for them will be "
                    "downgraded to unknown — the verdicts are conservative, not complete",
                    file=sys.stderr,
                )
            else:
                reason = "no --source-root given" if not source_roots else "lsp.yaml has enabled: false"
                print(
                    f"error: findings in {langs} present, and the language server is mandatory for "
                    f"them ({reason}).\n"
                    "       Pass --source-root <repo> with LSP enabled, or accept degraded triage "
                    "explicitly with --no-lsp.",
                    file=sys.stderr,
                )
                return 2
        else:
            for lang in required_present:
                if err := symbols.ensure_ready(lang):
                    print(
                        f"error: the {lang} language server is mandatory but not usable: {err}\n"
                        "       Fix it (see `appsec-triage doctor`), or accept degraded triage "
                        "explicitly with --no-lsp.",
                        file=sys.stderr,
                    )
                    symbols.close()
                    return 2

    out.mkdir(parents=True, exist_ok=True)
    journal_path = out / f"verdicts-{provider_cfg.name}.jsonl.partial"
    wanted = {f.finding_id for f in findings}
    recovered = [r for r in audit.Journal.recover(journal_path) if r.finding_id in wanted]
    if recovered:
        done_ids = {r.finding_id for r in recovered}
        before = len(findings)
        findings = [f for f in findings if f.finding_id not in done_ids]
        print(
            f"→ resuming an interrupted run: {len(recovered)} verdict(s) already decided, "
            f"{len(findings)} of {before} left",
            file=sys.stderr,
        )

    client = build_client(provider_cfg)
    try:
        with audit.Journal(journal_path, cfg.prompt_pack) as journal:
            run = TriagePipeline(client, provider_cfg, cfg, source=source, symbols=symbols).run(
                findings, progress=_progress, on_record=journal.append
            )
            run.records.extend(recovered)
            if reuse_plan:
                run.records.extend(reuse_plan.reused)
                run.reuse = reuse_plan.summary()
    finally:
        client.close()
        if symbols:
            print(f"→ language server: {symbols.stats}", file=sys.stderr)
            symbols.close()
    if source:
        print(f"→ code context: {source.stats()}", file=sys.stderr)

    run.coverage = coverage_report.read(
        findings_path if findings_path.is_dir() else findings_path.parent
    )
    for gap in run.coverage.gaps():
        print(f"  ! {gap}", file=sys.stderr)

    stem = provider_cfg.name
    audit.write_jsonl(run, out / f"verdicts-{stem}.jsonl")
    journal_path.unlink(missing_ok=True)
    audit.write_summary(run, out / f"summary-{stem}.json")
    report = html.write(run, out / f"report-{stem}.html", title=f"SAST LLM Triage — {provider_cfg.name}")

    counts = run.counts()
    print(
        f"\n  confirmed {counts['confirmed']} · unknown {counts['unknown']} · closed {counts['false_positive']}"
        f" · corrected {sum(1 for r in run.records if r.overrides)}"
        f" · errors {sum(1 for r in run.records if r.error)}"
        f" · ${run.total_cost_usd:.4f}",
        file=sys.stderr,
    )
    lsp_gated = sum(
        1 for r in run.records if any(o.startswith("lsp_required_no_answer") for o in r.overrides)
    )
    if lsp_gated:
        print(
            f"  ! {lsp_gated} closure(s) rejected: the mandatory language server gave no answer for them",
            file=sys.stderr,
        )
    print(report)

    fail_on = getattr(args, "fail_on", "none")
    gate_n = _gate_count(fail_on, counts)
    if gate_n is not None:
        if gate_n:
            what = "confirmed vuln(s)" if fail_on == "confirmed" else "finding(s) needing review"
            print(f"  ✗ gate --fail-on {fail_on}: {gate_n} {what} — failing the job (exit 1)", file=sys.stderr)
            return 1
        print(f"  ✓ gate --fail-on {fail_on}: clean", file=sys.stderr)
    return 0


def cmd_triage(args: argparse.Namespace) -> int:
    return _run_triage(args, Path(args.input), Path(args.out), [Path(r) for r in args.source_root])


def cmd_variants(args: argparse.Namespace) -> int:
    """Find the same construct elsewhere, seeded by what the pipeline confirmed.

    No model calls: the seed is already known to be real, and matching a shape
    is arithmetic. The output is candidates to look at, never verdicts — nothing
    here has been triaged and no scanner reported it.
    """
    from . import variants as variant_search
    from .models import VerdictLabel

    records = audit.read_jsonl(Path(args.verdicts))
    findings = list(ingest.load(Path(args.findings))) if args.findings else []
    by_id = {f.finding_id: f for f in findings}

    seeds = [
        (r, (by_id[r.finding_id].code_context.snippet if r.finding_id in by_id else None))
        for r in records
        if r.verdict.verdict is VerdictLabel.confirmed and r.kind == "weakness"
    ]
    if not seeds:
        print("no confirmed weaknesses to seed from", file=sys.stderr)
        return 0

    usable, rejected = [], []
    for record, snippet in seeds:
        ok, why = variant_search.seed_is_trustworthy(record)
        (usable if ok else rejected).append((record, snippet, why))

    print(chr(10) + "  seeds:", file=sys.stderr)
    for record, _, why in usable:
        print(
            f"    ok   {record.cwe or '-':10} {record.file_path}:{record.start_line or '?'}  ({why})",
            file=sys.stderr,
        )
    for record, _, why in rejected:
        print(
            f"    skip {record.cwe or '-':10} {record.file_path}:{record.start_line or '?'}  ({why})",
            file=sys.stderr,
        )

    roots = [Path(p) for p in (args.source_root or [])]
    found = variant_search.search([(r, sn) for r, sn, _ in usable], findings, roots)
    seeds = usable

    print(f"\n  {len(seeds)} confirmed weakness(es) used as seeds")
    print(f"  -> {len(found)} place(s) with the same shape that no scanner reported\n")

    by_seed: dict[str, list] = {}
    for v in found:
        by_seed.setdefault(v.seed_location, []).append(v)
    for seed, group in sorted(by_seed.items(), key=lambda kv: -len(kv[1])):
        print(f"  seed {seed}")
        for v in group[:10]:
            print(f"     {v.file_path}:{v.line}  {v.text[:110]}")
        if len(group) > 10:
            print(f"     ... {len(group) - 10} more")
        print()

    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(
            json.dumps([v.as_dict() for v in found], ensure_ascii=False, indent=2), encoding="utf-8"
        )
        print(f"  written: {args.out}")
    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    """Rebuild the review queue from verdicts already on disk — no model calls.

    Separate from `triage` on purpose: prioritisation is cheap and its knobs get
    tuned constantly, and re-running an hour of inference to try a different
    budget would make that impossible.
    """
    cfg = load_pipeline_config(args.config)
    if args.budget is not None:
        cfg.queue.review_budget_pct = args.budget
    if args.no_cluster:
        cfg.queue.cluster = False

    records = audit.read_jsonl(Path(args.verdicts))

    findings = {f.finding_id: f for f in ingest.load(Path(args.findings))} if args.findings else {}

    queue = prioritize.build(records, cfg.queue, findings)
    s = queue.summary()

    print(f"\n  {s['total_findings']} finding(s) triaged")
    print(f"  {s['clusters_collapsed']} collapsed into clusters")
    print(
        f"  -> {len(queue.to_review)} review item(s) covering {s['findings_behind_review_items']} finding(s)"
        f" = {s['manual_share_pct']}% manual (budget {s['budget_pct']}%)"
    )
    print(
        f"     of which {s['items_needing_a_decision']} need a decision and "
        f"{s['items_needing_an_action']} are remediation with the fix already named"
    )
    if s["budget_overflowed"]:
        print(
            "  ! budget-exempt items alone exceed the budget: this codebase needs more review than "
            "the target allows. Worth knowing rather than hiding.",
            file=sys.stderr,
        )
    print()

    for i, item in enumerate(queue.to_review, 1):
        more = f"  (+{item.cluster_size - 1} more)" if item.cluster_size > 1 else ""
        flag = "  [always-review]" if item.exempt else ""
        print(
            f"{i:>3}. [{item.score:>3}] {item.record.verdict.verdict.value:<14} "
            f"{str(item.record.cwe or '-'):<9} {item.record.file_path[-50:]}{more}{flag}"
        )
        brief = review_mod.build(item.record)
        for fact in brief.established:
            print(f"       ✓ {fact[:110]}")
        for n, q in enumerate(brief.questions, 1):
            print(f"       ? {n}. {q.text}")
            for where in q.look_at[:2]:
                if where:
                    print(f"           смотреть: {where[:100]}")
            if q.if_yes:
                print(f"           да → {q.if_yes}")
            if q.if_no:
                print(f"           нет → {q.if_no}")
        if args.verbose:
            for reason in item.reasons:
                print(f"       · {reason}")

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(
            json.dumps(
                {
                    "summary": s,
                    "queue": [
                        {**i.as_dict(), "review": review_mod.build(i.record).as_dict()} for i in queue.items
                    ],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        print(f"\n  written: {out}", file=sys.stderr)
    return 0


def cmd_scanners(_: argparse.Namespace) -> int:
    for name, avail in scanners.probe_all().items():
        mark = "✓" if avail.usable else "✗"
        print(f"{mark} {name:<10} {avail}")
    print("\nRunning a scanner executes third-party code over the target tree.")
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    """Dependency findings straight from cdxgen and the advisory databases.

    Exists because the SCA half used to depend on Trivy for its finding list: no
    scanner, nothing to triage — in an image that already carries cdxgen and can
    reach OSV. The output is the same shape `triage` consumes.
    """
    from .sca import discover as discover_mod

    target = Path(args.target).resolve()
    out_path = Path(args.out)
    result = discover_mod.discover(
        target, sbom_path=Path(args.sbom) if args.sbom else None,
        limit=args.limit or 0)

    payload = [json.loads(f.model_dump_json(exclude_none=True)) for f in result.findings]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    print(f"→ пакетов опрошено: {result.packages_checked}", file=sys.stderr)
    print(f"→ находок: {len(result.findings)} -> {out_path}", file=sys.stderr)
    for problem in result.problems[:10]:
        print(f"  ! {problem}", file=sys.stderr)
    if result.problems:
        print(f"  ! всего проблем: {len(result.problems)} — "
              "эти пакеты не проверены, а не признаны чистыми", file=sys.stderr)
    return 0 if result.usable else 2


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target).resolve()
    out_dir = Path(args.out)
    chosen = args.scanner or scanners_for_target(target)
    if not chosen:
        print("error: no usable scanner — run `appsec-triage scanners` to see why", file=sys.stderr)
        return 2

    print(f"→ scanning {target} with: {', '.join(chosen)}", file=sys.stderr)
    results = scanners.scan_all(
        target, chosen, out_dir,
        on_start=lambda n: print(f"  … {n}", end="", file=sys.stderr, flush=True),
    )
    for r in results:
        status = f"{r.findings} finding(s) in {r.duration_s:.0f}s" if r.ok else f"FAILED: {r.error}"
        print(f"\r  {'✓' if r.ok else '✗'} {r.scanner:<10} {status}", file=sys.stderr)

    manifest = scanners.write_manifest(target, results, out_dir)
    print(f"→ manifest: {manifest}", file=sys.stderr)
    for r in results:
        if r.ok and r.output_path:
            print(r.output_path)
    return 0 if any(r.ok for r in results) else 1


def cmd_run(args: argparse.Namespace) -> int:
    """Scan, then triage what came out — the whole job in one command."""
    target = Path(args.target).resolve()
    out = Path(args.out)
    scan_dir = out / "scans"

    if cmd_scan(argparse.Namespace(target=target, out=scan_dir, scanner=args.scanner)) != 0:
        return 1

    reports = [p for p in scan_dir.iterdir() if p.suffix in (".json", ".sarif") and p.name != "scan-manifest.json"]
    if not reports:
        print("error: scanners produced no readable report", file=sys.stderr)
        return 1

    return _run_triage(args, scan_dir, out, [target])


def cmd_bench(args: argparse.Namespace) -> int:
    cfg = load_pipeline_config(args.config)
    cfg.lsp = load_lsp_config()
    providers = args.providers or [cfg.provider]
    try:
        results = run_bench(
            corpus=Path(args.corpus),
            providers=providers,
            cfg=cfg,
            out_dir=Path(args.out),
            limit=args.limit,
            progress=_progress,
            source_roots=[Path(r) for r in args.source_root],
            no_lsp=args.no_lsp,
        )
    except BenchSetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if results.get("materialized_corpus"):
        print(f"→ corpus materialized into {results['source_roots'][0]}", file=sys.stderr)
    if not results.get("lsp"):
        print(
            "  ! bench ran without language servers: dataflow numbers are conservative, not comparable "
            "with resolver-backed runs",
            file=sys.stderr,
        )
    print(json.dumps(results, indent=2, ensure_ascii=False))
    return 0


def cmd_providers(_: argparse.Namespace) -> int:
    for name in list_providers():
        try:
            cfg = load_provider_config(name)
            key = "no key needed" if cfg.kind == "ollama" else ("key set" if cfg.api_key else "KEY MISSING")
            print(f"{name:<10} kind={cfg.kind:<9} model={cfg.model:<28} json={cfg.json_mode:<14} {key}")
        except ConfigError as exc:
            print(f"{name:<10} unavailable: {exc}")
    return 0


def cmd_prompts(_: argparse.Namespace) -> int:
    for cwe, prompt_id in registry.coverage().items():
        print(f"{cwe:<10} -> {prompt_id}")
    print("\n(any CWE not listed falls back to `base`)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="appsec-triage", description="LLM triage for SAST findings")
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("triage", help="triage a findings file or directory")
    t.add_argument("input", help="SARIF/JSON/JSONL file, or a directory of them")
    t.add_argument("-p", "--provider", help="provider profile name (configs/providers/<name>.yaml)")
    t.add_argument("-o", "--out", default="out", help="output directory")
    t.add_argument("--prompt-pack", dest="prompt_pack")
    t.add_argument("--config", type=Path)
    t.add_argument("--workers", type=int)
    t.add_argument("--limit", type=int, help="triage only the first N findings")
    t.add_argument(
        "--resolve-symbols",
        dest="resolve_symbols",
        action="store_true",
        help="for each dependency CVE: ask OSV/GHSA/NVD what the flaw is, fetch the fix it "
             "points at, resolve the vulnerable function and search this repository for it. "
             "Needs network access from the scanning container.",
    )
    t.add_argument(
        "--reuse",
        metavar="VERDICTS.JSONL",
        help="carry verdicts over from a previous run for findings whose code is unchanged",
    )
    t.add_argument(
        "--redo",
        metavar="CLASSES",
        help="comma-separated: unknown,error,overridden,confirmed,false_positive,all,none "
             "(default: unknown,error,overridden — the unresolved and the unreliable)",
    )
    t.add_argument(
        "--source-root",
        action="append",
        default=[],
        metavar="DIR",
        help="repository root; lets the builder widen cropped scanner snippets from the real file (repeatable)",
    )
    t.add_argument("--lsp-config", dest="lsp_config", type=Path,
                   help="override the LSP config (default: configs/lsp.yaml)")
    t.add_argument(
        "--no-lsp",
        action="store_true",
        help="proceed without language servers; for LSP-mandatory languages (lsp.yaml: required_languages) "
             "dataflow closures are then downgraded to unknown instead of accepted",
    )
    t.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=["none", "confirmed", "review"],
        default="none",
        help="CI gate: exit 1 when findings remain. 'confirmed' = any confirmed vuln; "
             "'review' = anything needing a human (confirmed + unknown). default: none (exit 0 on success)",
    )
    t.set_defaults(func=cmd_triage)

    b = sub.add_parser("bench", help="score providers against a labelled corpus")
    b.add_argument("corpus", help="JSONL with a `label` field per finding")
    b.add_argument("-p", "--providers", nargs="+", help="providers to compare side by side")
    b.add_argument("-o", "--out", default="out/bench")
    b.add_argument("--config", type=Path)
    b.add_argument("--limit", type=int)
    b.add_argument(
        "--source-root",
        action="append",
        default=[],
        help="score against a real checkout instead of materializing the snippets "
        "(corpus line numbers must then be real); repeatable",
    )
    b.add_argument(
        "--no-lsp",
        action="store_true",
        help="proceed without language servers; for LSP-mandatory languages (lsp.yaml: required_languages) "
             "dataflow closures are then downgraded to unknown instead of accepted",
    )
    b.set_defaults(func=cmd_bench)

    sc = sub.add_parser("scan", help="run the scanners against a source tree")
    sc.add_argument("target", help="directory to scan")
    sc.add_argument("-s", "--scanner", action="append", help="scanner profile (repeatable); default: all usable")
    sc.add_argument("-o", "--out", default="out/scans")
    sc.set_defaults(func=cmd_scan)

    r = sub.add_parser("run", help="scan a source tree and triage the findings in one pass")
    r.add_argument("target", help="directory to scan and triage")
    r.add_argument("-s", "--scanner", action="append", help="scanner profile (repeatable); default: all usable")
    r.add_argument("-p", "--provider", help="LLM provider profile")
    r.add_argument("-o", "--out", default="out")
    r.add_argument("--prompt-pack", dest="prompt_pack")
    r.add_argument("--config", type=Path)
    r.add_argument("--lsp-config", dest="lsp_config", type=Path,
                   help="override the LSP config (default: configs/lsp.yaml); "
                        "use a file with only the servers you need, e.g. configs/lsp-php-only.yaml "
                        "to avoid the typescript-language-server on mixed-language repos")
    r.add_argument("--workers", type=int)
    r.add_argument("--limit", type=int)
    r.add_argument(
        "--resolve-symbols",
        dest="resolve_symbols",
        action="store_true",
        help="for each dependency CVE: ask OSV/GHSA/NVD what the flaw is, fetch the fix it "
             "points at, resolve the vulnerable function and search this repository for it. "
             "Needs network access from the scanning container.",
    )
    r.add_argument(
        "--no-lsp",
        action="store_true",
        help="proceed without language servers; for LSP-mandatory languages (lsp.yaml: required_languages) "
             "dataflow closures are then downgraded to unknown instead of accepted",
    )
    r.add_argument(
        "--fail-on",
        dest="fail_on",
        choices=["none", "confirmed", "review"],
        default="none",
        help="CI gate: exit 1 when findings remain. 'confirmed' = any confirmed vuln; "
             "'review' = anything needing a human (confirmed + unknown). default: none (exit 0 on success)",
    )
    r.set_defaults(func=cmd_run)

    v = sub.add_parser(
        "variants",
        help="find the same construct elsewhere, seeded by confirmed findings (no model calls)",
    )
    v.add_argument("verdicts", help="verdicts-*.jsonl produced by `triage`")
    v.add_argument("-f", "--findings", help="the scan report(s), for the code the verdicts refer to")
    v.add_argument("--source-root", action="append", help="repository root to search (repeatable)")
    v.add_argument("-o", "--out", help="write the candidates as JSON")
    v.set_defaults(func=cmd_variants)

    q = sub.add_parser("queue", help="build the prioritised review queue from existing verdicts (no model calls)")
    q.add_argument("verdicts", help="verdicts-*.jsonl produced by `triage`")
    q.add_argument("-f", "--findings", help="the scan report(s), so severity and paths can feed the score")
    q.add_argument("-b", "--budget", type=float, help="share of findings a human will review, e.g. 30")
    q.add_argument("--no-cluster", action="store_true", help="one item per finding instead of per pattern")
    q.add_argument("--config", type=Path)
    q.add_argument("-o", "--out", help="write the queue as JSON")
    q.set_defaults(func=cmd_queue)

    s = sub.add_parser(
        "sbom",
        help="find vulnerable dependencies with cdxgen + OSV, without a scanner")
    s.add_argument("target", help="project root")
    s.add_argument("-o", "--out", required=True, help="findings file to write")
    s.add_argument("--sbom", help="reuse an SBOM instead of running cdxgen")
    s.add_argument("--limit", type=int, help="stop after N packages")
    s.set_defaults(func=cmd_sbom)

    sub.add_parser("scanners", help="show which scanners can run here").set_defaults(func=cmd_scanners)
    sub.add_parser("providers", help="list configured providers").set_defaults(func=cmd_providers)
    sub.add_parser("prompts", help="show CWE -> prompt coverage").set_defaults(func=cmd_prompts)
    sub.add_parser("doctor", help="check config and prompt packs").set_defaults(func=cmd_doctor)
    return p


def _force_utf8_streams() -> None:
    """Windows consoles still default to a legacy codepage (cp1251 here).

    Progress glyphs and file paths with non-ASCII characters raise
    UnicodeEncodeError mid-run otherwise — a report that took ten minutes to
    produce must not be lost to a console encoding.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Read `.env` into the environment, without overwriting what is already set.

    Provider profiles reference keys as `${DEEPSEEK_API_KEY}`, and without this
    every invocation had to be wrapped in a `source .env` — which meant
    `providers` and `doctor` reported a configured provider as unavailable and
    sent the reader looking for a problem that was not there.

    A real key belongs in a file with restricted permissions, never on the
    command line where the process table exposes it. Existing environment
    variables win, so an explicitly exported key still overrides the file.
    """
    if not path.is_file():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip("'\"")
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    _load_dotenv()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return args.func(args)
    except (ConfigError, ingest.IngestError, registry.PromptError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
