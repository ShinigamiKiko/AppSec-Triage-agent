"""Shared runtime helpers for CLI commands."""

from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from .. import coverage as coverage_report
from .. import ingest
from .. import reuse as reuse_mod
from ..config import load_lsp_config, load_pipeline_config, load_provider_config
from ..context.source import SourceResolver
from ..llm.factory import build_client
from ..lsp.service import LSPService
from ..pipeline import TriagePipeline
from ..report import audit, html

_PROGRESS_STATE: dict[str, float] = {}
_PROVEN_OUTCOMES = {"actual", "present"}


def progress(done: int, total: int) -> None:
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


def gate_count(fail_on: str, counts: dict[str, int]) -> int | None:
    if fail_on == "none":
        return None
    return {"confirmed": counts["confirmed"], "review": counts["confirmed"] + counts["unknown"]}[fail_on]


def run_triage(args: argparse.Namespace, findings_path: Path, out: Path, source_roots: list[Path]) -> int:
    cfg = load_pipeline_config(args.config)
    if getattr(args, "provider", None): cfg.provider = args.provider
    if getattr(args, "prompt_pack", None): cfg.prompt_pack = args.prompt_pack
    if getattr(args, "workers", None): cfg.max_workers = args.workers
    if getattr(args, "resolve_symbols", False): cfg.resolve_vulnerable_symbols = True
    if getattr(args, "govulncheck", None): cfg.govulncheck_report = str(args.govulncheck)
    if getattr(args, "scan_dir", None): cfg.scan_out_dir = str(args.scan_dir)
    if os.environ.get("NVD_API_KEY"): cfg.nvd_api_key = os.environ["NVD_API_KEY"]

    provider_cfg = load_provider_config(cfg.provider)
    if provider_cfg.leaves_the_perimeter: cfg.redact_secrets = True
    findings = ingest.load(findings_path)
    if govuln_path := getattr(args, "govulncheck", None):
        from ..ingest import govulncheck as govulncheck_ingest
        try:
            gov_findings = list(govulncheck_ingest.parse(govuln_path))
        except (OSError, ValueError, KeyError, TypeError) as exc:
            print(f"error: govulncheck report is unreadable: {exc}", file=sys.stderr)
            return 2
        findings.extend(gov_findings)
        print(f"→ govulncheck: {len(gov_findings)} authoritative traced finding(s)", file=sys.stderr)
    if getattr(args, "limit", None): findings = findings[:args.limit]
    print(f"→ {len(findings)} finding(s) · provider {provider_cfg.name} ({provider_cfg.model})", file=sys.stderr)
    if cfg.redact_secrets:
        print("→ hosted provider: high-entropy literals are replaced by a description of their shape before the prompt leaves this machine", file=sys.stderr)

    reuse_plan = None
    if getattr(args, "reuse", None):
        reuse_plan = reuse_mod.plan(findings, Path(args.reuse), reuse_mod.parse_redo(getattr(args, "redo", None)), current_model=provider_cfg.model, current_prompt_pack=cfg.prompt_pack)
        findings = reuse_plan.fresh
        print(f"→ reusing {len(reuse_plan.reused)} verdict(s), re-triaging {len(findings)} · {reuse_plan.counts}", file=sys.stderr)
        if reuse_plan.stale_provenance:
            print(f"  ! {reuse_plan.stale_provenance} reused verdict(s) came from different inputs — the report mixes provenance", file=sys.stderr)

    source = SourceResolver(source_roots) if source_roots else None
    if source: print(f"→ widening code context from {source.stats()['roots']} source root(s)", file=sys.stderr)
    symbols = None
    lsp_cfg = load_lsp_config(getattr(args, "lsp_config", None))
    cfg.lsp = lsp_cfg
    if lsp_cfg.enabled and source_roots and not getattr(args, "no_lsp", False):
        symbols = LSPService(lsp_cfg, source_roots)
        print("→ language servers enabled (definitions and reachability)", file=sys.stderr)
    required_present = sorted({lang for f in findings if (lang := lsp_cfg.language_for(f.code_context.file_path)) and lang in lsp_cfg.required_languages})
    if required_present:
        langs = ", ".join(required_present)
        if symbols is None:
            if getattr(args, "no_lsp", False):
                print(f"  ! {langs} findings present with --no-lsp: dataflow closures for them will be downgraded to unknown — the verdicts are conservative, not complete", file=sys.stderr)
            else:
                reason = "no --source-root given" if not source_roots else "lsp.yaml has enabled: false"
                print(f"error: findings in {langs} present, and the language server is mandatory for them ({reason}).\n       Pass --source-root <repo> with LSP enabled, or accept degraded triage explicitly with --no-lsp.", file=sys.stderr)
                return 2
        else:
            for lang in required_present:
                if err := symbols.ensure_ready(lang):
                    print(f"error: the {lang} language server is mandatory but not usable: {err}\n       Fix it (see `appsec-triage doctor`), or accept degraded triage explicitly with --no-lsp.", file=sys.stderr)
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
        print(f"→ resuming an interrupted run: {len(recovered)} verdict(s) already decided, {len(findings)} of {before} left", file=sys.stderr)

    from ..sca.govulncheck import GovulncheckUnavailable
    client = build_client(provider_cfg)
    try:
        with audit.Journal(journal_path, cfg.prompt_pack) as journal:
            try:
                pipeline = TriagePipeline(client, provider_cfg, cfg, source=source, symbols=symbols)
            except GovulncheckUnavailable as exc:
                print(f"error: граф вызовов запрошен, но недоступен — {exc}", file=sys.stderr)
                return 2
            run = pipeline.run(findings, progress=progress, on_record=journal.append)
            run.records.extend(recovered)
            if reuse_plan:
                run.records.extend(reuse_plan.reused)
                run.reuse = reuse_plan.summary()
    finally:
        client.close()
        if symbols:
            print(f"→ language server: {symbols.stats}", file=sys.stderr)
            symbols.close()
    if source: print(f"→ code context: {source.stats()}", file=sys.stderr)
    run.coverage = coverage_report.read(findings_path if findings_path.is_dir() else findings_path.parent)
    for gap in run.coverage.gaps(): print(f"  ! {gap}", file=sys.stderr)
    stem = provider_cfg.name
    audit.write_jsonl(run, out / f"verdicts-{stem}.jsonl")
    journal_path.unlink(missing_ok=True)
    audit.write_summary(run, out / f"summary-{stem}.json")
    report = html.write(run, out / f"report-{stem}.html", title=f"SAST LLM Triage — {provider_cfg.name}")
    from ..models import VerdictLabel
    counts = run.counts()
    proven = sum(1 for r in run.records if r.verdict.verdict is VerdictLabel.confirmed and (r.sca is None or r.sca.outcome in _PROVEN_OUTCOMES))
    unproven = counts["confirmed"] - proven
    print(f"\n  доказано {proven} · не закрыто {unproven} · закрыто {counts['false_positive']} · на человека {counts['unknown'] + unproven} · corrected {sum(1 for r in run.records if r.overrides)} · errors {sum(1 for r in run.records if r.error)} · ${run.total_cost_usd:.4f}" + (f" ({run.model_calls} запросов)" if run.model_calls else ""), file=sys.stderr)
    dependency_records = [r for r in run.records if r.kind == "dependency"]
    if cfg.resolve_vulnerable_symbols and dependency_records and not any(r.sca is not None for r in dependency_records):
        print(f"  ! цепочка проверки зависимостей не отработала ни по одной из {len(dependency_records)} находок — вердикты по зависимостям недостоверны (см. лог)", file=sys.stderr)
        return 1
    lsp_gated = sum(1 for r in run.records if any(o.startswith("lsp_required_no_answer") for o in r.overrides))
    if lsp_gated: print(f"  ! {lsp_gated} closure(s) rejected: the mandatory language server gave no answer for them", file=sys.stderr)
    print(report)
    fail_on = getattr(args, "fail_on", "none")
    gate_n = gate_count(fail_on, counts)
    if gate_n is not None:
        if gate_n:
            what = "confirmed vuln(s)" if fail_on == "confirmed" else "finding(s) needing review"
            print(f"  ✗ gate --fail-on {fail_on}: {gate_n} {what} — failing the job (exit 1)", file=sys.stderr)
            return 1
        print(f"  ✓ gate --fail-on {fail_on}: clean", file=sys.stderr)
    return 0
