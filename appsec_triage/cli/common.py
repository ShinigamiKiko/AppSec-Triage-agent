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
from ..llm.base import LLMAuthError, LLMError
from ..llm.factory import build_client
from ..lsp.service import LSPService, required_languages as lsp_required_languages
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


def preflight_provider(provider_cfg) -> str | None:
    """One tiny call before anything expensive: None when the provider answers.

    A rejected key used to surface 38 minutes into a run — after CodeQL, the
    SBOM, 890 advisory lookups and the SCA preparation — as a stream of
    warnings the run then ignored.
    """
    client = build_client(provider_cfg)
    try:
        client.ping()
    except LLMAuthError as exc:
        return str(exc)
    except LLMError as exc:
        return f"провайдер {provider_cfg.name} не отвечает: {exc}"
    finally:
        client.close()
    return None


def node_modules_problem(roots: list[Path]) -> str | None:
    """A JS project without an installed tree: the language server and the
    package-source lookups are blind, and the run should say so up front."""
    for root in roots:
        root = Path(root)
        if not (root / "package.json").is_file():
            continue
        modules = root / "node_modules"
        try:
            empty = not modules.is_dir() or not any(modules.iterdir())
        except OSError:
            empty = True
        if empty:
            return (f"{root}: package.json есть, а node_modules пуст или отсутствует — "
                    "typescript-language-server не построит индекс, исходники пакетов недоступны. "
                    "Выполните `yarn install --ignore-scripts` (или `npm ci --ignore-scripts`) до прогона; "
                    "без этого ответы LSP по JS/TS будут неполными, а медленный сервер отключится сам.")
    return None


def attach_file_log(out: Path) -> Path:
    """Step-by-step log in the output directory at INFO, whatever the console level.

    The console stays quiet; the file keeps `finding … started / decided in Ns`
    and the per-stage timings, which is what a slow run is diagnosed from.
    """
    import logging

    out.mkdir(parents=True, exist_ok=True)
    path = out / "appsec-triage.log"
    root = logging.getLogger()
    if not any(getattr(h, "baseFilename", None) == str(path.resolve()) for h in root.handlers):
        handler = logging.FileHandler(path, encoding="utf-8")
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s", "%H:%M:%S"))
        root.addHandler(handler)
        for existing in root.handlers:
            if existing is not handler and existing.level == logging.NOTSET:
                existing.setLevel(root.level)
        if root.level > logging.INFO or root.level == logging.NOTSET:
            root.setLevel(logging.INFO)
    return path


def gate_count(fail_on: str, counts: dict[str, int]) -> int | None:
    if fail_on == "none":
        return None
    return {"confirmed": counts["confirmed"], "review": counts["confirmed"] + counts["unknown"]}[fail_on]


def run_triage(args: argparse.Namespace, findings_path: Path, out: Path, source_roots: list[Path]) -> int:
    if source_roots:
        from ..context.detection import DetectionError, get_source_suffixes
        try:
            get_source_suffixes(source_roots, include_configs=True)
        except DetectionError as exc:
            print(f"error: invalid APPSEC_ECOSYSTEMS: {exc}", file=sys.stderr)
            return 2

    cfg = load_pipeline_config(args.config)
    if getattr(args, "provider", None): cfg.provider = args.provider
    if getattr(args, "prompt_pack", None): cfg.prompt_pack = args.prompt_pack
    if getattr(args, "workers", None): cfg.max_workers = args.workers
    # Only an explicit flag overrides the file: an argparse default would quietly
    # replace `parallel_llm` from pipeline.yaml on every run.
    if (parallel := getattr(args, "parallel_llm", None)) is not None:
        if parallel < 1:
            print("error: --parallel-llm must be 1 or more", file=sys.stderr)
            return 2
        cfg.parallel_llm = parallel
    if (resolve := getattr(args, "resolve_symbols", None)) is not None:
        cfg.resolve_vulnerable_symbols = resolve
    if getattr(args, "govulncheck", None): cfg.govulncheck_report = str(args.govulncheck)
    if getattr(args, "scan_dir", None): cfg.scan_out_dir = str(args.scan_dir)
    if getattr(args, "sbom", None): cfg.sbom_path = str(args.sbom)
    elif getattr(args, "scan_dir", None) and (Path(args.scan_dir) / ".sbom.json").is_file():
        cfg.sbom_path = str(Path(args.scan_dir) / ".sbom.json")
    if os.environ.get("NVD_API_KEY"): cfg.nvd_api_key = os.environ["NVD_API_KEY"]

    provider_cfg = load_provider_config(cfg.provider)
    if provider_cfg.leaves_the_perimeter: cfg.redact_secrets = True
    log_path = attach_file_log(out)
    print(f"→ подробный лог: {log_path}", file=sys.stderr)
    if not getattr(args, "no_preflight", False) and not getattr(args, "_preflight_done", False):
        if problem := preflight_provider(provider_cfg):
            print(f"error: {problem}", file=sys.stderr)
            return 2
    findings = ingest.load(findings_path)
    from ..ingest.dependency import qualify_composer_names, qualify_npm_names
    if qualified := qualify_composer_names(findings, source_roots):
        print(f"→ {qualified} Composer package name(s) completed from composer.lock", file=sys.stderr)
    if cfg.sbom_path:
        from ..sca import sbom as sbom_mod
        document, problem = sbom_mod.load(cfg.sbom_path)
        if problem:
            print(f"  ! {problem}", file=sys.stderr)
        elif scoped := qualify_npm_names(findings, document):
            print(f"→ {scoped} npm-имён восстановлены со scope по SBOM", file=sys.stderr)
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
        if not getattr(args, "_preflight_done", False) and (problem := node_modules_problem(source_roots)):
            print(f"  ! {problem}", file=sys.stderr)
        symbols = LSPService(lsp_cfg, source_roots)
        print("→ language servers enabled (definitions and reachability)", file=sys.stderr)
    required_present = lsp_required_languages(findings, lsp_cfg, cfg.scope.only_ecosystems)
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
            try:
                run = pipeline.run(findings, progress=progress, on_record=journal.append)
            except LLMAuthError as exc:
                print(f"\nerror: {exc}\n       прогон остановлен; готовые вердикты сохранены в {journal_path}, "
                      "повторный запуск продолжит с места остановки", file=sys.stderr)
                return 2
            run.records.extend(recovered)
            if reuse_plan:
                run.records.extend(reuse_plan.reused)
                run.reuse = reuse_plan.summary()
    finally:
        client.close()
        from ..sca.codeql_runner import close_servers
        close_servers()
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
    title = f"SAST LLM Triage — {provider_cfg.name}"
    report = html.write(run, out / f"report-{stem}.html", title=title)
    # The same report with the advisories retold in Russian. Two files rather
    # than one bilingual page: each reads as one language, and the original
    # wording stays available in the finding's own block.
    html.write(run, out / f"report-{stem}-ru.html", title=title, russian=True)
    from ..models import VerdictLabel
    counts = run.counts()
    proven = sum(1 for r in run.records if r.verdict.verdict is VerdictLabel.confirmed and (r.sca is None or r.sca.outcome in _PROVEN_OUTCOMES))
    unproven = counts["confirmed"] - proven
    print(f"\n  доказано {proven} · не закрыто {unproven} · закрыто {counts['false_positive']} · на человека {sum(1 for r in run.records if r.verdict.requires_human_review)} · corrected {sum(1 for r in run.records if r.overrides)} · errors {sum(1 for r in run.records if r.error)} · ${run.total_cost_usd:.4f}" + (f" ({run.model_calls} запросов)" if run.model_calls else ""), file=sys.stderr)
    total = len(run.records) or 1
    settled = sum(1 for r in run.records if not r.verdict.requires_human_review)
    target = getattr(cfg.queue, "auto_decide_target_pct", 70.0)
    print(f"  решено без человека: {settled}/{len(run.records)} ({100 * settled / total:.0f}%, цель ≥{target:.0f}%)",
          file=sys.stderr)
    if 100 * settled / total < target:
        print(f"  ! ниже цели: {len(run.records) - settled} находок ждут человека — "
              "см. summary (decided_by, dependency_priority) и лог", file=sys.stderr)
    priorities = {p: sum(1 for r in run.records if r.sca is not None and r.sca.priority == p)
                  for p in ("critical", "high", "medium", "low")}
    if any(priorities.values()):
        print("  приоритет зависимостей: " + ", ".join(f"{k} {v}" for k, v in priorities.items()), file=sys.stderr)
    from ..report.audit import _confidence_spread, _stage_seconds
    stages = _stage_seconds(run.records)
    if stages:
        print("  время по этапам (медиана/сумма, с): " + ", ".join(
            f"{k} {v['median']:.0f}/{v['total']:.0f}" for k, v in stages.items()), file=sys.stderr)
    spread = _confidence_spread(run.records)
    if spread.get("stdev") is not None and spread["stdev"] < 0.02:
        print(f"  ! уверенность модели почти не различается (σ={spread['stdev']}, "
              f"{spread['distinct']} значений на {spread['n']} вердиктов) — порог автоприменения ничего не решает",
              file=sys.stderr)
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
