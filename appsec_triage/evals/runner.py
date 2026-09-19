"""Benchmark runner: same corpus, same prompts, N providers, one comparison table."""

from __future__ import annotations

import json
import os
from collections.abc import Callable
from pathlib import Path

from ..config import PipelineConfig, load_provider_config
from ..context.source import SourceResolver
from ..ingest import native
from ..llm.factory import build_client
from ..lsp.service import LSPService, required_languages as lsp_required_languages
from ..pipeline import TriagePipeline
from ..report import audit
from ..sca import cassette
from .materialize import materialize
from .metrics import compare, score


class BenchSetupError(RuntimeError):
    """The bench cannot produce valid numbers — same contract as triage exit 2."""


def load_labels(corpus: Path) -> dict[str, str]:
    labels: dict[str, str] = {}
    for i, line in enumerate(Path(corpus).read_text(encoding="utf-8").splitlines()):
        if not line.strip():
            continue
        obj = json.loads(line)
        fid = str(obj.get("finding_id") or obj.get("id") or f"{corpus.stem}:{i}")
        if label := obj.get("label"):
            labels[fid] = str(label).strip().lower()
    return labels


def run_bench(
    corpus: Path,
    providers: list[str],
    cfg: PipelineConfig,
    out_dir: Path,
    limit: int | None = None,
    progress: Callable[[int, int], None] | None = None,
    source_roots: list[Path] | None = None,
    no_lsp: bool = False,
    resolve_symbols: bool = False,
    scan_dir: Path | None = None,
) -> dict:
    corpus = Path(corpus)
    labels = load_labels(corpus)
    if not labels:
        raise ValueError(f"{corpus}: no `label` field found — a benchmark needs ground truth")

    findings = list(native.parse(corpus))
    if limit:
        findings = findings[:limit]

    dependencies = sum(1 for f in findings if f.dependency is not None)
    if resolve_symbols and dependencies and not source_roots:
        raise BenchSetupError(
            f"{dependencies} dependency finding(s) with --resolve-symbols need the real checkout "
            "(--source-root): the chain searches the project tree, and against materialized "
            "snippets every package reads as unused."
        )
    if resolve_symbols:
        cfg.resolve_vulnerable_symbols = True
    if scan_dir:
        cfg.scan_out_dir = str(scan_dir)

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    roots = [Path(r) for r in (source_roots or [])]
    materialized = False
    if not roots:
        tree = out_dir / "source"
        findings = materialize(findings, tree)
        roots = [tree]
        materialized = True

    source = SourceResolver(roots)
    symbols = LSPService(cfg.lsp, roots) if cfg.lsp.enabled and not no_lsp else None

    required_present = lsp_required_languages(findings, cfg.lsp, cfg.scope.only_ecosystems)
    if required_present and not no_lsp:
        langs = ", ".join(required_present)
        if symbols is None:
            raise BenchSetupError(
                f"findings in {langs} present, and the language server is mandatory for them "
                "(lsp.yaml has enabled: false). Enable it, or accept degraded numbers explicitly with --no-lsp."
            )
        for lang in required_present:
            if err := symbols.ensure_ready(lang):
                symbols.close()
                raise BenchSetupError(
                    f"the {lang} language server is mandatory but not usable: {err}\n"
                    "Fix it (see `appsec-triage doctor`), or accept degraded numbers explicitly with --no-lsp."
                )

    cards = []
    try:
        for name in providers:
            provider_cfg = load_provider_config(name)
            client = build_client(provider_cfg)
            try:
                run = TriagePipeline(client, provider_cfg, cfg, source=source, symbols=symbols).run(
                    findings, progress=progress
                )
            finally:
                client.close()

            audit.write_jsonl(run, out_dir / f"verdicts-{name}.jsonl")
            cards.append(score(run.records, labels, provider=name, model=provider_cfg.model))
    finally:
        if symbols:
            symbols.close()

    result = compare(cards)
    result["corpus"] = str(corpus)
    result["labelled_findings"] = len(labels)
    result["prompt_pack"] = cfg.prompt_pack
    result["source_roots"] = [str(r) for r in roots]
    result["materialized_corpus"] = materialized
    result["lsp"] = symbols is not None
    result["dependency_findings"] = dependencies
    result["sca_chain"] = bool(cfg.resolve_vulnerable_symbols)
    result["http_cassette"] = {
        "dir": os.environ.get(cassette.DIR_ENV),
        "mode": os.environ.get(cassette.MODE_ENV, "replay") if os.environ.get(cassette.DIR_ENV) else None,
    }
    if symbols:
        result["lsp_stats"] = dict(symbols.stats)
    result["source_stats"] = source.stats()
    (out_dir / "comparison.json").write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    return result
