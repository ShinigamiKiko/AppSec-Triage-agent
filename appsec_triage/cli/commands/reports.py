"""Commands operating on existing verdict reports."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ... import ingest, prioritize, review
from ...models import VerdictLabel
from ...report import audit
from ..common import load_pipeline_config


def cmd_variants(args: argparse.Namespace) -> int:
    from ... import variants as variant_search
    records = audit.read_jsonl(Path(args.verdicts))
    findings = list(ingest.load(Path(args.findings))) if args.findings else []
    by_id = {f.finding_id: f for f in findings}
    seeds = [(r, by_id[r.finding_id].code_context.snippet if r.finding_id in by_id else None) for r in records if r.verdict.verdict is VerdictLabel.confirmed and r.kind == "weakness"]
    if not seeds:
        print("no confirmed weaknesses to seed from", file=sys.stderr)
        return 0
    usable, rejected = [], []
    for record, snippet in seeds:
        ok, why = variant_search.seed_is_trustworthy(record)
        (usable if ok else rejected).append((record, snippet, why))
    print(chr(10) + "  seeds:", file=sys.stderr)
    for record, _, why in usable: print(f"    ok   {record.cwe or '-':10} {record.file_path}:{record.start_line or '?'}  ({why})", file=sys.stderr)
    for record, _, why in rejected: print(f"    skip {record.cwe or '-':10} {record.file_path}:{record.start_line or '?'}  ({why})", file=sys.stderr)
    found = variant_search.search([(r, sn) for r, sn, _ in usable], findings, [Path(p) for p in (args.source_root or [])])
    print(f"\n  {len(usable)} confirmed weakness(es) used as seeds")
    print(f"  -> {len(found)} place(s) with the same shape that no scanner reported\n")
    by_seed: dict[str, list] = {}
    for v in found: by_seed.setdefault(v.seed_location, []).append(v)
    for seed, group in sorted(by_seed.items(), key=lambda kv: -len(kv[1])):
        print(f"  seed {seed}")
        for v in group[:10]: print(f"     {v.file_path}:{v.line}  {v.text[:110]}")
        if len(group) > 10: print(f"     ... {len(group) - 10} more")
        print()
    if args.out:
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(json.dumps([v.as_dict() for v in found], ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  written: {args.out}")
    return 0


def cmd_queue(args: argparse.Namespace) -> int:
    cfg = load_pipeline_config(args.config)
    if args.budget is not None: cfg.queue.review_budget_pct = args.budget
    if args.no_cluster: cfg.queue.cluster = False
    records = audit.read_jsonl(Path(args.verdicts))
    findings = {f.finding_id: f for f in ingest.load(Path(args.findings))} if args.findings else {}
    queue = prioritize.build(records, cfg.queue, findings)
    s = queue.summary()
    print(f"\n  {s['total_findings']} finding(s) triaged\n  {s['clusters_collapsed']} collapsed into clusters")
    print(f"  -> {len(queue.to_review)} review item(s) covering {s['findings_behind_review_items']} finding(s) = {s['manual_share_pct']}% manual (budget {s['budget_pct']}%)")
    print(f"     of which {s['items_needing_a_decision']} need a decision and {s['items_needing_an_action']} are remediation with the fix already named")
    if s["budget_overflowed"]: print("  ! budget-exempt items alone exceed the budget: this codebase needs more review than the target allows. Worth knowing rather than hiding.", file=sys.stderr)
    print()
    for i, item in enumerate(queue.to_review, 1):
        more = f"  (+{item.cluster_size - 1} more)" if item.cluster_size > 1 else ""
        flag = "  [always-review]" if item.exempt else ""
        print(f"{i:>3}. [{item.score:>3}] {item.record.verdict.verdict.value:<14} {item.record.cwe or '-':<9} {item.record.file_path[-50:]}{more}{flag}")
        brief = review.build(item.record)
        for fact in brief.established: print(f"       ✓ {fact[:110]}")
        for n, q in enumerate(brief.questions, 1):
            print(f"       ? {n}. {q.text}")
            for where in q.look_at[:2]:
                if where: print(f"           смотреть: {where[:100]}")
            if q.if_yes: print(f"           да → {q.if_yes}")
            if q.if_no: print(f"           нет → {q.if_no}")
        if args.verbose:
            for reason in item.reasons: print(f"       · {reason}")
    if args.out:
        out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"summary": s, "queue": [{**i.as_dict(), "review": review.build(i.record).as_dict()} for i in queue.items]}, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n  written: {out}", file=sys.stderr)
    return 0
