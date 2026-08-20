"""Extract dependency CVE context with the model, without triage or verdicts."""

from __future__ import annotations

import argparse
import html
import json
import os
import sys
from pathlib import Path

# Allow running this file directly from a checkout without installing the package.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from appsec_triage.config import load_provider_config
from appsec_triage.llm.factory import build_client
from appsec_triage.sca import advisories, discover
from appsec_triage.sca.resolve import SymbolResolver


def _identifiers(finding) -> list[str]:
    values = [finding.rule_id or "", finding.title or ""]
    out = []
    for value in values:
        for token in value.replace(",", " ").split():
            token = token.strip("()[]").upper()
            if token.startswith(("CVE-", "GHSA-", "OSV-", "GO-", "PYSEC-", "RUSTSEC-")) and token not in out:
                out.append(token)
    return out


def _record(project: str, finding, resolver: SymbolResolver) -> dict:
    dependency = finding.dependency
    package = dependency.package
    version = dependency.installed_version or ""
    advisory_id = _identifiers(finding)
    advisory_id = advisory_id[0] if advisory_id else ""
    try:
        advisory = advisories.collect(
            advisory_id, package, dependency.ecosystem or "npm", version)
        context = resolver.extract_context(advisory, version)
        if context is None:
            return {
                "project": project, "advisory": advisory.advisory_id or advisory_id,
                "package": package, "version": version, "status": "agent_failed",
                "error": "agent did not return context",
            }
        return {
            "project": project,
            "advisory": advisory.advisory_id or advisory_id,
            "aliases": advisory.aliases,
            "package": package,
            "version": version,
            "sources": advisory.sources,
            "fix_refs": advisory.fix_refs,
            "summary": advisory.summary,
            "scope": context.scope or "unknown",
            "source_stage": context.source_stage or "unknown",
            "symbol": str(context) if context.function or context.file else "",
            "file": context.file,
            "what_changed": context.what_changed,
            "precondition": context.precondition,
            "required_actions": list(context.required_actions),
            "search_targets": list(context.search_targets)
                or [name for name, _ in context.candidates],
            "evidence": context.evidence,
            "evidence_status": "verified" if context.evidence else "unverified",
            "context_note": context.note,
            "status": "extracted",
        }
    except Exception as exc:  # noqa: BLE001 - one advisory must not stop the batch
        return {
            "project": project, "advisory": advisory_id, "package": package,
            "version": version, "status": "error", "error": f"{type(exc).__name__}: {exc}",
        }


def _html(records: list[dict], output: Path) -> None:
    rows = []
    for item in records:
        status = item.get("status", "error")
        details = "<br>".join(
            f"<b>{html.escape(key)}</b>: {html.escape(str(value))}"
            for key, value in item.items()
            if key not in {"project", "advisory", "package", "version", "status"}
            and value not in (None, "", [], {})
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(item.get('project', '')))}</td>"
            f"<td>{html.escape(str(item.get('advisory', '')))}</td>"
            f"<td>{html.escape(str(item.get('package', '')))}@{html.escape(str(item.get('version', '')))}</td>"
            f"<td class='{html.escape(status)}'>{html.escape(status)}</td>"
            f"<td>{details}</td>"
            "</tr>"
        )
    document = """<!doctype html>
<meta charset="utf-8"><title>advisory context extraction</title>
<style>body{font:14px system-ui;margin:2rem;color:#202124}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #ddd;padding:.6rem;vertical-align:top;text-align:left}th{background:#f3f4f6}
.extracted{color:#087f5b;font-weight:600}.agent_failed,.error{color:#b42318;font-weight:600}
td:last-child{max-width:58rem;line-height:1.5}</style>
<h1>advisory context extraction</h1>
<p>Agent extraction only. No project SCA verdicts were run.</p>
<table><thead><tr><th>Project</th><th>Advisory</th><th>Package</th><th>Status</th><th>Extracted context</th></tr></thead>
<tbody>""" + "".join(rows) + "</tbody></table>"
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(document, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project", action="append", nargs=2, metavar=("NAME", "PATH"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--ecosystem", default="npm")
    args = parser.parse_args()
    if not os.environ.get("DEEPSEEK_API_KEY"):
        print("DEEPSEEK_API_KEY is not set", file=sys.stderr)
        return 2

    provider = load_provider_config("deepseek")
    client = build_client(provider)
    resolver = SymbolResolver(client, roots=[])
    records = []
    for name, raw_path in args.project:
        root = Path(raw_path).resolve()
        result = discover.discover(root, limit=args.limit)
        findings = [f for f in result.findings if f.dependency and
                    (f.dependency.ecosystem or "").lower() == args.ecosystem.lower()]
        print(f"{name}: {len(findings)} {args.ecosystem} advisory findings", file=sys.stderr)
        for finding in findings[:args.limit]:
            item = _record(name, finding, resolver)
            records.append(item)
            print(f"{name}: {item.get('advisory')} -> {item.get('status')}", file=sys.stderr)

    json_path = args.out.with_suffix(".json")
    json_path.write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
    _html(records, args.out)
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
