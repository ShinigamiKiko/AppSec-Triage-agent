"""Self-contained HTML report — the artifact an AppSec engineer actually opens.

Ordered by what needs a human first: confirmed, then unknown, then the closed
pile last. No external assets so it can be attached to a ticket or emailed.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path

from .. import review
from ..models import TriageRecord, VerdictLabel
from ..pipeline import TriageRun

_TABLE_CSS = """
table.findings{width:100%;border-collapse:collapse;font-size:13px;margin:12px 0 28px}
table.findings th{text-align:left;padding:8px 10px;border-bottom:2px solid #d0d7de;
  position:sticky;top:0;background:#fff}
table.findings td{padding:8px 10px;border-bottom:1px solid #eaeef2;vertical-align:top}
table.findings tr.yes{background:#fff5f5}
table.findings tr.no{background:#f6fff8}
td.answer{font-weight:600;white-space:nowrap}
td.answer.yes{color:#b32020}
td.answer.no{color:#1a7f37}
td.answer.maybe{color:#9a6700}
table.findings .kind{color:#57606a;font-size:11px}
table.findings .trace,table.findings .why{color:#3d444d;font-size:12px}
table.findings .ext-cell{font-size:12px}
span.ext{display:inline-block;padding:1px 6px;border-radius:3px;background:#ddf4ff;
  color:#0969da;font-weight:600;font-size:11px}
"""

_COV_CSS = """
.cov{padding:14px 18px;border-radius:8px;margin:18px 0;line-height:1.5}
.cov.ok{background:#0f2b18;border:1px solid #1f6b3a}
.cov.bad{background:#3a1414;border:1px solid #8b2c2c}
.cov.unknown{background:#2b2411;border:1px solid #7a6320}
.cov ul{margin:8px 0 8px 20px}
"""

_ORDER = {VerdictLabel.confirmed: 0, VerdictLabel.unknown: 1, VerdictLabel.false_positive: 2}

_CSS = """
:root{--bg:#fff;--fg:#16181d;--muted:#666e7a;--line:#e3e6ea;--card:#fff;
--confirmed:#c0392b;--unknown:#b7791f;--fp:#2f855a;--accent:#2b6cb0}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--fg:#e8eaed;--muted:#98a1ae;
--line:#2a2f37;--card:#1b1e24;--confirmed:#ff6b5e;--unknown:#e2b33c;--fp:#5fcf8e;--accent:#6aa9f0}}
*{box-sizing:border-box}
body{margin:0;padding:2rem 1.25rem;background:var(--bg);color:var(--fg);
font:15px/1.55 ui-sans-serif,system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1080px;margin:0 auto}
h1{font-size:1.5rem;margin:0 0 .25rem}
.sub{color:var(--muted);margin:0 0 1.5rem;font-size:.9rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.75rem;margin-bottom:2rem}
.card{border:1px solid var(--line);border-radius:10px;padding:.85rem 1rem;background:var(--card)}
.card .n{font-size:1.6rem;font-weight:650;line-height:1.2}
.card .l{color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.04em}
details{border:1px solid var(--line);border-radius:10px;margin-bottom:.6rem;background:var(--card);overflow:hidden}
summary{cursor:pointer;padding:.7rem .9rem;display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
summary::-webkit-details-marker{display:none}
.badge{font-size:.7rem;font-weight:700;letter-spacing:.05em;padding:.15rem .5rem;border-radius:999px;
border:1px solid currentColor;text-transform:uppercase;white-space:nowrap}
.confirmed{color:var(--confirmed)}.unknown{color:var(--unknown)}.false_positive{color:var(--fp)}
.path{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.82rem;color:var(--muted);
overflow:hidden;text-overflow:ellipsis;flex:1;min-width:0}
.cwe{font-size:.78rem;font-weight:600;color:var(--accent)}
.body{padding:0 .9rem .9rem;border-top:1px solid var(--line)}
.body h4{margin:.9rem 0 .3rem;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
pre{background:rgba(127,127,127,.09);padding:.6rem .75rem;border-radius:7px;overflow-x:auto;
font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;margin:0}
ul{margin:.2rem 0;padding-left:1.2rem}
.meta{display:flex;flex-wrap:wrap;gap:.4rem .9rem;color:var(--muted);font-size:.75rem;margin-top:.9rem;
padding-top:.6rem;border-top:1px dashed var(--line)}
.override{border-left:3px solid var(--unknown);padding-left:.7rem;margin:.3rem 0;font-size:.85rem}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin-bottom:2rem}
th,td{text-align:left;padding:.4rem .6rem;border-bottom:1px solid var(--line)}
th{color:var(--muted);font-weight:600;font-size:.75rem;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:1rem;margin:2rem 0 .7rem;padding-bottom:.3rem;border-bottom:1px solid var(--line)}
.note{color:var(--muted);font-size:.85rem}
.sym{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem;color:var(--accent);
background:rgba(127,127,127,.12);padding:.1rem .4rem;border-radius:4px;white-space:nowrap}
.kind{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.loc{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.75rem;color:var(--muted)}
.conf{font-variant-numeric:tabular-nums;font-weight:600;font-size:.85rem;cursor:help}
.blocking{border-left:3px solid var(--accent);padding-left:.7rem;font-style:italic}
.flowlist{list-style:none;padding:0;margin:.4rem 0}
.flow{border-left:3px solid var(--line);padding:.5rem 0 .5rem .8rem;margin-left:.4rem;position:relative}
.flow.source{border-left-color:var(--confirmed)}
.flow.sink{border-left-color:var(--confirmed)}
.flow.sanitizer{border-left-color:var(--fp)}
.flow.unverified{opacity:.62;border-left-style:dashed}
.flow p{margin:.3rem 0 0;font-size:.87rem}
.flow pre{margin:.35rem 0 0}
.flowhead{display:flex;gap:.6rem;align-items:center;flex-wrap:wrap}
.role{font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.05em}
.taint{font-size:.68rem;padding:.05rem .4rem;border-radius:999px;border:1px solid currentColor}
.taint.tainted{color:var(--confirmed)}.taint.clean{color:var(--fp)}
.brief{border:1px solid var(--accent);border-radius:8px;padding:.2rem .9rem .8rem;margin:.9rem 0;
background:rgba(43,108,176,.06)}
.brief h4{color:var(--accent)}
.q{font-weight:600;margin:.5rem 0 .3rem}
.implies{font-size:.85rem;color:var(--muted);margin:.3rem 0 0}
.questions{padding-left:1.2rem}
.questions>li{margin-bottom:.8rem}
.warn{font-size:.68rem;color:var(--unknown);border:1px dashed currentColor;padding:.05rem .4rem;border-radius:999px}
"""


def _e(value: object) -> str:
    return html.escape(str(value if value is not None else ""))


_ROLE_ICON = {"source": "◉", "propagation": "→", "sanitizer": "🛡", "sink": "⌖"}


def _dataflow_html(v) -> str:
    if not v.dataflow:
        return (
            '<h4>Dataflow</h4><p class="note">No path was reported by the analyzer, so none was '
            "reconstructed. The verdict rests on the code and description alone.</p>"
        )
    rows = []
    for step in v.dataflow:
        cls = f"flow {step.role.value}" + ("" if step.grounded else " unverified")
        taint = "tainted" if step.tainted else "clean"
        badge = "" if step.grounded else '<span class="warn">unverified</span>'
        code = f"<pre>{_e(step.code)}</pre>" if step.code else ""
        rows.append(
            f'<li class="{cls}"><div class="flowhead">'
            f'<span class="role">{_ROLE_ICON.get(step.role.value, "→")} {_e(step.role.value)}</span>'
            f'<span class="taint {taint}">{taint}</span>'
            f'<span class="loc">{_e(step.location or "")}</span>{badge}</div>'
            f"{code}<p>{_e(step.explanation)}</p></li>"
        )
    return f'<h4>Dataflow — how the value travels</h4><ol class="flowlist">{"".join(rows)}</ol>'


_ANSWER = {
    "confirmed": ("да", "yes"),
    "unknown": ("не установлено", "maybe"),
    "false_positive": ("нет", "no"),
}


def _where(r: TriageRecord) -> str:
    """File, line and symbol — the three things a reviewer opens the editor with."""
    parts: list[str] = []
    if r.sca and r.sca.call_sites:
        parts.extend(r.sca.call_sites[:3])
    elif r.file_path:
        location = r.file_path
        if r.start_line:
            location = f"{location}:{r.start_line}"
        parts.append(location)
    symbol = (r.sca.symbol if r.sca and r.sca.symbol else None)
    if not symbol and r.verdict.vulnerable_symbol:
        symbol = r.verdict.vulnerable_symbol.name
    if symbol:
        parts.append(f"<code>{_e(symbol)}</code>")
    return "<br>".join(_e(p) if not p.startswith("<code>") else p for p in parts) or "—"


_ROUTES = {
    "excluded": "вне платформы — факт среды, без поиска и CodeQL",
    "callgraph": "граф вызовов",
    "codeql": "CodeQL",
    "psalm": "Psalm (типы и taint, PHP)",
    "text": "поиск по тексту, без CodeQL",
    "package": "факт импорта пакета",
    "condition": "условие эксплуатации",
    "unknown": "не определён",
}


def _trace(r: TriageRecord) -> str:
    """What was followed, and which route the dependency chain took to get there."""
    body = _trace_body(r)
    route = r.sca.route if r.sca else ""
    calls = r.sca.codeql_calls if r.sca else []
    parts = []
    if route:
        parts.append(f"<em>маршрут: {_e(_ROUTES.get(route, route))}</em>")
    if body != "—":
        parts.append(body)
    if calls:
        # Who asked CodeQL what, and the answer — the reviewer's proof the database was consulted.
        parts.append("<small>" + "<br>".join(_e(call[:240]) for call in calls[:4]) + "</small>")
    return "<br>".join(parts) or "—"


def _trace_body(r: TriageRecord) -> str:
    """What was actually followed, not what might exist."""
    # The audit line first, when there is one: it says how the closure was
    # checked, and a reviewer reading a closed row wants that before the trace.
    audit = r.sca.audit if r.sca else ""
    if r.sca and r.sca.trace:
        return f"{_e(audit)}<br>{_e(r.sca.trace)}" if audit else _e(r.sca.trace)
    if audit:
        return _e(audit)
    steps = getattr(r.verdict, "dataflow", None) or []
    if steps:
        return "<br>".join(
            _e(f"{s.location or 'unknown'} {s.role}") for s in steps[:4])
    if r.symbol_context:
        return "<br>".join(_e(s) for s in r.symbol_context[:3])
    return "—"


def _external_cell(r: TriageRecord) -> str:
    """What has to be checked outside the code, and by whom.

    Kept in its own column because it is a different kind of answer: not "we
    looked and found nothing" but "the answer is not here". A reviewer who sees
    it should know where to go, not merely that the tool gave up.
    """
    if not r.sca:
        return "—"
    if r.sca.owner:
        return (f'<span class="ext">инфраструктура</span><br>{_e(r.sca.external)}'
                f'<br><em>владелец: {_e(r.sca.owner)}</em>')
    if r.sca.external:
        return f'<span class="ext">EXTERNAL</span><br>{_e(r.sca.external)}'
    return "—"


def _summary_table(run: TriageRun) -> str:
    """One row per finding, in the order a queue should be worked."""
    rank = {"confirmed": 0, "unknown": 1, "false_positive": 2}
    ordered = sorted(run.records, key=lambda r: (rank.get(r.verdict.verdict.value, 3),
                                                 r.file_path or ""))
    rows = []
    for r in ordered:
        answer, css = _ANSWER.get(r.verdict.verdict.value, ("—", "maybe"))
        if r.sca and r.sca.package:
            what = f"<strong>{_e(r.sca.package)}</strong>"
            if r.sca.installed_version:
                what += f" {_e(r.sca.installed_version)}"
            kind = _e(r.sca.placement or "зависимость")
        else:
            what = f"<strong>{_e(r.cwe or r.rule_id or '—')}</strong>"
            kind = _e(r.rule_id or "код проекта")
        note = _e(r.sca.outcome_note) if r.sca and r.sca.outcome_note else _e(r.verdict.reason)
        rows.append(
            f"<tr class='{css}'>"
            f"<td>{what}<br><span class='kind'>{kind}</span></td>"
            f"<td class='answer {css}'>{answer}</td>"
            f"<td>{_where(r)}</td>"
            f"<td class='trace'>{_trace(r)}</td>"
            f"<td class='ext-cell'>{_external_cell(r)}</td>"
            f"<td class='why'>{note[:400]}</td>"
            f"</tr>"
        )
    return (
        '<h2>Находки</h2><table class="findings"><thead><tr>'
        "<th>Что</th><th>Уязвимо</th><th>Где</th><th>Трасса</th>"
        "<th>Вне кода</th><th>Почему</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


def _record_html(r: TriageRecord) -> str:
    v = r.verdict
    sym = v.vulnerable_symbol
    sym_summary = f'<span class="sym">{_e(sym.name)}</span>' if sym else ""
    parts = [
        (f'<details><summary>'
        f'<span class="badge {v.verdict.value}">{v.verdict.value.replace("_", " ")}</span>'
        f'<span class="cwe">{_e(r.cwe or "—")}</span>'
        f"{sym_summary}"
        f'<span class="path" title="{_e(r.file_path)}">{_e(r.file_path)}</span>'
        f'<span class="conf" title="{_e(v.confidence_rationale)}">'
        f'{_e(v.confidence_band or "—")} · {v.confidence:.2f}</span>'
        f'</summary><div class="body">'),
        f"<h4>Verdict rationale</h4><p>{_e(v.reason)}</p>",
    ]

    brief = review.build(r)
    if brief.actionable:
        facts = "".join(f"<li>{_e(f)}</li>" for f in brief.established)
        blocks = []
        for q in brief.questions:
            where = "".join(f"<li><code>{_e(w)}</code></li>" for w in q.look_at if w)
            implies = ""
            if q.if_yes or q.if_no:
                implies = (
                    f'<p class="implies"><strong>да →</strong> {_e(q.if_yes)}'
                    f'<br><strong>нет →</strong> {_e(q.if_no)}</p>'
                )
            blocks.append(
                f'<li><p class="q">{_e(q.text)}</p>'
                + (f"<p class=\"note\">смотреть:</p><ul>{where}</ul>" if where else "")
                + implies
                + "</li>"
            )
        parts.append(
            '<div class="brief"><h4>Что нужно от тебя</h4>'
            + (f'<p class="note">Установлено автоматически:</p><ul>{facts}</ul>' if facts else "")
            + f'<ol class="questions">{"".join(blocks)}</ol></div>'
        )

    if sym:
        loc = f' <span class="loc">{_e(sym.location)}</span>' if sym.location else ""
        heading = "What is at fault" if v.verdict.value == "confirmed" else "What the scanner pointed at"
        parts.append(
            f"<h4>{heading}</h4>"
            f'<p><code class="sym">{_e(sym.name)}</code> <span class="kind">{_e(sym.kind)}</span>{loc}<br>'
            f"{_e(sym.why)}</p>"
        )

    parts.append(_dataflow_html(v))

    if v.confidence_rationale:
        parts.append(
            f"<h4>Certainty: {_e(v.confidence_band or '—')} ({v.confidence:.2f})</h4>"
            f"<p>{_e(v.confidence_rationale)}</p>"
        )
    if v.verdict.value == "unknown" and v.blocking_question:
        parts.append(
            f'<h4>What would settle this</h4><p class="blocking">{_e(v.blocking_question)}</p>'
        )
    if v.evidence:
        quotes = "\n".join(_e(q) for q in v.evidence)
        parts.append(f"<h4>Evidence (verified against input)</h4><pre>{quotes}</pre>")
    if v.missing_information:
        items = "".join(f"<li>{_e(m)}</li>" for m in v.missing_information)
        parts.append(f"<h4>Missing information</h4><ul>{items}</ul>")
    if r.overrides:
        blocks = "".join(f'<div class="override">{_e(o)}</div>' for o in r.overrides)
        original = _e(r.original_verdict.verdict.value) if r.original_verdict else "—"
        parts.append(f"<h4>Post-validation overrides (model said: {original})</h4>{blocks}")
    if r.error:
        parts.append(f"<h4>Error</h4><pre>{_e(r.error)}</pre>")

    meta = [
        f"class: {_e(v.evidence_class.value)}",
        f"decided by: {_e(r.decided_by)}",
        f"human review: {'yes' if v.requires_human_review else 'no'}",
        f"provider: {_e(r.provider)}",
        f"model: {_e(r.model or '—')}",
        f"prompt: {_e(r.prompt_id)} v{_e(r.prompt_version)}",
    ]
    if r.latency_ms:
        meta.append(f"latency: {r.latency_ms} ms")
    if r.cost_usd:
        meta.append(f"cost: ${r.cost_usd:.5f}")
    parts.append('<div class="meta">' + "".join(f"<span>{m}</span>" for m in meta) + "</div>")
    parts.append("</div></details>")
    return "".join(parts)


def _coverage_html(run: TriageRun) -> str:
    """A banner above the numbers when a scanner did not run.

    Placed before the counts on purpose: it changes what they mean. Twenty
    findings from a complete scan and twenty from a scan that lost its
    dependency layer are not the same report, and nothing else on the page
    distinguishes them.
    """
    cov = getattr(run, "coverage", None)
    if cov is None:
        return (
            '<div class="cov unknown">Scanner coverage unknown — these findings were not produced '
            "by a scan this report can account for.</div>"
        )
    if getattr(cov, "complete", False):
        return f'<div class="cov ok">All scanners completed: {_e(", ".join(cov.ran))}.</div>'
    gaps = "".join(f"<li>{_e(g)}</li>" for g in cov.gaps())
    return (
        '<div class="cov bad"><strong>This report is incomplete.</strong>'
        f"<ul>{gaps}</ul>"
        "Findings below cover only what did run — a low count here is not evidence of a clean "
        "codebase.</div>"
    )


def render(run: TriageRun, *, title: str = "SAST LLM Triage") -> str:
    counts = run.counts()
    total = len(run.records) or 1
    overridden = sum(1 for r in run.records if r.overrides)
    review = sum(1 for r in run.records if r.verdict.requires_human_review)

    scoped_out = sum(v for v in run.scope_excluded.values())
    cards = [
        ("Findings", len(run.records), ""),
        ("Model triaged", run.triaged_count, ""),
        ("Confirmed", counts["confirmed"], "confirmed"),
        ("Unknown", counts["unknown"], "unknown"),
        ("Auto-closed", counts["false_positive"], "false_positive"),
        ("Needs a human", review, ""),
        ("Noise removed", f'{100 * counts["false_positive"] / total:.0f}%', ""),
        ("Out of scope", scoped_out, ""),
    ]
    cards_html = "".join(
        f'<div class="card"><div class="n {cls}">{_e(n)}</div><div class="l">{_e(label)}</div></div>'
        for label, n, cls in cards
    )

    by_cwe: dict[str, dict[str, int]] = {}
    for r in run.records:
        b = by_cwe.setdefault(r.cwe or "unclassified", {"confirmed": 0, "unknown": 0, "false_positive": 0})
        b[r.verdict.verdict.value] += 1
    rows = "".join(
        f"<tr><td>{_e(cwe)}</td><td>{b['confirmed']}</td><td>{b['unknown']}</td>"
        f"<td>{b['false_positive']}</td><td>{sum(b.values())}</td></tr>"
        for cwe, b in sorted(by_cwe.items(), key=lambda kv: -sum(kv[1].values()))
    )

    ordered = sorted(run.records, key=lambda r: (_ORDER[r.verdict.verdict], -r.verdict.confidence))
    findings_html = "".join(_record_html(r) for r in ordered)

    coverage_html = _coverage_html(run)
    generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{_e(title)}</title><style>{_CSS}{_COV_CSS}{_TABLE_CSS}</style></head>
<body><main>
<h1>{_e(title)}</h1>
<p class="sub">{generated} · provider <strong>{_e(run.provider)}</strong> ·
model <strong>{_e(run.model)}</strong> · prompts <strong>{_e(run.prompt_pack)}</strong> ·
{overridden} verdict(s) corrected by post-validation ·
cost ${run.total_cost_usd:.4f}</p>
{coverage_html}
<div class="cards">{cards_html}</div>
<h2>By CWE</h2>
<table><thead><tr><th>CWE</th><th>Confirmed</th><th>Unknown</th><th>Closed</th><th>Total</th></tr></thead>
<tbody>{rows}</tbody></table>
{_summary_table(run)}
<h2>Findings — highest priority first</h2>
{findings_html}
</main></body></html>"""


def write(run: TriageRun, path: Path, *, title: str = "SAST LLM Triage") -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render(run, title=title), encoding="utf-8")
    return path
