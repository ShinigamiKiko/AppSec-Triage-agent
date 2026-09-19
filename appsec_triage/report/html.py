"""Self-contained HTML report — the artifact an AppSec engineer actually opens."""

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
table.findings .cond-cell{font-size:12px;max-width:26rem}
span.cond{display:inline-block;padding:1px 6px;border-radius:3px;font-weight:600;font-size:11px}
span.cond.holds{background:#ffebe9;color:#b32020}
span.cond.absent{background:#dafbe1;color:#1a7f37}
span.cond.outside{background:#fff8c5;color:#9a6700}
table.findings .cond-hits{color:#57606a;font-size:11px}
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
ol.why{list-style:none;margin:.4rem 0 0;padding:0;counter-reset:st}
ol.why>li{counter-increment:st;position:relative;padding:.1rem 0 .7rem 1.7rem;
border-left:2px solid var(--line);margin-left:.45rem}
ol.why>li:last-child{border-left-color:transparent;padding-bottom:.1rem}
ol.why>li::before{content:counter(st);position:absolute;left:-.62rem;top:0;width:1.15rem;height:1.15rem;
border-radius:999px;background:var(--card);border:1px solid var(--line);color:var(--muted);
font-size:.62rem;display:flex;align-items:center;justify-content:center;font-variant-numeric:tabular-nums}
ol.why li.analyzer::before{border-color:var(--accent);color:var(--accent)}
ol.why li.audit::before{border-color:var(--fp);color:var(--fp)}
ol.why li.checks::before{border-color:var(--unknown);color:var(--unknown)}
ol.why .steptitle{display:block;font-size:.69rem;text-transform:uppercase;letter-spacing:.05em;
color:var(--muted);margin-bottom:.15rem}
ol.why p{margin:.15rem 0;font-size:.87rem}
ol.why ul{margin:.25rem 0;padding-left:1.1rem}
ol.why li ul li{font-size:.83rem;margin:.12rem 0}
ol.why .journal li{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.75rem;
color:var(--muted);margin:.18rem 0}
.conf-block{display:grid;gap:.3rem;margin:.35rem 0 .45rem;max-width:32rem}
.confrow{display:grid;grid-template-columns:8rem 1fr 2.6rem;gap:.5rem;align-items:center}
.conflabel{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.04em}
.confbar{height:.55rem;background:rgba(127,127,127,.16);border-radius:999px;overflow:hidden}
.confbar i{display:block;height:100%;background:var(--accent);border-radius:999px}
.confbar i.high{background:var(--fp)}
.confbar i.medium{background:var(--unknown)}
.confbar i.low{background:var(--confirmed)}
.confbar.model i{background:repeating-linear-gradient(90deg,var(--muted) 0 3px,transparent 3px 6px)}
.confnum{font-variant-numeric:tabular-nums;font-size:.8rem;text-align:right}
.confsaid{font-size:.72rem;color:var(--muted);font-variant-numeric:tabular-nums}
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
        parts.append("<small>" + "<br>".join(_e(call[:240]) for call in calls[:4]) + "</small>")
    return "<br>".join(parts) or "—"


def _trace_body(r: TriageRecord) -> str:
    """What was actually followed, not what might exist."""
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
    """What has to be checked outside the code, and by whom."""
    if not r.sca:
        return "—"
    if r.sca.owner:
        return (f'<span class="ext">инфраструктура</span><br>{_e(r.sca.external)}'
                f'<br><em>владелец: {_e(r.sca.owner)}</em>')
    if r.sca.external:
        return f'<span class="ext">EXTERNAL</span><br>{_e(r.sca.external)}'
    return "—"


_CONDITION_LABEL = {
    "holds": ("условие выполнено", "holds"),
    "absent": ("условия нет в коде", "absent"),
    "external": ("решается вне репозитория", "outside"),
    "infrastructure": ("чужая инфраструктура", "outside"),
}


def _condition_cell(r: TriageRecord) -> str:
    """What the flaw needs besides the vulnerable function, and what the repository answered."""
    sca = r.sca
    if not sca or not sca.condition:
        return "—"
    label, css = _CONDITION_LABEL.get(sca.condition_state, ("проверялось", "outside"))
    parts = [f'<span class="cond {css}">{_e(label)}</span>', _e(sca.condition[:300])]
    if sca.condition_hits:
        found = "<br>".join(_e(hit) for hit in sca.condition_hits[:3])
        parts.append(f'<span class="cond-hits">в коде: {found}</span>')
    return "<br>".join(parts)


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
            f"<td class='cond-cell'>{_condition_cell(r)}</td>"
            f"</tr>"
        )
    return (
        '<h2>Находки</h2><table class="findings"><thead><tr>'
        "<th>Что</th><th>Уязвимо</th><th>Где</th><th>Трасса</th>"
        "<th>Вне кода</th><th>Почему</th><th>Условие уязвимости</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table>"
    )


_DECIDED_BY = {
    "llm": "модель",
    "heuristics": "детерминированная проверка, без модели",
    "post_validation": "пост-валидация",
    "scope": "фильтр области",
    "challenged": "второй проход",
    "error": "ошибка",
}

_OUTCOMES = {
    "actual": "вызов есть и до него доходит пользовательский ввод",
    "not_reached": "граф вызовов до уязвимой функции не доходит",
    "unused": "путь импорта не найден в дереве проекта",
    "test_only_import": "пакет импортируется только тестами",
    "not_shipped": "пакет нужен только для сборки и тестов",
    "no_direct_call": "прямого вызова уязвимой функции нет",
    "condition_absent": "условие эксплуатации не выполнено",
    "wrong_receiver": "вызовы этого имени ведут в другой класс",
    "not_applicable": "уязвимого пути нет в поставляемом пакете",
    "present": "вызов есть, путь от ввода не доказан",
    "call_unconfirmed": "вызов есть, получатель не подтверждён",
    "mentioned": "имя только упоминается, вызова нет",
    "only_in_tests": "вызовы есть только в тестовом коде",
    "infrastructure": "решается на чужой инфраструктуре",
    "undecided": "цепочка не определила",
}


def _confidence_html(v) -> str:
    """Measured confidence beside the number the model gave itself, so the gap is visible."""
    band = v.confidence_band or "—"
    pct = max(0, min(100, round((v.confidence or 0) * 100)))
    rows = [
        '<div class="confrow"><span class="conflabel">по проверкам</span>'
        f'<span class="confbar"><i class="{_e(band)}" style="width:{pct}%"></i></span>'
        f'<span class="confnum">{v.confidence:.2f}</span></div>'
    ]
    said = v.self_reported_confidence
    note = ""
    if said is not None:
        spct = max(0, min(100, round(said * 100)))
        rows.append(
            '<div class="confrow"><span class="conflabel">модель о себе</span>'
            f'<span class="confbar model"><i style="width:{spct}%"></i></span>'
            f'<span class="confnum">{said:.2f}</span></div>'
        )
        if abs(said - v.confidence) >= 0.05:
            where = "выше" if said > v.confidence else "ниже"
            note = (
                f'<p class="note">Модель оценила себя на {abs(said - v.confidence):.2f} {where} '
                "измеренного. Решает измеренное: оно считается из выживших цитат, подтверждения "
                "вторым сканером и трассы резолвера.</p>"
            )
    rationale = f"<p>{_e(v.confidence_rationale)}</p>" if v.confidence_rationale else ""
    return (
        f"<h4>Уверенность: {_e(band)}</h4>"
        f'<div class="conf-block">{"".join(rows)}</div>{note}{rationale}'
    )


def _why_html(r: TriageRecord) -> str:
    """The trail that produced this verdict, in the order it actually happened."""
    v = r.verdict
    steps: list[str] = []

    def step(title: str, body: str, kind: str = "") -> None:
        steps.append(
            f'<li class="step {kind}"><span class="steptitle">{_e(title)}</span>{body}</li>'
        )

    source = f"правило <code>{_e(r.rule_id or '—')}</code>"
    if r.sca and r.sca.package:
        source += f" · пакет <code>{_e(r.sca.package)}@{_e(r.sca.installed_version)}</code>"
        if r.sca.placement:
            source += f" · {_e(r.sca.placement)}"
    step("Сканер сообщил", f"<p>{source}</p>")

    if r.reachability:
        step("Граф вызовов", f"<p>{_e(r.reachability)}</p>")

    sca = r.sca
    if sca:
        bits = []
        if sca.route:
            bits.append(f"маршрут: <b>{_e(_ROUTES.get(sca.route, sca.route))}</b>")
        if sca.symbol:
            bits.append(f"уязвимая функция: <code>{_e(sca.symbol)}</code>")
        body = f"<p>{' · '.join(bits)}</p>" if bits else ""
        if sca.outcome:
            body += f"<p><b>{_e(_OUTCOMES.get(sca.outcome, sca.outcome))}</b></p>"
        if sca.outcome_note:
            body += f'<p class="note">{_e(sca.outcome_note)}</p>'
        if sca.call_sites:
            sites = "".join(f"<li><code>{_e(s)}</code></li>" for s in sca.call_sites[:6])
            body += f"<ul>{sites}</ul>"
        if body:
            step("Цепочка зависимости", body)
        if sca.codeql_calls:
            asked = "".join(f"<li>{_e(c)}</li>" for c in sca.codeql_calls)
            step("Что спросили у анализатора", f'<ul class="journal">{asked}</ul>', "analyzer")
        if sca.audit:
            step("Проверка закрытия", f"<p>{_e(sca.audit)}</p>", "audit")
        if sca.condition and sca.condition_state in ("holds", "absent"):
            label = _CONDITION_LABEL.get(sca.condition_state, ("проверялось", ""))[0]
            body = f"<p><b>{_e(label)}</b></p><p>{_e(sca.condition)}</p>"
            if sca.condition_hits:
                hits = "".join(f"<li><code>{_e(hit)}</code></li>" for hit in sca.condition_hits[:4])
                body += f"<ul>{hits}</ul>"
            step("Условие уязвимости", body, "audit")
        if sca.external:
            step("Решается вне репозитория", f"<p>{_e(sca.external)}</p>")
        if sca.problems:
            issues = "".join(f"<li>{_e(p)}</li>" for p in sca.problems[:5])
            step("Что не удалось проверить", f"<ul>{issues}</ul>", "checks")

    if v.reason:
        by_model = r.decided_by in ("llm", "challenged") or bool(r.overrides)
        step("Модель рассудила" if by_model else "Основание", f"<p>{_e(v.reason)}</p>")

    if r.overrides:
        original = _e(r.original_verdict.verdict.value) if r.original_verdict else "—"
        items = "".join(f"<li>{_e(o)}</li>" for o in r.overrides)
        step(
            "Пост-валидация вмешалась",
            f'<p class="note">модель говорила: <b>{original}</b></p><ul>{items}</ul>',
            "checks",
        )

    if r.challenge_note:
        step("Второй проход возразил", f"<p>{_e(r.challenge_note)}</p>", "checks")

    decided = _DECIDED_BY.get(r.decided_by, r.decided_by)
    step(
        "Итог",
        f'<p><span class="badge {v.verdict.value}">{v.verdict.value.replace("_", " ")}</span>'
        f" — решил: <b>{_e(decided)}</b>"
        + (" · нужен человек" if v.requires_human_review else "")
        + "</p>",
        "final",
    )

    return f'<h4>Как получен вердикт</h4><ol class="why">{"".join(steps)}</ol>'


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
        + (
            f'<span class="confsaid" title="уверенность, которую заявила сама модель">'
            f"ЛЛМ {v.self_reported_confidence:.2f}</span>"
            if v.self_reported_confidence is not None
            else ""
        )
        + '</summary><div class="body">'),
        _why_html(r),
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

    parts.append(_confidence_html(v))
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
    """A banner above the numbers when a scanner did not run."""
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
