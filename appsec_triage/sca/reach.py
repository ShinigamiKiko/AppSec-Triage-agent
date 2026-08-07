"""Step 4: does untrusted input actually reach the call?

Presence answers "this code calls the vulnerable function". For a whole class of
flaws — injection, XSS, traversal, deserialisation — that is not yet the
vulnerability: it matters only if an attacker controls what flows in. Answering
that needs two different things, and neither is sufficient alone.

*The language server* knows the call graph. From a call site it walks incoming
calls outwards and asks whether any of them is an entry point — a controller
action, a route handler. That establishes the call is reachable from outside,
and nothing about what flows into it.

*CodeQL* knows dataflow. Its taint queries carry a path from an untrusted source
to a sink. If a path ends at one of our call sites, an attacker's value arrives
there. That establishes the flow, and nothing about whether the query modelled
this particular library correctly.

So a positive verdict requires both: an entry point above the call, and a taint
path into it. Anything less is `UNKNOWN` with the reason recorded — a missing
tool is never allowed to read as "not reachable", because that is the failure
that closes a real vulnerability.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Iterable

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..context.routes import RouteIndex
    from ..lsp.service import LSPService
    from ..models import Finding
    from .presence import Hit

log = logging.getLogger(__name__)

_MAX_HOPS = 4

_INPUT_DRIVEN_CWES = {
    "22", "23", "36", "73",
    "77", "78", "88",
    "79", "80", "83", "87",
    "89", "564", "943",
    "90", "91",
    "94", "95", "96", "98",
    "113", "117", "93",
    "502",
    "611", "776", "827",
    "918",
}


class Reachability(str, Enum):
    REACHABLE = "reachable"
    NO_INPUT_PATH = "no_input_path"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class ReachResult:
    verdict: Reachability
    entrypoint: str = ""
    taint_path: str = ""
    tools_used: list[str] = field(default_factory=list)
    tools_missing: list[str] = field(default_factory=list)
    detail: str = ""

    @property
    def actionable(self) -> bool:
        return self.verdict is Reachability.REACHABLE


def needs_input_path(cwe: str | None) -> bool:
    """Whether this weakness only matters with attacker-controlled input."""
    if not cwe:
        return False
    digits = "".join(ch for ch in str(cwe) if ch.isdigit())
    return digits in _INPUT_DRIVEN_CWES



def _entrypoint_above(
    lsp: "LSPService",
    routes: "RouteIndex | None",
    hit: "Hit",
    root: Path,
) -> tuple[str, str]:
    """Walk incoming calls outwards; return (description, problem)."""
    if routes is not None and routes.usable:
        direct = routes.enclosing(hit.file, hit.line)
        if direct is not None:
            return direct.describe(), ""
    language = lsp.cfg.language_for(hit.file)
    if not language:
        return "", f"нет языкового сервера для {hit.file}"
    client = lsp._client(language)  # noqa: SLF001 - single accessor, kept internal
    if client is None:
        return "", f"языковой сервер {language} не запустился"
    if not client.supports("callHierarchyProvider"):
        if routes is not None and routes.usable:
            found = routes.perimeter(hit.file)
            if found:
                hops, path = found
                return f"маршрут в {hops} переход(ах): {' -> '.join(path[:4])}", ""
            return "", "файл не связан ни с одним маршрутом"
        return "", f"сервер {language} не умеет callHierarchy, таблицы маршрутов нет"

    path = root / hit.file
    seen: set[tuple[str, int]] = set()
    frontier = [(path, hit.line, [f"{hit.file}:{hit.line}"])]
    for _ in range(_MAX_HOPS):
        next_frontier = []
        for current, line, trail in frontier:
            for call in client.incoming_calls(current, line - 1, 0) or []:
                item = call.get("from") or {}
                uri = item.get("uri") or ""
                name = item.get("name") or "?"
                start = ((item.get("selectionRange") or {}).get("start") or {}).get("line", 0)
                key = (uri, start)
                if key in seen:
                    continue
                seen.add(key)
                step = [*trail, name]
                if routes is not None and routes.usable:
                    rel = uri.replace("file://", "")
                    route = routes.enclosing(rel, start + 1)
                    if route is not None:
                        return f"{route.describe()} через {' -> '.join(step[-3:])}", ""
                next_frontier.append((Path(uri.replace("file://", "")), start + 1, step))
        if not next_frontier:
            break
        frontier = next_frontier
    return "", f"за {_MAX_HOPS} переходов точка входа не найдена"



def _taint_into(findings: Iterable["Finding"], hits: Iterable["Hit"]) -> tuple[str, str]:
    """A CodeQL dataflow whose sink lands on one of our call sites."""
    targets = {(h.file.replace("\\", "/"), h.line) for h in hits}
    files = {f for f, _ in targets}
    saw_any = False
    for finding in findings:
        if (finding.scanner or "").lower() != "codeql":
            continue
        saw_any = True
        steps = finding.trace or []
        if not steps:
            continue
        sink = steps[-1]
        sink_file = (sink.file_path or "").replace("\\", "/")
        if sink_file not in files:
            continue
        if any(sink_file == f and abs((sink.line or 0) - line) <= 3 for f, line in targets):
            source = steps[0]
            return (f"{source.file_path}:{source.line} -> {sink_file}:{sink.line} "
                    f"({finding.rule_id or finding.title})"), ""
    if not saw_any:
        return "", "CodeQL не отработал — потоков данных нет"
    return "", "CodeQL отработал, но потока в эту точку не нашёл"


def has_taint_path(findings: Iterable["Finding"], hits: Iterable["Hit"]) -> bool:
    path, _ = _taint_into(findings, hits)
    return bool(path)



TAINT_SYSTEM = """You decide one thing: can an attacker control what reaches
this call?

You are shown the call, the file around it, and the imports. Follow the argument
backwards through the code you can see: a request object, a query parameter, a
message body, a file upload, a header — any of those is attacker-controlled. A
constant, a configuration value, a database column written by the application
itself, or a value derived only from those, is not.

Answer `yes` only when the material shows the path. If the value comes from a
parameter of the enclosing function and you cannot see who calls it, that is
`unknown` — not `no`. `no` means you can see where the value comes from and it
is not attacker-controlled.

`evidence` must be one line copied character-for-character from the material.
An answer whose quote does not appear verbatim is discarded.

Return one JSON object:
{"verdict": "yes|no|unknown", "evidence": "...", "why": "..."}"""

_TAINT_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "evidence", "why"],
    "properties": {
        "verdict": {"type": "string", "enum": ["yes", "no", "unknown"]},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}

_TAINT_CONTEXT_LINES = 25


def _taint_by_model(hits, root: Path, client, symbol: str) -> tuple[str, str, str]:
    """(verdict, quote, why) for whether untrusted input reaches the call.

    The pair of tools answers this only where both can run: CodeQL needs a
    database for the language, the language server needs a call graph, and
    neither exists for PHP. Reading the file is what a reviewer does instead,
    and it is held to the same rule as every other model answer here — quote
    the material or be discarded.
    """
    if client is None:
        return "unknown", "", "модель не подключена"

    for hit in list(hits)[:3]:
        try:
            lines = (root / hit.file).read_text(
                encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        start = max(0, hit.line - 1 - _TAINT_CONTEXT_LINES)
        end = min(len(lines), hit.line + _TAINT_CONTEXT_LINES)
        imports = [ln for ln in lines[:60]
                   if ln.strip().startswith(("use ", "import ", "from ", "require"))]
        material = "\n".join([
            f"Vulnerable symbol: {symbol}",
            f"=== CALL SITE: {hit.file}:{hit.line} ===", hit.text, "",
            *(["=== IMPORTS ===", *imports[:20], ""] if imports else []),
            f"=== {hit.file} lines {start + 1}-{end} ===",
            *(f"{n}: {lines[n - 1]}" for n in range(start + 1, end + 1)),
        ])
        try:
            answer = json.loads(
                client.complete(TAINT_SYSTEM, material, json_schema=_TAINT_SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - one failed call, not the run
            log.debug("taint question failed at %s: %s", hit, exc)
            continue

        quote = (answer.get("evidence") or "").strip()
        if not quote or quote not in material:
            log.debug("discarding ungrounded taint answer at %s", hit)
            continue
        return ((answer.get("verdict") or "unknown").strip().lower(),
                quote, (answer.get("why") or "")[:200])
    return "unknown", "", "модель не дала заземлённого ответа"


def assess(
    hits: list["Hit"],
    root: Path | str,
    *,
    lsp: "LSPService | None",
    routes: "RouteIndex | None",
    codeql_findings: Iterable["Finding"] = (),
    client=None,
) -> ReachResult:
    """Both halves, or `UNKNOWN`. Never "safe" from a missing tool."""
    if not hits:
        return ReachResult(Reachability.UNKNOWN, detail="нет мест вызова для проверки")

    root = Path(root)
    used: list[str] = []
    missing: list[str] = []

    entry, entry_problem = "", "языковой сервер не подключён"
    if lsp is not None:
        for hit in hits[:5]:
            entry, entry_problem = _entrypoint_above(lsp, routes, hit, root)
            if entry:
                break
    if entry:
        used.append("lsp")
    else:
        missing.append(f"lsp ({entry_problem})")

    findings = list(codeql_findings)
    taint, taint_problem = _taint_into(findings, hits)
    if taint:
        used.append("codeql")
    else:
        missing.append(f"codeql ({taint_problem})")

    if not taint:
        verdict, quote, why = _taint_by_model(hits, root, client, str(hits[0]) if hits else "")
        if verdict == "yes":
            taint = f"по чтению кода: {why} | цитата: {quote[:120]}"
            used.append("модель")
            missing = [m for m in missing if not m.startswith("codeql")]
        elif verdict == "no":
            return ReachResult(
                Reachability.NO_INPUT_PATH, entry, "", [*used, "модель"], missing,
                detail=(f"пользовательский ввод сюда не доходит: {why} | "
                        f"цитата: {quote[:120]}"))

    if entry and taint:
        return ReachResult(
            Reachability.REACHABLE, entry, taint, used, missing,
            detail="точка входа найдена языковым сервером, поток данных — CodeQL",
        )

    both_ran = ("не отработал" not in taint_problem
                and "не запустился" not in entry_problem
                and "нет языкового сервера" not in entry_problem
                and "не подключён" not in entry_problem)
    if both_ran and not entry and not taint:
        return ReachResult(
            Reachability.NO_INPUT_PATH, tools_used=["lsp", "codeql"], tools_missing=[],
            detail=f"{entry_problem}; {taint_problem}",
        )

    return ReachResult(
        Reachability.UNKNOWN, entry, taint, used, missing,
        detail="достижимость не установлена: " + "; ".join(missing),
    )
