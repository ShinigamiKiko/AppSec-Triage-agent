"""The model investigates a dependency CVE, and CodeQL answers every question.

Until this step the model named a function and the chain ran the query: the
database was consulted on the model's behalf, never by it. That hid the part
worth having. A model reading an advisory knows which exports lead to the flaw
and can react to what comes back — a wrapper at the call site, a second export
worth checking — and nothing mechanical does that.

So the model gets CodeQL as its instrument. It names package functions or call
sites; the database of this project resolves the calls through the package's
exports and reports whether untrusted input reaches them, with the path. It sees
every answer and may ask again, for a bounded number of rounds.

The trust rules do not move. A call CodeQL found and a path CodeQL traced are
facts of the database, and the chain may use them. A miss on a name the model
chose is not a fact about the code — it may simply have asked the wrong name — so
it closes nothing, and the chain's own deterministic search still runs.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import PurePosixPath

from ..prompts import registry
from . import codeql_reach

log = logging.getLogger(__name__)

SYSTEM = registry.step("codeql-agent")

_ROUNDS = 3
_MAX_FUNCTIONS = 6
_MAX_SITES = 4
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
# A class may be namespaced: PHP names it `Symfony\Component\Yaml\Yaml`, and Psalm
# resolves calls only against the fully qualified name.
_CLASS_NAME = re.compile(r"^\\?[A-Za-z_$][\w$]*(\\[A-Za-z_$][\w$]*)*$")

_SCHEMA = {
    "type": "object",
    "required": ["functions", "sites", "why"],
    "properties": {
        "functions": {
            "type": "array", "maxItems": _MAX_FUNCTIONS, "items": {
                "type": "object", "required": ["name", "vulnerable"],
                "properties": {"name": {"type": "string"}, "class": {"type": "string"},
                               "vulnerable": {"type": "boolean"}},
            },
        },
        "sites": {
            "type": "array", "maxItems": _MAX_SITES, "items": {
                "type": "object", "required": ["file", "line"],
                "properties": {"file": {"type": "string"}, "line": {"type": "integer"}},
            },
        },
        "why": {"type": "string"},
    },
}


@dataclass(slots=True)
class Investigation:
    """What the model's own CodeQL questions established."""

    label: str = ""
    klass: str = ""
    found: object = None
    """`PresenceResult` for the call CodeQL resolved, or None when none was found."""
    answer: object = None
    """The `ApiAnswer` that found it, so its dataflow answer is used as well."""
    reached: codeql_reach.Reached | None = None
    requests: int = 0
    detail: str = ""


def _material(advisory, symbol, package: str, engine: str = "CodeQL") -> str:
    lines = [
        f"Advisory: {advisory.advisory_id} — {advisory.summary}",
        (advisory.details or "")[:1500],
        f"Vulnerable package: {package} ({advisory.ecosystem or 'unknown ecosystem'})",
        f"Analysis engine for this project: {engine}.",
    ]
    if engine == "Psalm":
        lines.append("This is a PHP project: put the fully qualified class name in `class` "
                     "(for example Symfony\\Component\\Yaml\\Yaml), the method name in `name`, and leave "
                     "`class` empty only for a plain function. Position questions (`sites`) are not available.")
    if symbol is not None and str(symbol) and getattr(symbol, "function", ""):
        lines.append(f"Vulnerable function named by the fix analysis: {symbol}")
    if symbol is not None and getattr(symbol, "what_changed", ""):
        lines.append(f"What the fix changed: {symbol.what_changed}")
    return "\n\n".join(line for line in lines if line)


_SENTENCE = re.compile(r"[^.!?\n]+[.!?]?")
_UNAFFECTED = re.compile(
    r"\b(?:un-?affected|not\s+(?:be\s+)?(?:affected|vulnerable|impacted)|is\s+safe|are\s+safe|safe\s+alternative)\b",
    re.IGNORECASE)
# Clauses are judged one at a time: "`load()` is vulnerable while `safeLoad()` is
# unaffected" speaks about two functions.
_CLAUSE = re.compile(r"\s*(?:[;,]|\bwhile\b|\bwhereas\b|\bbut\b|\bhowever\b)\s*", re.IGNORECASE)
# "Applications that do not pass input to `load()` are not affected" is about the
# callers of the vulnerable function, not about the function.
_ABOUT_CALLERS = re.compile(
    r"\b(?:do(?:es)?\s+not|don't|doesn't|never|without|unless|only\s+if|only\s+when)\b", re.IGNORECASE)


def declared_unaffected(advisory, name: str) -> str:
    """The advisory's own sentence saying this function is not affected, or "".

    The model is told to mark a safe alternative as context and still marked
    `safeLoad` vulnerable on a seeded project, whose advisory reads "The
    `safeLoad()` function is unaffected." That sentence is a fact the text
    states, so it overrides the model's mark instead of relying on the prompt.
    """
    if not name:
        return ""
    text = f"{getattr(advisory, 'summary', '') or ''}\n{getattr(advisory, 'details', '') or ''}"
    mention = re.compile(rf"(?<![\w$]){re.escape(name)}(?![\w$])")
    for sentence in _SENTENCE.findall(text):
        for clause in _CLAUSE.split(sentence):
            named = mention.search(clause)
            phrase = _UNAFFECTED.search(clause)
            # The function must be what the clause calls unaffected: named before
            # the phrase, and not as the target of a condition on its callers.
            if named and phrase and named.start() < phrase.start() and not _ABOUT_CALLERS.search(clause):
                return " ".join(sentence.split())
    return ""


def _functions(reply: dict, asked: set[str]) -> list[tuple[str, str, bool]]:
    """(name, class, vulnerable) for each new, well-formed function the model asked about.

    `vulnerable` is only ever True when the model said so explicitly: a function
    asked for context — the safe alternative the advisory recommends — must not
    turn its own call or path into evidence of the flaw.
    """
    functions = []
    for item in (reply.get("functions") or [])[:_MAX_FUNCTIONS]:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name") or "").split("::")[-1].split(".")[-1].strip().rstrip("()")
        klass = str(item.get("class") or "").strip()
        if not _CLASS_NAME.match(klass or "a"):
            continue
        # `\Symfony\...\Yaml` and `Symfony\...\Yaml` are one class; the engines answer under the second.
        klass = klass.lstrip("\\")
        label = f"{klass}::{name}" if klass else name
        if name and _IDENTIFIER.match(name) and label not in asked:
            asked.add(label)
            functions.append((name, klass, item.get("vulnerable") is True))
    return functions


def _sites(reply: dict, asked: set[tuple[str, int]]) -> list[tuple[str, int]]:
    sites = []
    for item in (reply.get("sites") or [])[:_MAX_SITES]:
        if not isinstance(item, dict):
            continue
        file = str(item.get("file") or "").replace("\\", "/").strip()
        line = item.get("line")
        path = PurePosixPath(file)
        if (not file or path.is_absolute() or ".." in path.parts
                or not isinstance(line, int) or line < 1 or (file, line) in asked):
            continue
        asked.add((file, line))
        sites.append((file, line))
    return sites


def investigate(
    client, advisory, symbol, package: str, *,
    ask_functions: Callable[[list[tuple[str, str]]], object],
    ask_sites: Callable[[list[tuple[str, int]]], object],
    rounds: int = _ROUNDS,
    engine: str = "CodeQL",
) -> Investigation:
    """Let the model question the analysis engine about this CVE; return what it established."""
    result = Investigation()
    if client is None:
        result.detail = f"модель не подключена — {engine} моделью не опрашивался"
        return result

    material = _material(advisory, symbol, package, engine)
    asked_functions: set[str] = set()
    asked_sites: set[tuple[str, int]] = set()
    for round_no in range(1, rounds + 1):
        left = getattr(client, "budget_left_usd", None)
        if left is not None and left <= 0:
            result.detail = "бюджет прогона исчерпан"
            break
        try:
            reply = json.loads(client.complete(SYSTEM, material, json_schema=_SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - the chain's own search still runs
            log.warning("codeql investigation round %d failed for %s: %s", round_no, advisory.advisory_id, exc)
            result.detail = f"раунд {round_no} не выполнен: {exc}"
            break

        functions = _functions(reply, asked_functions)
        pairs = [(name, klass) for name, klass, _ in functions]
        vulnerable: set[str] = set()
        overruled: list[str] = []
        for name, klass, flag in functions:
            label = f"{klass}::{name}" if klass else name
            if not flag:
                continue
            if sentence := declared_unaffected(advisory, name):
                overruled.append(f"- {label} is marked context, not vulnerable: the advisory says «{sentence[:200]}»")
                log.info("codeql investigation for %s: %s overruled by advisory text", advisory.advisory_id, label)
                continue
            vulnerable.add(label)
        sites = _sites(reply, asked_sites)
        if not pairs and not sites:
            break

        additions = [f"=== {engine.upper()} ANSWERS, ROUND {round_no} ===", *overruled]
        if pairs:
            result.requests += 1
            answer = ask_functions(pairs)
            if answer is None:
                additions.append(f"{engine} cannot be asked about these functions for this project.")
            elif not answer.usable:
                additions.append(f"{engine} did not run: {answer.problem}")
            else:
                for name, klass in pairs:
                    label = f"{klass}::{name}" if klass else name
                    hits = answer.calls.get(label) or []
                    reached = answer.reached.get(label)
                    listed = "; ".join(f"{hit} {hit.text[:100]}" for hit in hits[:5])
                    role = "" if label in vulnerable else " (context — not marked vulnerable, not evidence)"
                    additions.append(f"- {label}{role}: {len(hits)} call(s)" + (f": {listed}" if listed else ""))
                    if reached is not None:
                        additions.append(f"  {reached.render()}")
                    elif hits:
                        additions.append("  no path from untrusted input to these calls")
                    if (hits and label in vulnerable
                            and (result.found is None or (reached is not None and result.reached is None))):
                        result.label, result.klass, result.answer = label, klass, answer
                        result.found = answer.presence(label)
                        if reached is not None:
                            result.reached = reached
        if sites:
            result.requests += 1
            outcome = ask_sites(sites)
            where = ", ".join(f"{file}:{line}" for file, line in sites)
            if isinstance(outcome, codeql_reach.Reached):
                additions.append(outcome.render())
                # A position proves the flaw only when it is a call of a vulnerable
                # function already found; any other call it reaches is context.
                at_vulnerable_call = result.found is not None and any(
                    (hit.file, hit.line) == (outcome.file, outcome.line) for hit in result.found.hits)
                if at_vulnerable_call:
                    result.reached = result.reached or outcome
            elif outcome is False:
                additions.append(f"CodeQL: no path from untrusted input to {where}.")
            elif isinstance(outcome, str):
                additions.append(outcome)
            else:
                additions.append(f"CodeQL could not evaluate {where} (no database, or not a call in it).")
        material = f"{material}\n\n" + "\n".join(additions)

    log.info("codeql investigation for %s: %d request(s), found=%s, reached=%s", advisory.advisory_id,
             result.requests, result.label or "-", bool(result.reached))
    return result
