"""Which class an unbound call actually lands on, asked of the language server.

`$this->decorated->onAuthenticationFailure(...)` is a real call whose receiver is
declared as an interface, and `$container->getParameter('roles')` is a real call
to something entirely unrelated to the advisory. Textually the two are
identical, and no list of common method names separates them — the list is never
complete, and it was measured failing on exactly this pair.

A language server answers it directly: ask where the method at this position is
defined. If the definition is the advisory's class, the call is the vulnerable
one. If it is a different class, the name collided and the finding drops.

The honest limit, stated rather than hidden: without an installed dependency
tree there is nothing for the server to index, so definitions inside libraries
cannot be found. That leaves the question open — which is what it was — and the
reason recorded says which of the two situations it is.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from ..prompts import registry
from . import container as container_mod
from .presence import Hit, PresenceResult, SymbolPresence

if TYPE_CHECKING:  # pragma: no cover - typing only
    from ..lsp.service import LSPService

log = logging.getLogger(__name__)

_MAX_HITS = 8


@dataclass(slots=True)
class Resolution:
    presence: PresenceResult
    asked: int = 0
    answered: int = 0
    detail: str = ""
    settled: bool = False
    """This answer decides the question; nothing further should be consulted."""
    disproved: bool = False
    """The server resolved every call site, and none lands in the flawed package.

    A positive fact, not an absence: the receiver's type is known and it is a
    different type. `json.NewDecoder(...).Decode(x)` matches an advisory about
    `pgx.Bind.Decode` by name alone, and only a resolver can say the receiver is
    `encoding/json`'s decoder — which settles the finding rather than doubting it.
    """


def _definition_class(location: dict, path_map: dict[str, str] | None = None) -> tuple[str, str]:
    """(class name, file path) implied by a definition location."""
    uri = location.get("uri") or location.get("targetUri") or ""
    if not uri:
        return "", ""
    path = uri.replace("file://", "")
    for prefix, replacement in (path_map or {}).items():
        if path.startswith(prefix):
            path = replacement + path[len(prefix):]
            break
    return Path(path).stem, path


_RECEIVER = re.compile(
    r"(\$this->\w+)\s*->\s*(\w+)\s*\("
    r"|((?:this|self)\.\w+)\s*\.\s*(\w+)\s*\("
    r"|(\b[a-z]\w*\.\w+)\s*\.\s*([A-Z]\w*)\s*\("
)


def _receiver_expression(text: str) -> str:
    """The `x.y` part of a call on a field, whichever language wrote it."""
    match = _RECEIVER.search(text)
    if not match:
        return ""
    return next((group for group in match.groups()[::2] if group), "")


def _by_configuration(
    result: PresenceResult, root: Path, klass: str, wiring
) -> Resolution | None:
    """The container's own answer, where the application states it.

    Tried before the language server because it is exact where it applies: the
    configuration names the class, it does not infer it. The server was measured
    answering two of five positions and one of those wrongly.
    """
    if wiring is None or not wiring.usable:
        return None

    for hit in result.hits[:_MAX_HITS]:
        receiver = _receiver_expression(hit.text)
        if not receiver:
            continue
        try:
            text = (root / hit.file).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        found = container_mod.receiver_class(wiring, text, receiver)
        if not found.klass:
            if found.detail:
                log.debug("container did not resolve %s: %s", receiver, found.detail)
            continue
        if found.klass.lower() == klass.lower():
            return Resolution(
                PresenceResult(SymbolPresence.CALLED, result.symbol, [hit],
                               result.files_scanned, result.truncated,
                               detail=(f"конфигурация контейнера называет класс: "
                                       f"{found.detail} ({found.via})")),
                detail="разрешено по конфигурации контейнера")
    return None


SYSTEM = registry.step("receiver")

_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "evidence", "why"],
    "properties": {
        "verdict": {"type": "string", "enum": ["yes", "no", "unknown"]},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}

_IMPORT = re.compile(r"^\s*(?:use|import|from|require)\b.*$", re.MULTILINE)
_CONTEXT_LINES = 12


def _context(root: Path, hit: Hit, klass: str, package: str, wiring) -> str:
    """Everything a person would look at to answer, and nothing else."""
    parts = [f"Package: {package}", f"Class in question: {klass}", "",
             f"=== CALL SITE: {hit.file}:{hit.line} ===", hit.text, ""]
    try:
        lines = (root / hit.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []

    if lines:
        imports = _IMPORT.findall("\n".join(lines[:80]))
        if imports:
            parts += ["=== IMPORTS IN THIS FILE ===", *imports[:25], ""]
        start = max(0, hit.line - 1 - _CONTEXT_LINES)
        end = min(len(lines), hit.line + _CONTEXT_LINES)
        parts += [f"=== {hit.file} lines {start + 1}-{end} ===",
                  *(f"{n}: {lines[n - 1]}" for n in range(start + 1, end + 1)), ""]
        declarations = [
            ln for ln in lines
            if re.search(r"(private|protected|public|readonly)\s+[\w\\|?<>]+\s+\$?\w+", ln)
            or re.search(r"\b\w+\s*:\s*[A-Z][\w<>.]*\s*[;=,)]", ln)
            or re.search(r"^\s*\w+\s+\*?[A-Z][\w.]*\s*(?:`|$)", ln)
            or "__construct" in ln or "constructor(" in ln or "def __init__" in ln]
        if declarations:
            parts += ["=== DECLARATIONS IN THIS FILE ===", *declarations[:15], ""]

    if wiring is not None and getattr(wiring, "usable", False):
        owner = container_mod.class_of_file("\n".join(lines)) if lines else ""
        relevant = []
        for key, value in {**wiring.classes, **wiring.aliases}.items():
            if klass.lower() in f"{key}{value}".lower() or (owner and owner in key):
                relevant.append(f"{key}: {value}")
        for key, target in wiring.decorates.items():
            if owner and owner in key:
                relevant.append(f"{key}: decorates {target}")
        if relevant:
            parts += ["=== SERVICE CONFIGURATION ===", *relevant[:15], ""]
    return "\n".join(parts)


def _by_model(
    result: PresenceResult, root: Path, klass: str, package: str, wiring, client
) -> Resolution | None:
    """Ask the model to read the call the way a reviewer would.

    A type resolver answers syntactically and gives up on containers, factories
    and magic accessors — measured at two answers out of five positions, one of
    them wrong. Reading the file settles most of those, so the model is asked,
    and every answer must quote the material verbatim or it is discarded.
    """
    if client is None:
        return None

    for hit in result.hits[:3]:
        if not _receiver_expression(hit.text):
            continue
        material = _context(root, hit, klass, package, wiring)
        try:
            raw = client.complete(SYSTEM, material, json_schema=_SCHEMA).text
            answer = json.loads(raw)
        except Exception as exc:  # noqa: BLE001 - one failed call, not the run
            log.debug("receiver question failed at %s: %s", hit, exc)
            continue

        quote = (answer.get("evidence") or "").strip()
        verdict = (answer.get("verdict") or "unknown").strip().lower()
        if not quote or quote not in material:
            log.debug("discarding ungrounded receiver answer at %s", hit)
            continue

        why = (answer.get("why") or "")[:200]
        if verdict == "yes":
            return Resolution(
                PresenceResult(SymbolPresence.CALLED, result.symbol, [hit],
                               result.files_scanned, result.truncated,
                               detail=f"модель разобрала вызов: {why} | цитата: {quote[:120]}"),
                detail="разрешено моделью по коду и конфигурации")
        if verdict == "no":
            return Resolution(
                PresenceResult(SymbolPresence.ABSENT, result.symbol, [],
                               result.files_scanned, result.truncated,
                               detail=(f"вызов идёт не в {klass}: {why} | "
                                       f"цитата: {quote[:120]}")),
                detail="модель показала другой класс")
    return None


def resolve(
    result: PresenceResult,
    lsp: LSPService | None,
    root: Path | str,
    klass: str,
    package: str = "",
    wiring=None,
    client=None,
    package_dir: Path | None = None,
) -> Resolution:
    """Turn `CALL_UNCONFIRMED` into a decision where something can settle it."""
    if result.presence is not SymbolPresence.CALL_UNCONFIRMED:
        return Resolution(result)
    if not klass:
        return Resolution(result, detail="advisory не называет класс — сверять не с чем")

    settled = _by_configuration(result, Path(root), klass, wiring)
    if settled is not None:
        return settled

    # The language server before the model, not after. Both answer the same
    # question — which class the receiver has — but the server reads the code and
    # the model guesses, and a guess that runs first makes the answer change from
    # run to run: measured on a Go project, the same finding came back `actual`
    # in one run and `no_direct_call` in the next because the model, not gopls,
    # was deciding. Deterministic evidence leads; the model only fills the gap
    # the server leaves.
    answer = _by_lsp(result, lsp, Path(root), klass, package, package_dir)
    if answer.settled:
        return answer

    # The server could not say; `answer` carries why, and stays the fallback so
    # that reason reaches the report when the model cannot say either.
    return _by_model(result, Path(root), klass, package, wiring, client) or answer


def _inside(where: str, directory: Path | None) -> bool:
    """Is this definition inside the flawed package's own installed tree?"""
    if directory is None or not where:
        return False
    try:
        Path(where).resolve().relative_to(Path(directory).resolve())
    except (ValueError, OSError):
        return False
    return True


def _by_lsp(
    result: PresenceResult, lsp: LSPService | None, root: Path, klass: str,
    package: str, package_dir: Path | None = None,
) -> Resolution:
    """Resolve the receiver by asking the language server for the definition.

    Where the definition *lands* is the test, not what the file is called. A
    method name is shared across libraries — `Decode`, `Append`, `Receive` — so
    the only question that separates them is whether the resolved definition sits
    inside the flawed package's own tree. Measured: five call sites matching an
    advisory about `pgx.Bind.Decode` all resolved into `encoding/json`, which the
    file-stem comparison could only call "another class", and which the location
    test calls what it is — a different library.

    Always returns a `Resolution`; `settled` says whether it decides the question
    or is merely the record of why the server could not answer.
    """
    if lsp is None:
        return Resolution(result, detail="языковой сервер не подключён")

    matched: list[Hit] = []
    elsewhere: list[str] = []
    considered = 0
    resolved_away = 0
    asked = answered = 0

    for hit in result.hits[:_MAX_HITS]:
        language = lsp.cfg.language_for(hit.file)
        if not language:
            continue
        considered += 1
        client = lsp._client(language)
        if client is None:
            return Resolution(result, asked,
                              detail=f"сервер {language} не запустился")

        path = root / hit.file
        try:
            client.open_document(path, language)
            # `definition` takes a 1-indexed line and converts it itself, the
            # same as every other caller. Subtracting here as well asked the
            # server about the line *above* the call, where the column usually
            # lands on nothing — measured as "asked 8 times, zero definitions",
            # which reads as a server that cannot resolve rather than a question
            # about the wrong place.
            locations = client.definition(path, hit.line, max(hit.column, 0)) or []
        except Exception as exc:  # noqa: BLE001 - one dead request, not the run
            log.debug("definition failed at %s:%s: %s", hit.file, hit.line, exc)
            continue

        asked += 1
        if not locations:
            continue
        answered += 1
        path_map = lsp._path_map_for(language)
        landed_away = False
        for location in locations:
            name, where = _definition_class(location, path_map)
            if not name:
                continue
            if Path(where).resolve() == (root / hit.file).resolve():
                # The server handed back the call site itself. Measured on
                # symfony/demo: that is the shape of "could not resolve", not
                # evidence about the type, so it must not count toward a closure.
                continue
            # A definition inside the flawed package proves the receiver's type;
            # the class-name comparison stays as a fallback for the ecosystems
            # where the file is named after the class it declares.
            if _inside(where, package_dir) or name.lower() == klass.lower():
                matched.append(hit)
                landed_away = False
                break
            landed_away = True
            elsewhere.append(f"{hit} -> {name} ({Path(where).name})")
        if landed_away:
            resolved_away += 1

    if matched:
        return Resolution(
            PresenceResult(SymbolPresence.CALLED, result.symbol, matched,
                           result.files_scanned, result.truncated,
                           detail=f"языковой сервер подтвердил класс {klass} в месте вызова"),
            asked, answered, settled=True,
            detail=f"разрешено определений: {answered} из {asked}")

    # Disproved only when nothing was left unanswered: every call site the server
    # was asked about resolved, and every one landed outside the flawed package.
    # A single unresolved site keeps the finding open — a partial answer cannot
    # rule out that the one site we could not read is the real call.
    complete = considered and asked == considered and answered == considered
    if elsewhere and complete and resolved_away == considered and package_dir is not None:
        return Resolution(
            PresenceResult(SymbolPresence.ABSENT, result.symbol, [],
                           result.files_scanned, result.truncated,
                           detail=(f"языковой сервер разрешил все {considered} совпадени(й): "
                                   f"получатель принадлежит другому типу, не {package} "
                                   f"({'; '.join(elsewhere[:2])})")),
            asked, answered, settled=True, disproved=True,
            detail=f"все {considered} мест(а) разрешены вне {package}")

    if elsewhere:
        return Resolution(
            PresenceResult(SymbolPresence.CALL_UNCONFIRMED, result.symbol,
                           result.hits, result.files_scanned, result.truncated,
                           detail=(f"{result.detail}; языковой сервер привёл в другие классы "
                                   f"({'; '.join(elsewhere[:2])}) — это довод против, "
                                   f"но не доказательство")),
            asked, answered, settled=True,
            detail="определения ведут в другие классы")

    if not asked:
        reason = "языковой сервер не отвечал по этим файлам"
    elif not answered:
        reason = (f"сервер спрошен {asked} раз(а) и не вернул ни одного определения "
                  f"для {package or 'этого пакета'}")
    else:
        reason = (f"из {asked} запрос(ов) сервер ответил {answered}, "
                  f"но ни одно определение не указало на {klass}")
    return Resolution(result, asked, answered, detail=reason)
