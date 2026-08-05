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


SYSTEM = """You decide one thing: does this call land on the class named below?

You are shown a call site, the file it lives in, and any service configuration
that mentions the class or the property. Real applications hide the concrete
class behind interfaces, containers, factories and magic accessors — that is
exactly why a type resolver could not answer, and why you are being asked.

Answer `yes` only when something in the material shows it. A property declared
as an interface that the configuration binds to this class is a yes. A property
declared as an unrelated class is a no. Anything else is `unknown`, and unknown
is a perfectly good answer — a wrong `yes` invents a vulnerability, a wrong `no`
hides one.

`evidence` must be one line copied character-for-character from the material
above. Not paraphrased, not reconstructed. An answer whose quote does not appear
verbatim is discarded, so quote something real or answer `unknown`.

Return one JSON object:
{"verdict": "yes|no|unknown", "evidence": "...", "why": "..."}"""

_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "evidence", "why"],
    "properties": {
        "verdict": {"type": "string", "enum": ["yes", "no", "unknown"]},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}

_IMPORT = re.compile(r"^\s*(?:use|import|from|require)\b.*$", re.M)
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
    lsp: "LSPService | None",
    root: Path | str,
    klass: str,
    package: str = "",
    wiring=None,
    client=None,
) -> Resolution:
    """Turn `CALL_UNCONFIRMED` into a decision where something can settle it."""
    if result.presence is not SymbolPresence.CALL_UNCONFIRMED:
        return Resolution(result)
    if not klass:
        return Resolution(result, detail="advisory не называет класс — сверять не с чем")

    settled = _by_configuration(result, Path(root), klass, wiring)
    if settled is not None:
        return settled

    settled = _by_model(result, Path(root), klass, package, wiring, client)
    if settled is not None:
        return settled

    if lsp is None:
        return Resolution(result, detail="языковой сервер не подключён")

    root = Path(root)
    matched: list[Hit] = []
    elsewhere: list[str] = []
    asked = answered = 0

    for hit in result.hits[:_MAX_HITS]:
        language = lsp.cfg.language_for(hit.file)
        if not language:
            continue
        client = lsp._client(language)  # noqa: SLF001 - the single accessor
        if client is None:
            return Resolution(result, asked,
                              detail=f"сервер {language} не запустился")

        path = root / hit.file
        try:
            client.open_document(path, language)
            locations = client.definition(path, hit.line - 1, max(hit.column, 0)) or []
        except Exception as exc:  # noqa: BLE001 - one dead request, not the run
            log.debug("definition failed at %s:%s: %s", hit.file, hit.line, exc)
            continue

        asked += 1
        if not locations:
            continue
        answered += 1
        path_map = lsp._path_map_for(language)  # noqa: SLF001
        for location in locations:
            name, where = _definition_class(location, path_map)
            if not name:
                continue
            if Path(where).resolve() == (root / hit.file).resolve():
                continue
            if name.lower() == klass.lower():
                matched.append(hit)
                break
            elsewhere.append(f"{hit} -> {name} ({Path(where).name})")

    if matched:
        return Resolution(
            PresenceResult(SymbolPresence.CALLED, result.symbol, matched,
                           result.files_scanned, result.truncated,
                           detail=f"языковой сервер подтвердил класс {klass} в месте вызова"),
            asked, answered, detail=f"разрешено определений: {answered} из {asked}")

    if elsewhere:
        return Resolution(
            PresenceResult(SymbolPresence.CALL_UNCONFIRMED, result.symbol,
                           result.hits, result.files_scanned, result.truncated,
                           detail=(f"{result.detail}; языковой сервер привёл в другие классы "
                                   f"({'; '.join(elsewhere[:2])}) — это довод против, "
                                   f"но не доказательство")),
            asked, answered, detail="определения ведут в другие классы")

    if not asked:
        reason = "языковой сервер не отвечал по этим файлам"
    elif not answered:
        reason = (f"сервер спрошен {asked} раз(а) и не вернул ни одного определения "
                  f"для {package or 'этого пакета'}")
    else:
        reason = (f"из {asked} запрос(ов) сервер ответил {answered}, "
                  f"но ни одно определение не указало на {klass}")
    return Resolution(result, asked, answered, detail=reason)
