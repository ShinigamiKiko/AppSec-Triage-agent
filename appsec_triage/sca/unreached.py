"""A call-graph closure is a claim, and this is the step that checks it.

Every other closure in the chain is checked by something. A reached finding is
read at its call sites before it is called exploitable. A symbol from the model
is checked against the fix diff. A receiver type is resolved rather than matched
by name. The one place a verdict was taken on trust was the opposite answer:
govulncheck saying the vulnerable function is not reached closed the finding
immediately, and on a real Go project that is most of the run — seventeen of
nineteen findings on one measured scan.

The graph deserves that trust for what it does: it compiled the program and it
resolved the calls it could name. What it cannot do is see the calls that have
no name at compile time — a method invoked through reflection, an implementation
loaded as a plugin, a file generated after the graph was taken or skipped behind
a build tag. Those are not weaknesses in its analysis, they are outside it, and
no amount of re-running it would surface them.

So this step looks for exactly those constructs and nothing else. It is
deliberately asymmetric to `exploitable`: that one can only lower a finding,
this one can only raise it. A closure it disagrees with is reopened for a
person; a closure it agrees with stands, and it can never close anything
further. And it is held to the same evidence rule as everything else — a
reopening needs a verbatim quote from the source or from the search output it
asked for, because "it might use reflection somewhere" is true of every program
ever written and says nothing about this one.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path

from ..prompts import registry
from .exploitable import _grep  # one literal, bounded, read-only search for both steps

log = logging.getLogger(__name__)

SEARCH_SYSTEM = registry.step("unreachable-search")
SYSTEM = registry.step("unreachable-audit")

CLOSURE_SEARCH_SYSTEM = registry.step("closure-search")
CLOSURE_SYSTEM = registry.step("closure-audit")

# What each mechanical closure cannot see. Kept as data next to the check rather
# than folded into one prompt: the failure modes have nothing in common, and a
# single "think about whether this might be wrong" produces the hedging this
# whole step exists to avoid. The wording goes into the material, so changing
# what a check is known to miss does not mean touching the logic.
_BLIND_SPOTS = {
    "not_shipped": (
        "Утверждение взято из пометки в SBOM: пакет объявлен как нужный только "
        "для сборки или тестов. Пометка бывает верной формально и неверной по "
        "сути: пакет объявлен dev-зависимостью, но импортируется из кода, "
        "который едет в продакшн — хелпер из фикстур, вызванный из обработчика, "
        "сидер, подключённый к рабочей команде. Ищите импорт этого пакета за "
        "пределами тестов."
    ),
    "unused": (
        "Утверждение получено поиском по дереву проекта: путь импорта нигде не "
        "встречается. Поиск читает текст, поэтому мимо него проходит импорт под "
        "псевдонимом, ре-экспорт через свой модуль-обёртку, путь, собранный из "
        "строки в динамическом импорте, файл за build-тегом и сгенерированный "
        "код. Ищите пакет в этих формах, а не его точное имя."
    ),
    "wrong_receiver": (
        "Утверждение получено языковым сервером: он разрешил все места вызова "
        "этого имени, и ни одно не ведёт в уязвимый пакет. Разрешение по типам "
        "надёжно там, где тип выводится; оно молчит там, где вызов идёт через "
        "интерфейс, через значение в контейнере или через функцию, лежащую в "
        "поле. Ищите вызовы того же имени на значениях, тип которых по коду "
        "не определить."
    ),
    "no_input_path": (
        "Утверждение получено запросом CodeQL: от известных ему источников "
        "пользовательских данных путь до места вызова не найден. Источники — это "
        "модель фреймворков, а не свойство кода: мимо неё проходят потребители "
        "очередей и сообщений, аргументы командной строки и переменные окружения, "
        "gRPC- и WebSocket-обработчики, самописный или редкий веб-фреймворк, "
        "данные из файла, базы или кэша, куда их записал пользователь, и значения, "
        "переданные через рефлексию или контейнер. Ищите, откуда аргумент "
        "уязвимого вызова приходит в этих формах."
    ),
    "test_only": (
        "Утверждение получено по списку тестовых путей из prompts/training-context.md: "
        "пакет импортируется только в файлах, которые этот список считает тестовыми. "
        "Мимо него проходит тестовый хелпер или фикстура, которую рабочий код "
        "подключает сам (require из директории tests в обработчике, сидер, "
        "вызванный рабочей командой), и директория с тестовым именем, которая на "
        "самом деле собирается в образ. Ищите импорт этих тестовых файлов из рабочего кода."
    ),
}

_SEARCH_SCHEMA = {
    "type": "object",
    "required": ["patterns", "why"],
    "properties": {
        "patterns": {"type": "array", "items": {"type": "string"}},
        "why": {"type": "string"},
    },
}

_SCHEMA = {
    "type": "object",
    "required": ["invisible_path", "quote", "why"],
    "properties": {
        "invisible_path": {"type": "boolean"},
        "quote": {"type": "string"},
        "why": {"type": "string"},
    },
}


@dataclass(slots=True)
class Audit:
    """What checking a call-graph closure established."""

    invisible_path: bool = False
    quote: str = ""
    why: str = ""
    detail: str = ""
    # Which closure was audited, so the report says what was checked rather than
    # "checked" — a reviewer reading "path the graph cannot see" and one reading
    # "import the search would miss" are looking for different things.
    subject: str = "граф вызовов"
    passed: str = "проверено на вызовы, невидимые графу — не найдено"
    # Which mechanical closure was audited, and whether the audit actually ran.
    # A closure that nothing checks may rest on the check alone; one that is too
    # weak for that needs to tell "audited, nothing found" from "never audited".
    kind: str = ""
    checked: bool = False

    @property
    def reopens(self) -> bool:
        """Only a quoted "yes" reopens; everything else leaves the closure alone."""
        return self.invisible_path and bool(self.quote)

    def render(self) -> str:
        if self.reopens:
            return f"{self.subject}: {self.why} | «{self.quote[:120]}»"
        return self.detail or self.passed


def audit(reachability, root: Path | str, advisory, symbol, client) -> Audit:
    """Check a "not reached" answer for the paths a static graph cannot resolve."""
    if client is None:
        return Audit(detail="модель не подключена — закрытие графом не проверено")
    left = getattr(client, "budget_left_usd", None)
    if left is not None and left <= 0:
        return Audit(detail="бюджет прогона исчерпан — закрытие графом не проверено")

    root = Path(root)
    function = str(getattr(symbol, "function", "") or "")
    package = str(getattr(advisory, "package", "") or "")

    header = "\n\n".join([
        f"Advisory: {advisory.advisory_id} — {advisory.summary}",
        (getattr(advisory, "details", "") or "")[:900],
        f"Уязвимая функция: {function or 'не определена'}",
        f"Пакет: {package or 'не указан'}",
        "Граф вызовов (govulncheck) сообщил: уязвимая функция НЕ достигается.",
        (getattr(reachability, "render", lambda: "")() or ""),
    ])

    # The graph's blind spots are not on any path it drew, so there is nothing to
    # read at a call site here — the whole question is what to look for. The
    # search round is therefore not an optional extra as it is in `exploitable`;
    # without it this step has no material at all and must say so.
    try:
        asked = json.loads(client.complete(
            SEARCH_SYSTEM, header, json_schema=_SEARCH_SCHEMA).text)
        patterns = [str(p) for p in (asked.get("patterns") or [])][:4]
    except Exception as exc:  # noqa: BLE001 - a failed audit is not a failed run
        log.debug("audit search failed for %s: %s", advisory.advisory_id, exc)
        return Audit(detail=f"закрытие графом не проверено: {exc}")

    if not patterns:
        return Audit(detail="проверять на невидимые графу вызовы было нечего")

    results = _grep(root, patterns)
    material = "\n\n".join([
        header,
        f"=== ВЫ ЗАПРОСИЛИ ПОИСК: {', '.join(patterns)} ===",
        results or "(ни одно совпадение не найдено)",
        ("Отсутствие совпадений — тоже факт: если рефлексии и подгрузки модулей "
        "в коде нет, графу нечего было пропустить."),
    ])

    try:
        answer = json.loads(client.complete(SYSTEM, material, json_schema=_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - one dead call, not the run
        log.warning("audit of graph closure failed for %s: %s", advisory.advisory_id, exc)
        return Audit(detail=f"закрытие графом не проверено: {exc}")

    quote = (answer.get("quote") or "").strip()
    why = (answer.get("why") or "").strip()[:300]
    invisible = bool(answer.get("invisible_path", False))

    if invisible:
        # Same rule as every other step that can move a verdict: the quote has to
        # be in what we showed. Here it matters more than anywhere else — this is
        # the one step whose output adds work rather than removing it, and a
        # model that reopens on a hunch would hand back the queue the whole agent
        # exists to shrink.
        shown = " ".join(material.split())
        if not quote or " ".join(quote.split()) not in shown:
            return Audit(
                detail=(f"переоткрытие отклонено: цитаты «{quote[:60]}» нет "
                        "ни в коде, ни в результатах поиска"))

    return Audit(invisible_path=invisible, quote=quote, why=why,
                 subject="граф вызовов мог не увидеть путь")


_CLOSURE_SCHEMA = {
    "type": "object",
    "required": ["closure_wrong", "quote", "why"],
    "properties": {
        "closure_wrong": {"type": "boolean"},
        "quote": {"type": "string"},
        "why": {"type": "string"},
    },
}


def audit_closure(kind: str, claim: str, root: Path | str, advisory, symbol, client) -> Audit:
    """Check a mechanical closure against the way that kind of check fails.

    Same shape and the same rules as the call-graph audit above: one search round
    the model directs, one judgement, and a reopening only on a verbatim quote.
    What differs is the blind spot it is pointed at, and that is data — the check
    that read a flag in the SBOM fails differently from the one that grepped for
    an import path.
    """
    if client is None:
        return Audit(detail="модель не подключена — закрытие не проверено")
    left = getattr(client, "budget_left_usd", None)
    if left is not None and left <= 0:
        return Audit(detail="бюджет прогона исчерпан — закрытие не проверено")
    blind = _BLIND_SPOTS.get(kind)
    if blind is None:
        return Audit(detail=f"для закрытия «{kind}» проверка не описана")

    root = Path(root)
    header = "\n\n".join([
        f"Advisory: {advisory.advisory_id} — {advisory.summary}",
        (getattr(advisory, "details", "") or "")[:900],
        f"Уязвимая функция: {getattr(symbol, 'function', '') or 'не определена'}",
        f"Пакет: {getattr(advisory, 'package', '') or 'не указан'}",
        f"ЗАКРЫТИЕ, КОТОРОЕ ПРОВЕРЯЕТСЯ: {claim}",
        f"ГДЕ ТАКАЯ ПРОВЕРКА ОШИБАЕТСЯ: {blind}",
    ])

    try:
        asked = json.loads(client.complete(
            CLOSURE_SEARCH_SYSTEM, header, json_schema=_SEARCH_SCHEMA).text)
        patterns = [str(p) for p in (asked.get("patterns") or [])][:8]
    except Exception as exc:  # noqa: BLE001 - a failed audit is not a failed run
        log.debug("closure search failed for %s: %s", advisory.advisory_id, exc)
        return Audit(detail=f"закрытие не проверено: {exc}")

    if not patterns:
        return Audit(detail="проверять это закрытие было нечем", kind=kind, checked=True)

    material = "\n\n".join([
        header,
        f"=== ВЫ ЗАПРОСИЛИ ПОИСК: {', '.join(patterns)} ===",
        _grep(root, patterns) or "(ни одно совпадение не найдено)",
        ("Отсутствие совпадений — тоже факт: если ни одной из этих форм в коде "
        "нет, мимо механической проверки ничего не прошло."),
    ])

    try:
        answer = json.loads(client.complete(
            CLOSURE_SYSTEM, material, json_schema=_CLOSURE_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - one dead call, not the run
        log.warning("closure audit failed for %s: %s", advisory.advisory_id, exc)
        return Audit(detail=f"закрытие не проверено: {exc}")

    quote = (answer.get("quote") or "").strip()
    why = (answer.get("why") or "").strip()[:300]
    wrong = bool(answer.get("closure_wrong", False))

    if wrong:
        shown = " ".join(material.split())
        if not quote or " ".join(quote.split()) not in shown:
            return Audit(
                detail=(f"переоткрытие отклонено: цитаты «{quote[:60]}» нет "
                        "ни в коде, ни в результатах поиска"),
                kind=kind, checked=True)

    return Audit(
        invisible_path=wrong, quote=quote, why=why,
        subject=f"закрытие «{kind}» не выдержало проверки",
        passed=f"закрытие «{kind}» проверено на свою слепую зону — не опровергнуто",
        kind=kind, checked=True,
    )
