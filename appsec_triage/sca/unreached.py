"""A call-graph closure is a claim, and this is the step that checks it."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import Path

from ..prompts import registry
from .exploitable import _grep  # one literal, bounded, read-only search for both steps
from ..llm.tools import TOOL_MODE_NOTE, function_tool, run_tool_loop, supports_tools

log = logging.getLogger(__name__)



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
        "Утверждение получено по списку тестовых путей из prompts/context/: "
        "пакет импортируется только в файлах, которые этот список считает тестовыми. "
        "Мимо него проходит тестовый хелпер или фикстура, которую рабочий код "
        "подключает сам (require из директории tests в обработчике, сидер, "
        "вызванный рабочей командой), и директория с тестовым именем, которая на "
        "самом деле собирается в образ. Ищите импорт этих тестовых файлов из рабочего кода."
    ),
    "only_in_tests": (
        "Утверждение получено так: найдены все места вызова уязвимой функции, и "
        "каждое лежит в файле, который список тестовых путей из "
        "prompts/context/ считает тестовым. Мимо такой проверки "
        "проходит вызов через обёртку — рабочий код зовёт свою функцию, а уже "
        "она зовёт уязвимую, и имени уязвимой в рабочем файле нет; тестовый "
        "хелпер или фабрика, которую подключает рабочий код (сидер, фикстура, "
        "консольная команда); директория с тестовым именем, которая на самом "
        "деле собирается в образ; и вызов, собранный из строки или идущий через "
        "контейнер. Ищите рабочий код, который вызывает эти тестовые файлы или "
        "повторяет тот же вызов под своим именем."
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


def _callback_patterns(name: str) -> list[re.Pattern[str]]:
    """Ways a package hands one of its own methods to the framework by name."""
    quoted = rf"""['"]{re.escape(name)}['"]"""
    return [
        # [$this, 'formatArgs'], [self::class, 'handle'], [Foo::class, 'handle']
        re.compile(rf"\[\s*(?:\$this|self::class|static::class|__CLASS__|[\w\\]+::class)\s*,\s*{quoted}\s*\]"),
        # getSubscribedEvents(): 'event' => 'onLogin' or 'event' => ['onLogin', 10]
        re.compile(rf"=>\s*\[?\s*{quoted}"),
        # 'Some\\Class::onLogin' as a string callable
        re.compile(rf"""['"][\w\\]+::{re.escape(name)}['"]"""),
        # getattr(obj, 'handle') / setattr-style dispatch
        re.compile(rf"getattr\([^)]*{quoted}"),
    ]


def callback_registration(name: str, source: dict[str, str]) -> str:
    """`file:line: code` where the package registers `name` as a callback, or "".

    A listener, a template filter, a message handler is called by the framework, never
    by the application: "no call from the project" says nothing about it.
    """
    if not name or not source:
        return ""
    patterns = _callback_patterns(name)
    for path, text in source.items():
        if name not in text:
            continue
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                start = text.rfind("\n", 0, match.start()) + 1
                end = text.find("\n", match.end())
                line = text[start:end if end >= 0 else len(text)].strip()
                return f"{path}:{text.count(chr(10), 0, match.start()) + 1}: {line[:160]}"
    return ""


@dataclass(slots=True)
class Audit:
    """What checking a call-graph closure established."""

    invisible_path: bool = False
    quote: str = ""
    why: str = ""
    detail: str = ""
    subject: str = "граф вызовов"
    passed: str = "проверено на вызовы, невидимые графу — не найдено"
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


def _patterns_by_tools(client, system: str, header: str, root: Path, limit: int,
                       parallel: int = 1) -> list[str]:
    """Let the model grep itself; return the patterns it searched, in order."""
    searched: list[str] = []

    def grep(arguments: dict) -> str:
        pattern = str(arguments.get("pattern") or "").strip()
        if not pattern or "\n" in pattern or len(pattern) > 200:
            return "Not run: expected one short literal substring."
        if pattern in searched:
            return "Not run: already searched; the result is above."
        searched.append(pattern)
        return _grep(root, [pattern]) or f"--- «{pattern}»: не найдено нигде"

    tool = function_tool(
        "grep", "Literal substring search across this project's source. One pattern per call; "
                "not a regular expression.",
        {"pattern": {"type": "string", "description": "Plain substring."}}, ["pattern"])
    loop = run_tool_loop(client, system + TOOL_MODE_NOTE, header, [tool], {"grep": grep},
                         max_calls=limit, max_turns=limit + 2, parallel=parallel)
    if loop.error and not searched:
        raise RuntimeError(loop.error)
    return searched[:limit]


def audit(reachability, root: Path | str, advisory, symbol, client, parallel: int = 1) -> Audit:
    """Check a "not reached" answer for the paths a static graph cannot resolve."""
    if client is None:
        return Audit(kind="not_reached",
                     detail="модель не подключена — закрытие графом не проверено")
    left = getattr(client, "budget_left_usd", None)
    if left is not None and left <= 0:
        return Audit(kind="not_reached",
                     detail="бюджет прогона исчерпан — закрытие графом не проверено")

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

    try:
        if supports_tools(client):
            patterns = _patterns_by_tools(client, registry.step("unreachable-search"), header, root, 4, parallel)
        else:
            asked = json.loads(client.complete(
                registry.step("unreachable-search"), header, json_schema=_SEARCH_SCHEMA).text)
            patterns = [str(p) for p in (asked.get("patterns") or [])][:4]
    except Exception as exc:  # noqa: BLE001 - a failed audit is not a failed run
        log.debug("audit search failed for %s: %s", advisory.advisory_id, exc)
        return Audit(kind="not_reached", detail=f"закрытие графом не проверено: {exc}")

    if not patterns:
        return Audit(kind="not_reached",
                     detail="закрытие графом не проверено: искать было нечего — "
                            "модель не назвала ни одного паттерна")

    results = _grep(root, patterns)
    material = "\n\n".join([
        header,
        f"=== ВЫ ЗАПРОСИЛИ ПОИСК: {', '.join(patterns)} ===",
        results or "(ни одно совпадение не найдено)",
        ("Отсутствие совпадений — тоже факт: если рефлексии и подгрузки модулей "
        "в коде нет, графу нечего было пропустить."),
    ])

    try:
        answer = json.loads(client.complete(registry.step("unreachable-audit"), material, json_schema=_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - one dead call, not the run
        log.warning("audit of graph closure failed for %s: %s", advisory.advisory_id, exc)
        return Audit(kind="not_reached", detail=f"закрытие графом не проверено: {exc}")

    quote = (answer.get("quote") or "").strip()
    why = (answer.get("why") or "").strip()[:300]
    invisible = bool(answer.get("invisible_path", False))

    if invisible:
        shown = " ".join(material.split())
        if not quote or " ".join(quote.split()) not in shown:
            return Audit(
                kind="not_reached", checked=True,
                detail=(f"переоткрытие отклонено: цитаты «{quote[:60]}» нет "
                        "ни в коде, ни в результатах поиска"))

    return Audit(invisible_path=invisible, quote=quote, why=why,
                 subject="граф вызовов мог не увидеть путь",
                 passed="закрытие графом проверено на невидимые ему вызовы — не опровергнуто",
                 kind="not_reached", checked=True)


_CLOSURE_SCHEMA = {
    "type": "object",
    "required": ["closure_wrong", "quote", "why"],
    "properties": {
        "closure_wrong": {"type": "boolean"},
        "quote": {"type": "string"},
        "why": {"type": "string"},
    },
}


def audit_closure(kind: str, claim: str, root: Path | str, advisory, symbol, client,
                  parallel: int = 1) -> Audit:
    """Check a mechanical closure against the way that kind of check fails."""
    if client is None:
        return Audit(kind=kind, detail="модель не подключена — закрытие не проверено")
    left = getattr(client, "budget_left_usd", None)
    if left is not None and left <= 0:
        return Audit(kind=kind, detail="бюджет прогона исчерпан — закрытие не проверено")
    blind = _BLIND_SPOTS.get(kind)
    if blind is None:
        return Audit(kind=kind, detail=f"для закрытия «{kind}» проверка не описана")

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
        if supports_tools(client):
            patterns = _patterns_by_tools(client, registry.step("closure-search"), header, root, 8, parallel)
        else:
            asked = json.loads(client.complete(
                registry.step("closure-search"), header, json_schema=_SEARCH_SCHEMA).text)
            patterns = [str(p) for p in (asked.get("patterns") or [])][:8]
    except Exception as exc:  # noqa: BLE001 - a failed audit is not a failed run
        log.debug("closure search failed for %s: %s", advisory.advisory_id, exc)
        return Audit(kind=kind, detail=f"закрытие не проверено: {exc}")

    if not patterns:
        return Audit(detail="закрытие не проверено: модель не назвала ни одного паттерна "
                            "для поиска", kind=kind)

    material = "\n\n".join([
        header,
        f"=== ВЫ ЗАПРОСИЛИ ПОИСК: {', '.join(patterns)} ===",
        _grep(root, patterns) or "(ни одно совпадение не найдено)",
        ("Отсутствие совпадений — тоже факт: если ни одной из этих форм в коде "
        "нет, мимо механической проверки ничего не прошло."),
    ])

    try:
        answer = json.loads(client.complete(
            registry.step("closure-audit"), material, json_schema=_CLOSURE_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - one dead call, not the run
        log.warning("closure audit failed for %s: %s", advisory.advisory_id, exc)
        return Audit(kind=kind, detail=f"закрытие не проверено: {exc}")

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
