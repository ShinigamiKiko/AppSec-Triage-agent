"""Turning the three checks into one statement about a dependency CVE.

The rule the pipeline needs is short: the vulnerability is *actual* when the
vulnerable symbol is called here, and — for weaknesses that require
attacker-controlled input — when that input demonstrably reaches the call.

Everything else is a degree of not-knowing, and the distinctions between those
degrees are what makes the report usable. "The package does not ship this code"
is a closure. "Nothing here calls it" is not: most vulnerable functions are
library internals reached through public API, so absence of a direct call means
the question moved, not that it was answered.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .presence import PresenceResult, SymbolPresence
from .reach import ReachResult, Reachability
from .resolve import VulnerableSymbol


class CVEVerdict(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    NOT_SHIPPED = "not_shipped"
    UNUSED = "unused"
    CONDITION_ABSENT = "condition_absent"
    ACTUAL = "actual"
    PRESENT_UNPROVEN = "present"
    ONLY_IN_TESTS = "only_in_tests"
    CALL_UNCONFIRMED = "call_unconfirmed"
    MENTIONED_ONLY = "mentioned"
    NOT_APPLICABLE = "not_applicable"
    NO_DIRECT_CALL = "no_direct_call"
    NO_VULNERABLE_SYMBOL = "no_vulnerable_symbol"
    NO_DEPENDENCY_PATH = "no_dependency_path"
    UNDECIDED = "undecided"


@dataclass(slots=True)
class CVEDecision:
    verdict: CVEVerdict
    headline: str
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def closes(self) -> bool:
        """Outcomes that rest on a fact, not on failing to find something.

        Each of these is a positive statement: the package does not ship to
        production, the repository never names it, the condition the flaw needs
        is not met, the vulnerable path is not in the artifact. None of them is
        "we looked and saw nothing".
        """
        return self.verdict in (CVEVerdict.NOT_APPLICABLE, CVEVerdict.NOT_SHIPPED,
                                CVEVerdict.UNUSED, CVEVerdict.CONDITION_ABSENT,
                                 CVEVerdict.INFRASTRUCTURE,
                                 CVEVerdict.NO_VULNERABLE_SYMBOL,
                                 CVEVerdict.NO_DEPENDENCY_PATH)

    @property
    def reassigned(self) -> bool:
        """Closed for this service, and owned by somebody else.

        For the application's queue this is a false positive — the service
        cannot change an LDAP server's settings or TLS on a load balancer, and
        the finding does not belong to it. The flag stays so a report can route
        it rather than merely dismiss it.
        """
        return self.verdict is CVEVerdict.INFRASTRUCTURE


def decide(
    symbol: VulnerableSymbol | None,
    presence: PresenceResult | None,
    reach: ReachResult | None,
    *,
    cwe: str | None = None,
    input_driven: bool | None = None,
    dev_only: bool | None = None,
    used: bool | None = None,
    used_detail: str = "",
    direct: bool | None = None,
    condition=None,
) -> CVEDecision:
    """Combine the steps. Facts that settle it are checked before anything else."""
    if dev_only:
        return CVEDecision(
            CVEVerdict.NOT_SHIPPED,
            "не поставляется в продакшн: пакет только для сборки и тестов",
            ["в SBOM помечен как build-only — в рантайме его нет"],
        )

    if used is False:
        if direct:
            return CVEDecision(
                CVEVerdict.UNUSED,
                "библиотека не используется в коде проекта",
                [used_detail or "имя пакета не встречается ни в одном файле",
                 "пакет объявлен прямой зависимостью, но в коде не упоминается",
                 "остаётся путь через контейнер или автозагрузку — но следов нет"],
            )
        return CVEDecision(
            CVEVerdict.NO_DIRECT_CALL,
            "транзитивный пакет: в вашем коде не упоминается, и это ожидаемо",
            [used_detail or "имя пакета не встречается ни в одном файле",
             "его вызывает родитель, а не вы — отсутствие имени здесь ничего не решает"],
        )

    if condition is not None and getattr(condition, "state", None) is not None:
        from .conditions import ConditionState

        if condition.state is ConditionState.ABSENT:
            return CVEDecision(
                CVEVerdict.CONDITION_ABSENT,
                f"условие эксплуатации не выполняется: {condition.statement}",
                [condition.render()],
            )
        if condition.state is ConditionState.INFRASTRUCTURE:
            return CVEDecision(
                CVEVerdict.INFRASTRUCTURE,
                f"к сервису не относится — инфраструктура: {condition.statement}",
                [condition.render(),
                 "для этого сервиса ложное срабатывание; чинится владельцем системы"],
            )

    if symbol is None:
        return CVEDecision(
            CVEVerdict.UNDECIDED,
            "уязвимая функция для этой CVE не определена",
            ["в справочнике нет записи по этому advisory"],
        )
    if symbol.not_distributed or (presence and presence.presence is SymbolPresence.NOT_DISTRIBUTED):
        return CVEDecision(
            CVEVerdict.NOT_APPLICABLE,
            f"неприменимо: {symbol.file or symbol} не входит в устанавливаемый пакет",
            [symbol.note or "путь отсутствует в дистрибутиве пакета"],
        )
    if not symbol.usable or presence is None or presence.presence is SymbolPresence.NOT_SEARCHABLE:
        return CVEDecision(
            CVEVerdict.UNDECIDED,
            f"нечего искать по {symbol.advisory_id}",
            [presence.detail if presence else "поиск не выполнялся"],
        )

    reasons = [f"уязвимый символ: {symbol} — {symbol.strength}"]

    if presence.presence is SymbolPresence.ABSENT:
        return CVEDecision(
            CVEVerdict.NO_DIRECT_CALL,
            f"прямого вызова {symbol} в коде нет",
            [*reasons, presence.detail,
             "закрывать нельзя: функция может вызываться внутри библиотеки "
             "из публичного API, который вы вызываете"],
        )

    if presence.presence is SymbolPresence.CALL_UNCONFIRMED:
        return CVEDecision(
            CVEVerdict.CALL_UNCONFIRMED,
            f"{symbol.function} вызывается, но класс объекта не подтверждён",
            [*reasons, presence.detail,
             "разрешить тип может языковой сервер; синтаксически это не видно"],
            [str(h) for h in presence.hits[:5]],
        )

    if presence.presence is SymbolPresence.REFERENCED:
        return CVEDecision(
            CVEVerdict.MENTIONED_ONLY,
            f"{symbol} не вызывается — класс только упомянут",
            [*reasons, presence.detail,
             "упоминание класса в конфигурации или регистрации не является вызовом"],
            [str(h) for h in presence.hits[:3]],
        )

    if presence.only_in_tests:
        return CVEDecision(
            CVEVerdict.ONLY_IN_TESTS,
            f"{symbol} вызывается только в тестах",
            [*reasons, "все места вызова — тестовый код, это не поверхность атаки",
             "закрывать нельзя: рабочий код может вызывать через другой путь"],
            [str(h) for h in presence.hits[:5]],
        )

    evidence = [str(h) for h in presence.production_hits[:5]] or [
        str(h) for h in presence.hits[:5]]
    driven = input_driven
    if driven is None:
        from .reach import needs_input_path

        driven = needs_input_path(cwe)

    if not driven:
        return CVEDecision(
            CVEVerdict.ACTUAL,
            f"уязвимость актуальна: {symbol} вызывается в коде",
            [*reasons, "эксплуатация не требует пользовательского ввода — "
                       "достаточно самого вызова"],
            evidence,
        )

    if reach is None:
        return CVEDecision(
            CVEVerdict.PRESENT_UNPROVEN,
            f"{symbol} вызывается, достижимость не проверялась",
            [*reasons, "проверка достижимости не запускалась"],
            evidence,
        )
    if reach.verdict is Reachability.REACHABLE:
        return CVEDecision(
            CVEVerdict.ACTUAL,
            f"уязвимость актуальна: {symbol} вызывается и достижима извне",
            [*reasons, f"точка входа: {reach.entrypoint}",
             f"поток данных: {reach.taint_path}"],
            evidence,
        )
    if reach.verdict is Reachability.NO_INPUT_PATH:
        return CVEDecision(
            CVEVerdict.PRESENT_UNPROVEN,
            f"{symbol} вызывается, но пути от пользовательского ввода не найдено",
            [*reasons, reach.detail,
             "оба инструмента отработали и пути не нашли — это довод, но не доказательство"],
            evidence,
        )
    return CVEDecision(
        CVEVerdict.PRESENT_UNPROVEN,
        f"{symbol} вызывается, достижимость не установлена",
        [*reasons, reach.detail],
        evidence,
    )
