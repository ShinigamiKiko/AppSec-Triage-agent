"""Turning the three checks into one statement about a dependency CVE."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from .presence import PresenceResult, SymbolPresence
from .reach import Reachability, ReachResult
from .resolve import VulnerableSymbol


class CVEVerdict(str, Enum):
    INFRASTRUCTURE = "infrastructure"
    NOT_SHIPPED = "not_shipped"
    UNUSED = "unused"
    CONDITION_ABSENT = "condition_absent"
    ACTUAL = "actual"
    PRESENT_UNPROVEN = "present"
    ONLY_IN_TESTS = "only_in_tests"
    ONLY_TEST_IMPORT = "test_only_import"
    CALL_UNCONFIRMED = "call_unconfirmed"
    MENTIONED_ONLY = "mentioned"
    NOT_APPLICABLE = "not_applicable"
    NO_DIRECT_CALL = "no_direct_call"
    WRONG_RECEIVER = "wrong_receiver"
    NOT_REACHED = "not_reached"
    NOT_CALLED = "not_called"
    VERSION_UNAFFECTED = "version_unaffected"
    UNDECIDED = "undecided"


@dataclass(slots=True)
class CVEDecision:
    verdict: CVEVerdict
    headline: str
    reasons: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)

    @property
    def closes(self) -> bool:
        """Outcomes that rest on a fact, not on failing to find something."""
        return self.verdict in (CVEVerdict.NOT_APPLICABLE, CVEVerdict.NOT_SHIPPED,
                                CVEVerdict.UNUSED, CVEVerdict.CONDITION_ABSENT,
                                CVEVerdict.INFRASTRUCTURE, CVEVerdict.WRONG_RECEIVER,
                                CVEVerdict.NOT_REACHED, CVEVerdict.ONLY_TEST_IMPORT,
                                CVEVerdict.ONLY_IN_TESTS, CVEVerdict.NOT_CALLED,
                                CVEVerdict.VERSION_UNAFFECTED)



def _audited(audit, kind: str) -> bool:
    """Did the check aimed at this closure's blind spot actually run?"""
    return audit is not None and getattr(audit, "checked", False) and audit.kind == kind


def _unchecked(headline: str, audit, kind: str, *reasons: str) -> CVEDecision:
    """A closure that could not be checked goes to a person, carrying why."""
    detail = getattr(audit, "detail", "") if audit is not None else ""
    return CVEDecision(
        CVEVerdict.PRESENT_UNPROVEN,
        headline,
        [*[r for r in reasons if r],
         detail or f"проверка закрытия «{kind}» не выполнялась",
         "не закрыто: механическая проверка не прошла контроль своей слепой зоны"],
    )


def version_unaffected(check) -> CVEDecision:
    """The installed version lies outside every range the advisory lists."""
    return CVEDecision(
        CVEVerdict.VERSION_UNAFFECTED,
        f"не уязвимо: {check.detail}",
        [check.detail,
         "сверено с диапазонами advisory (introduced / fixed / last_affected), а не с одним номером фикса",
         "закрыто по версии — поиск функции и достижимости не нужен"],
    )


def _lsp_checked(lsp_audit) -> bool:
    """The model asked the language server, and it found no project caller."""
    return _audited(lsp_audit, "not_called") and not lsp_audit.reopens


def _not_called(lsp_audit, *reasons: str) -> CVEDecision:
    """A false positive with a mark: the version is affected, nothing here calls the flaw."""
    return CVEDecision(
        CVEVerdict.NOT_CALLED,
        "ложное срабатывание с пометкой: уязвимую функцию код проекта не вызывает",
        [*[r for r in reasons if r], lsp_audit.render(),
         "проверено языковым сервером от объявления в пакете, а не поиском по тексту",
         "пометка: установленная версия уязвима — если вызов появится, находка вернётся",
         "не покрыто: вызов через публичный API пакета, который модель не спросила"],
    )


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
    test_only: bool = False,
    package_used: bool | None = None,
    package_used_detail: str = "",
    receiver_disproved: bool = False,
    reachability=None,
    call_site=None,
    graph_audit=None,
    closure_audit=None,
    dataflow=None,
    direct: bool | None = None,
    condition=None,
    lsp_audit=None,
) -> CVEDecision:
    """Combine the steps."""
    if reachability is not None:
        if reachability.reachable:
            if dataflow is not None and dataflow is not False:
                return CVEDecision(
                    CVEVerdict.ACTUAL,
                    "уязвимость актуальна: пользовательский ввод доходит до вызова",
                    [dataflow.render(), "поток данных построен CodeQL по базе этого прогона"],
                    [f"{dataflow.source_file}:{dataflow.source_line}",
                     f"{dataflow.file}:{dataflow.line}"],
                )
            if call_site is not None and call_site.lowers:
                return CVEDecision(
                    CVEVerdict.CONDITION_ABSENT,
                    "путь есть, но так, как этот код вызывает, изъян не срабатывает",
                    [reachability.render(), call_site.render(),
                     "закрыто по прочитанному месту вызова, с цитатой из кода"],
                    reachability.trace[:6],
                )
            return CVEDecision(
                CVEVerdict.ACTUAL,
                "уязвимость актуальна: граф вызовов доходит до уязвимой функции",
                [reachability.render(),
                 "это трасса из графа вызовов, а не совпадение имён",
                 *([call_site.render()] if call_site is not None else [])],
                reachability.trace[:6],
            )
        if graph_audit is not None and graph_audit.reopens:
            return CVEDecision(
                CVEVerdict.PRESENT_UNPROVEN,
                "граф вызовов пути не нашёл, но в коде есть вызовы, которых он не видит",
                [reachability.render(), graph_audit.render(),
                 ("не закрыто: закрытие графом не проходит проверку на "
                 "рефлексию и подгружаемый код")],
                reachability.trace[:6],
            )
        if not _audited(graph_audit, "not_reached"):
            return _unchecked(
                "граф вызовов пути не нашёл, но закрытие не проверено",
                graph_audit, "not_reached", reachability.render())
        return CVEDecision(
            CVEVerdict.NOT_REACHED,
            "по графу вызовов уязвимая функция недостижима",
            [reachability.render(), graph_audit.render(),
             "закрыто по статическому графу, проверенному на рефлексию, "
             "подгружаемые модули и генерируемый код"],
        )
    if closure_audit is not None and closure_audit.reopens:
        return CVEDecision(
            CVEVerdict.PRESENT_UNPROVEN,
            "закрытие не выдержало проверки на свою слепую зону",
            [closure_audit.render(),
             "не закрыто: механическая проверка была верна, но её вывод не следует"],
        )

    if receiver_disproved:
        if not _audited(closure_audit, "wrong_receiver"):
            return _unchecked(
                "получатель другого типа, но закрытие не проверено",
                closure_audit, "wrong_receiver",
                (presence.detail if presence else ""))
        return CVEDecision(
            CVEVerdict.WRONG_RECEIVER,
            "совпало имя метода, но получатель другого типа",
            [(presence.detail if presence else "")
             or "языковой сервер разрешил все места вызова вне этого пакета",
             closure_audit.render(),
             "закрыто по разрешению типов, а не по отсутствию имени в коде"],
        )
    if dev_only:
        if not _audited(closure_audit, "not_shipped"):
            return _unchecked(
                "пакет помечен build-only, но закрытие не проверено",
                closure_audit, "not_shipped",
                "в SBOM помечен как build-only")
        return CVEDecision(
            CVEVerdict.NOT_SHIPPED,
            "не поставляется в продакшн: пакет только для сборки и тестов",
            ["в SBOM помечен как build-only — в рантайме его нет",
             closure_audit.render()],
        )

    if dataflow is not None and dataflow is not False:
        return CVEDecision(
            CVEVerdict.ACTUAL,
            "уязвимость актуальна: пользовательский ввод доходит до вызова",
            [dataflow.render(), "поток данных построен CodeQL по базе этого прогона"],
            [f"{dataflow.source_file}:{dataflow.source_line}",
             f"{dataflow.file}:{dataflow.line}"],
        )
    if used is False and test_only and direct:
        if not _audited(closure_audit, "test_only"):
            return _unchecked(
                "импорты найдены только в тестах, но закрытие не проверено",
                closure_audit, "test_only", used_detail)
        return CVEDecision(
            CVEVerdict.ONLY_TEST_IMPORT,
            "библиотека подключается только в тестовом коде",
            [used_detail or "импорты найдены только в тестовых путях",
             "тестовые пути заданы в prompts/training-context.md, тот же список видит модель",
             closure_audit.render(),
             "рабочий код пакет не импортирует — в поставляемом приложении он не вызывается"],
        )
    if dataflow is False and input_driven:
        audited = (closure_audit is not None and closure_audit.checked
                   and closure_audit.kind == "no_input_path")
        if not audited:
            return CVEDecision(
                CVEVerdict.PRESENT_UNPROVEN,
                "CodeQL не нашёл пути от пользовательского ввода, но закрытие не проверено",
                ["CodeQL: путь от известных ему источников к этому вызову не найден",
                 (closure_audit.render() if closure_audit is not None
                  else "проверка источников, которых CodeQL не моделирует, не выполнялась"),
                 "не закрыто: отсутствие пути от смоделированных источников не доказательство"],
            )
        return CVEDecision(
            CVEVerdict.CONDITION_ABSENT,
            "пользовательский ввод до уязвимого вызова не доходит",
            ["CodeQL: путь от источника пользовательских данных к этому вызову не найден",
             "уязвимость этого класса без управляемого ввода не срабатывает",
             closure_audit.render(),
             "закрыто по потоку данных, а не по отсутствию имени в коде"],
        )

    if symbol is not None and symbol.package_paths and package_used is False and direct:
        paths = min(symbol.package_paths, key=len)
        if not _audited(closure_audit, "unused"):
            return _unchecked(
                f"путь {paths} в коде не найден, но закрытие не проверено",
                closure_audit, "unused", package_used_detail)
        return CVEDecision(
            CVEVerdict.UNUSED,
            f"уязвимый пакет {paths} не импортируется",
            [symbol.note or "advisory называет уязвимые пути импорта",
             package_used_detail or "путь пакета не встречается в коде проекта",
             closure_audit.render(),
             "имя функции могло совпасть с чужим — без импорта вызова быть не может"],
        )

    if symbol is not None and not symbol.usable and symbol.package_paths \
            and package_used:
        paths = min(symbol.package_paths, key=len)
        return CVEDecision(
            CVEVerdict.ACTUAL,
            f"уязвимость актуальна: пакет {paths} импортируется",
            [symbol.note or "уязвим весь пакет, без конкретной функции",
             "для этого advisory сам импорт пакета и есть уязвимость"],
            [package_used_detail],
        )

    if used is False:
        if direct:
            if not _audited(closure_audit, "unused"):
                return _unchecked(
                    "имя пакета в коде не найдено, но закрытие не проверено",
                    closure_audit, "unused", used_detail)
            return CVEDecision(
                CVEVerdict.UNUSED,
                "библиотека не используется в коде проекта",
                [used_detail or "имя пакета не встречается ни в одном файле",
                 "пакет объявлен прямой зависимостью, но в коде не упоминается",
                 closure_audit.render(),
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
            if getattr(condition, "source", "") == "text":
                if _lsp_checked(lsp_audit):
                    return _not_called(lsp_audit, condition.render())
                return _unchecked(
                    "условие эксплуатации не найдено текстовым поиском, но закрытие не проверено",
                    lsp_audit, "condition_absent", condition.render(),
                    "отсутствие имён в файлах — не доказательство: вызов может идти через "
                    "обёртку, настройка — собираться во время работы")
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
        if _lsp_checked(lsp_audit):
            return _not_called(lsp_audit, *reasons, presence.detail)
        return CVEDecision(
            CVEVerdict.NO_DIRECT_CALL,
            f"прямого вызова {symbol} в коде нет",
            [*reasons, presence.detail,
             ("закрывать нельзя: функция может вызываться внутри библиотеки "
             "из публичного API, который вы вызываете")],
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
        if _lsp_checked(lsp_audit):
            return _not_called(lsp_audit, *reasons, presence.detail)
        return CVEDecision(
            CVEVerdict.MENTIONED_ONLY,
            f"{symbol} не вызывается — класс только упомянут",
            [*reasons, presence.detail,
             "упоминание класса в конфигурации или регистрации не является вызовом"],
            [str(h) for h in presence.hits[:3]],
        )

    if presence.only_in_tests:
        if not _audited(closure_audit, "only_in_tests"):
            return _unchecked(
                f"вызовы {symbol} найдены только в тестах, но закрытие не проверено",
                closure_audit, "only_in_tests", *reasons, presence.detail)
        return CVEDecision(
            CVEVerdict.ONLY_IN_TESTS,
            f"{symbol} вызывается только в тестах",
            [*reasons, "все места вызова — тестовый код, это не поверхность атаки",
             closure_audit.render(),
             "рабочий код эту функцию не вызывает — в поставляемом приложении она не работает"],
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
            [*reasons, ("эксплуатация не требует пользовательского ввода — "
                       "достаточно самого вызова")],
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
