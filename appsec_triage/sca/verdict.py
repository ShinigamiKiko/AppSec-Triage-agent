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
    WRONG_RECEIVER = "wrong_receiver"
    NOT_REACHED = "not_reached"
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
                                CVEVerdict.INFRASTRUCTURE, CVEVerdict.WRONG_RECEIVER,
                                CVEVerdict.NOT_REACHED)

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
) -> CVEDecision:
    """Combine the steps. Facts that settle it are checked before anything else."""
    # A real call graph outranks every approximation below it, in both
    # directions: it names the frames when the flaw is reached, and it has read
    # the whole program when it is not. Everything else here infers reachability
    # from names, imports or a single call site.
    if reachability is not None:
        if reachability.reachable:
            # The graph proved the path; the call site decides whether the flaw
            # can fire along it. A quoted line saying it cannot — plain HTTP
            # where the flaw needs HTTP/2, a link-local address where it needs
            # an attacker — lowers this to a condition that is not met. Without
            # a quote nothing moves: the graph's answer stands.
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
        # The closure was checked for the calls the graph cannot resolve. A
        # quoted hit there is not proof of a path — nothing traced one — but it
        # is proof that the graph's silence does not settle this, so the finding
        # goes back to a person rather than closing.
        if graph_audit is not None and graph_audit.reopens:
            return CVEDecision(
                CVEVerdict.PRESENT_UNPROVEN,
                "граф вызовов пути не нашёл, но в коде есть вызовы, которых он не видит",
                [reachability.render(), graph_audit.render(),
                 "не закрыто: закрытие графом не проходит проверку на "
                 "рефлексию и подгружаемый код"],
                reachability.trace[:6],
            )
        return CVEDecision(
            CVEVerdict.NOT_REACHED,
            "по графу вызовов уязвимая функция недостижима",
            [reachability.render(),
             (graph_audit.render() if graph_audit is not None
              else "закрыто по статическому графу: вызовы через рефлексию или "
                   "подгружаемые модули он не видит")],
        )
    # One guard for every mechanical closure below, because they all fail the
    # same way: the check was right about what it measured and wrong about what
    # that meant. The audit found something the check could not see and quoted
    # it, so the finding goes back to a person instead of closing. Placed here
    # rather than repeated in each branch — a closure added later is covered
    # without anyone remembering to cover it.
    if closure_audit is not None and closure_audit.reopens:
        return CVEDecision(
            CVEVerdict.PRESENT_UNPROVEN,
            "закрытие не выдержало проверки на свою слепую зону",
            [closure_audit.render(),
             "не закрыто: механическая проверка была верна, но её вывод не следует"],
        )

    # The language server resolved every matching call site and none of them
    # lands in the flawed package: the name collided, the type did not. This is
    # a resolver's answer about types, not an absence of text, so it closes.
    if receiver_disproved:
        return CVEDecision(
            CVEVerdict.WRONG_RECEIVER,
            "совпало имя метода, но получатель другого типа",
            [(presence.detail if presence else "")
             or "языковой сервер разрешил все места вызова вне этого пакета",
             "закрыто по разрешению типов, а не по отсутствию имени в коде"],
        )
    if dev_only:
        return CVEDecision(
            CVEVerdict.NOT_SHIPPED,
            "не поставляется в продакшн: пакет только для сборки и тестов",
            ["в SBOM помечен как build-only — в рантайме его нет"],
        )

    # CodeQL was asked whether attacker-controlled input reaches the call. A path
    # found is the strongest positive there is — the call happens *and* the input
    # arrives. A path absent closes only a weakness that needs input to begin
    # with: "no user data reaches this" says nothing about a flaw that fires on
    # any call, so without a CWE saying input is required it is doubt, not proof.
    if dataflow is not None and dataflow is not False:
        return CVEDecision(
            CVEVerdict.ACTUAL,
            "уязвимость актуальна: пользовательский ввод доходит до вызова",
            [dataflow.render(), "поток данных построен CodeQL по базе этого прогона"],
            [f"{dataflow.source_file}:{dataflow.source_line}",
             f"{dataflow.file}:{dataflow.line}"],
        )
    if dataflow is False and input_driven:
        return CVEDecision(
            CVEVerdict.CONDITION_ABSENT,
            "пользовательский ввод до уязвимого вызова не доходит",
            ["CodeQL: путь от источника пользовательских данных к этому вызову не найден",
             "уязвимость этого класса без управляемого ввода не срабатывает",
             "закрыто по потоку данных, а не по отсутствию имени в коде"],
        )

    # The advisory names the import paths its flaw lives in, and none of them is
    # imported by code the project owns. For a direct dependency that settles it:
    # the vulnerable file is never loaded, so no name found in the repository can
    # be a call into it.
    #
    # This is what separates a real call from a collision on a common name, and
    # it was measured: a project importing only `x/crypto/bcrypt` was told three
    # `x/crypto/ssh` flaws were "actual" because it calls `ldap.DialURL` and the
    # advisories name `Dial`. govulncheck, reading a real call graph, agreed the
    # ssh code is never reached.
    #
    # Only for a direct dependency. For a transitive one the application is not
    # expected to import the path at all — its parent does, and absence there
    # means nothing (see the bridge).
    if symbol is not None and symbol.package_paths and package_used is False and direct:
        paths = min(symbol.package_paths, key=len)
        return CVEDecision(
            CVEVerdict.UNUSED,
            f"уязвимый пакет {paths} не импортируется",
            [symbol.note or "advisory называет уязвимые пути импорта",
             package_used_detail or "путь пакета не встречается в коде проекта",
             "имя функции могло совпасть с чужим — без импорта вызова быть не может"],
        )

    # A package-level advisory — the whole package is unsafe, with no vulnerable
    # function to search for. There is no call to find, so the verdict rests on
    # one fact: is the flagged import path used. Decided here, before the generic
    # symbol logic sends a functionless finding to manual review.
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
