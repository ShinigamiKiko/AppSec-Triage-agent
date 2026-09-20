"""From a transitive flaw to something the application could plausibly call."""

from __future__ import annotations

import logging
from collections import Counter
from dataclasses import dataclass, field

from . import declarations as decl

log = logging.getLogger(__name__)


@dataclass(slots=True)
class BridgeSymbol:
    """A function of the intermediate package that reaches the flaw."""

    function: str
    klass: str = ""
    visibility: str = "public"
    file: str = ""
    line: int = 0

    @property
    def callable_from_outside(self) -> bool:
        return self.visibility == "public" and not self.function.startswith("_")

    def __str__(self) -> str:
        return f"{self.klass}::{self.function}" if self.klass else self.function


@dataclass(slots=True)
class BridgeResult:
    calls_it: bool | None = None
    symbols: list[BridgeSymbol] = field(default_factory=list)
    call_sites: int = 0
    detail: str = ""

    @property
    def public_symbols(self) -> list[BridgeSymbol]:
        return [s for s in self.symbols if s.callable_from_outside]

    @property
    def closes(self) -> bool:
        """The parent was read in full and never calls the vulnerable function."""
        return self.calls_it is False


def _callers(
    targets: set[str],
    parent_source: dict[str, str],
    *,
    parent_package: str = "",
    max_symbols: int = 12,
) -> BridgeResult:
    """Which functions of `parent_source` call any name in `targets`."""
    label = ", ".join(sorted(targets)[:3]) or "искомую функцию"
    if not parent_source:
        return BridgeResult(
            detail=f"исходники {parent_package or 'посредника'} не получены — "
                   "нельзя проверить, вызывает ли он уязвимую функцию")

    languages = Counter(lang for path in parent_source
                        if (lang := decl.language_of(path)) is not None)
    if not languages:
        kinds = sorted({p.rsplit(".", 1)[-1] for p in list(parent_source)[:40] if "." in p})
        return BridgeResult(
            detail=(f"язык {parent_package or 'посредника'} не разбирается "
                    f"(файлы: {', '.join(kinds[:6]) or 'неизвестно'}) — "
                    "нельзя проверить, вызывает ли он уязвимую функцию"))

    patterns = {(language, target): decl.call_pattern(target, language)
                for language in languages for target in targets}

    found: list[BridgeSymbol] = []
    sites = 0
    for path, text in parent_source.items():
        language = decl.language_of(path)
        if language is None:
            continue
        parsed: list | None = None
        for target in targets:
            for match in patterns[(language, target)].finditer(text):
                sites += 1
                if parsed is None:
                    parsed = decl.declarations(path, text)
                enclosing = decl.enclosing_in(parsed, match.start())
                if enclosing is None or enclosing.name in targets:
                    continue
                symbol = BridgeSymbol(enclosing.name, enclosing.owner, enclosing.visibility,
                                      path, enclosing.line)
                if not any(str(s) == str(symbol) for s in found):
                    found.append(symbol)
                if len(found) >= max_symbols:
                    break
            if len(found) >= max_symbols:
                break
        if len(found) >= max_symbols:
            break

    if not sites:
        return BridgeResult(
            calls_it=False, call_sites=0,
            detail=(f"{parent_package or 'пакет-посредник'} нигде не вызывает "
                    f"{label} — путь к уязвимости через него не идёт; "
                    "это поиск по имени, он не видит тип получателя, "
                    "поэтому находку не закрывает"))

    public = [s for s in found if s.callable_from_outside]
    return BridgeResult(
        calls_it=True, symbols=found, call_sites=sites,
        detail=(f"{parent_package or 'посредник'} вызывает {label} "
                f"в {sites} месте(ах); наружу открыто: "
                f"{', '.join(str(s) for s in public[:4]) or 'ничего публичного'}"))


@dataclass(slots=True)
class BridgeWalk:
    """The result of following the bridge across one or more packages."""

    targets: list[BridgeSymbol] = field(default_factory=list)
    hops: int = 0
    closed: bool = False
    unknown: bool = False
    detail: str = ""

    @property
    def confidence(self) -> float:
        """One hop is the measured baseline; each further hop multiplies the doubt."""
        return round(0.9 * (0.7 ** max(self.hops - 1, 0)), 3)


def walk_bridge(
    vulnerable_function: str,
    chain: list[str],
    source_of,
    *,
    max_depth: int = 4,
    max_symbols: int = 12,
) -> BridgeWalk:
    """Follow the flaw outward along `chain`, package by package, toward the app."""
    if not vulnerable_function:
        return BridgeWalk(unknown=True, detail="уязвимая функция не определена")

    targets = {vulnerable_function}
    carried = [BridgeSymbol(vulnerable_function)]
    if not chain:
        return BridgeWalk(targets=carried, unknown=True,
                          detail="цепочка посредников пуста")

    def stopped(detail: str, hops: int) -> BridgeWalk:
        return BridgeWalk(targets=carried, hops=hops, unknown=True, detail=detail)

    for depth, package in enumerate(chain, 1):
        if depth > max_depth:
            return stopped(
                f"цепочка глубже {max_depth} посредников — дальше не прослеживаем",
                depth - 1)

        source = source_of(package)
        if not source:
            return stopped(
                f"{package} не установлен в дереве проекта — "
                "путь через него не прослежен",
                depth - 1)

        result = _callers(targets, source, parent_package=package, max_symbols=max_symbols)
        if result.calls_it is False:
            return BridgeWalk(hops=depth, closed=True, detail=result.detail)

        public = result.public_symbols
        if not public:
            carried = result.symbols[:max_symbols]
            return stopped(
                f"{package} вызывает искомое только через непубличные функции — "
                "снаружи этот путь не адресуем", depth)

        carried = public[:max_symbols]
        targets = {s.function for s in public}

    return BridgeWalk(
        targets=carried, hops=len(chain),
        detail=(f"путь по именам через {len(chain)} посредник(ов): "
                f"{' -> '.join(chain)}; уверенность падает с каждым шагом, "
                "граф вызовов это не подтверждал"))
