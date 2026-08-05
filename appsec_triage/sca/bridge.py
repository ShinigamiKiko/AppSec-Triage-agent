"""From a transitive flaw to something the application could plausibly call.

Searching an application for `matchesDomain` finds nothing, because the
application does not call it — guzzle does, and the application calls guzzle.
Measured on the advisories resolved so far, only 5 of 22 vulnerable functions
were public API at all; the rest are internals, and a search for their names in
first-party code can only ever come back empty.

The intermediate package's own source closes that gap, and it is already
fetched for the confirmation step. Two questions are answerable from it:

*Does the parent call the flaw at all?* If `symfony/mailer` never calls the
vulnerable function of `egulias/email-validator`, then no path through the
parent reaches it. That is a real closure resting on the parent's code, not on
the absence of evidence in the application's.

*Through which of its own functions?* The enclosing declarations of those call
sites are the parent's side of the bridge. Public ones are what an application
can call, so those names — not the transitive one — are what to look for in
first-party code.

The walk stops at one hop by design. Following it further needs a call graph of
the library, which is what CodeQL is for; guessing at it by name matching would
manufacture confidence that nothing here has earned.
"""

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


def find_bridge(
    vulnerable_function: str,
    parent_source: dict[str, str],
    *,
    parent_package: str = "",
    max_symbols: int = 12,
) -> BridgeResult:
    """Which functions of `parent_source` call `vulnerable_function`."""
    if not vulnerable_function:
        return BridgeResult(detail="уязвимая функция не определена")
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

    found: list[BridgeSymbol] = []
    sites = 0
    for path, text in parent_source.items():
        language = decl.language_of(path)
        if language is None:
            continue
        call = decl.call_pattern(vulnerable_function, language)
        for match in call.finditer(text):
            sites += 1
            enclosing = decl.enclosing(path, text, match.start())
            if enclosing is None or enclosing.name == vulnerable_function:
                continue
            symbol = BridgeSymbol(enclosing.name, enclosing.owner, enclosing.visibility,
                                  path, enclosing.line)
            if not any(str(s) == str(symbol) for s in found):
                found.append(symbol)
            if len(found) >= max_symbols:
                break
        if len(found) >= max_symbols:
            break

    if not sites:
        return BridgeResult(
            calls_it=False, call_sites=0,
            detail=(f"{parent_package or 'пакет-посредник'} нигде не вызывает "
                    f"{vulnerable_function} — путь к уязвимости через него не идёт"))

    public = [s for s in found if s.callable_from_outside]
    return BridgeResult(
        calls_it=True, symbols=found, call_sites=sites,
        detail=(f"{parent_package or 'посредник'} вызывает {vulnerable_function} "
                f"в {sites} месте(ах); наружу открыто: "
                f"{', '.join(str(s) for s in public[:4]) or 'ничего публичного'}"))
