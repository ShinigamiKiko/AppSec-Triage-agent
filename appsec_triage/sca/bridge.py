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

The walk can follow several hops, because a flaw is often two or three packages
deep: the application calls A, A calls B, B calls the vulnerable function of C.
One hop from the flaw yields B's function, but the application does not call that
either — it calls A — so a single-hop search of first-party code comes back
empty on a path that is entirely real. Each further hop repeats the same
question one package outward, until it reaches a name the application could
actually write.

This is name matching, and name matching across hops is where false confidence
is manufactured: two unrelated functions called `send` would splice into a path
that does not exist. So the walk is bounded in depth, its confidence decays with
each hop, and every result says how many hops it rests on and that it is a
name-level path, not one proven by a call graph — which remains CodeQL's job.
A hop whose source is not on disk stops the walk as *unknown*, never as closed.
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
    return _callers({vulnerable_function}, parent_source,
                    parent_package=parent_package, max_symbols=max_symbols)


def _callers(
    targets: set[str],
    parent_source: dict[str, str],
    *,
    parent_package: str = "",
    max_symbols: int = 12,
) -> BridgeResult:
    """Which functions of `parent_source` call any name in `targets`.

    The generalisation the walk needs: one hop looks for the vulnerable function,
    every hop after it looks for the public names the previous hop surfaced.
    """
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

    # One pattern per (language, name), built once rather than once per file:
    # a package is hundreds of files and the walk asks about several names.
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
                    # Parsed once per file, not once per match: `decl.enclosing`
                    # re-reads the whole file every call, which is quadratic on a
                    # file with many call sites.
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
        """One hop is the measured baseline; each further hop multiplies the doubt.

        Derived rather than stored: every construction site set it from `hops`,
        so a new early exit that forgot the argument would have shipped a
        default confidence of 1.0 next to a three-hop path.
        """
        return round(0.9 * (0.7 ** max(self.hops - 1, 0)), 3)


def walk_bridge(
    vulnerable_function: str,
    chain: list[str],
    source_of,
    *,
    max_depth: int = 4,
    max_symbols: int = 12,
) -> BridgeWalk:
    """Follow the flaw outward along `chain`, package by package, toward the app.

    `chain` is the packages between the flaw and the application, innermost
    first: the direct parent of the vulnerable package, then its parent, and so
    on out to the direct dependency the project declares. `source_of(package)`
    returns that package's installed source, or empty when it is not on disk.

    Returns what to search for in first-party code — the public names of the
    outermost package on a real path — together with how many hops that rests on
    and a confidence that decays per hop. Three terminal shapes:

    - **closed**: some package on the chain never calls inward, so no path runs
      through it. A fact about that package's code, and it stands.
    - **unknown**: a package's source is not on disk, or the chain is deeper than
      we will follow. The question is open, reported as such, never as closed.
    - a target list: the walk reached the direct dependency, and these public
      names are its side of the bridge to look for in the application.
    """
    if not vulnerable_function:
        return BridgeWalk(unknown=True, detail="уязвимая функция не определена")

    targets = {vulnerable_function}
    # What to offer if the walk stops early. Starts as the flaw itself and
    # becomes each hop's public symbols, so a walk that runs out of source still
    # hands back the furthest names it did establish rather than nothing.
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
                f"исходники {package} не на диске — путь через него не прослежен",
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

        # These public names are the outer package's side of the bridge — what
        # the next package out (or, after the last hop, first-party code) calls.
        carried = public[:max_symbols]
        targets = {s.function for s in public}

    return BridgeWalk(
        targets=carried, hops=len(chain),
        detail=(f"путь по именам через {len(chain)} посредник(ов): "
                f"{' -> '.join(chain)}; уверенность падает с каждым шагом, "
                "граф вызовов это не подтверждал"))
