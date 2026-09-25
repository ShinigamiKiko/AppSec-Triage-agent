"""From a transitive flaw to something the application could plausibly call."""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass, field

from . import declarations as decl

log = logging.getLogger(__name__)

_JS_NAME = r"[A-Za-z_$][\w$]*"

# Called by the language, never by name: an object used as a function (a middleware, a
# runtime), `new`, a property read, a cast, array access, iteration. No search finds a
# call of them, so their absence from a parent's code says nothing about a path.
_IMPLICIT = frozenset({
    "__invoke", "__call", "__callStatic", "__get", "__set", "__isset", "__unset", "__toString",
    "__construct", "__destruct", "__clone", "__serialize", "__unserialize", "__sleep", "__wakeup",
    "offsetGet", "offsetSet", "offsetExists", "offsetUnset", "getIterator", "jsonSerialize",
    "__call__", "__init__", "__new__", "__getattr__", "__getattribute__", "__getitem__",
    "__setitem__", "__iter__", "__next__", "__enter__", "__exit__", "__str__", "__repr__", "__del__",
})


def _default_imports(text: str, package: str) -> dict[str, list[tuple[int, int]]]:
    """Local names bound to a package's CommonJS/default export."""
    quoted = rf"(?P<quote>['\"]){re.escape(package)}(?P=quote)"
    patterns = (
        rf"\b(?:const|let|var)\s+(?P<alias>{_JS_NAME})\s*=\s*require\s*\(\s*{quoted}\s*\)",
        rf"\bimport\s+(?P<alias>{_JS_NAME})\s+from\s+{quoted}",
    )
    bindings: dict[str, list[tuple[int, int]]] = {}
    for pattern in patterns:
        for match in re.finditer(pattern, text):
            bindings.setdefault(match.group("alias"), []).append(match.span())
    return bindings


@dataclass(slots=True)
class BridgeSymbol:
    """A function of the intermediate package that reaches the flaw."""

    function: str
    klass: str = ""
    visibility: str = "public"
    file: str = ""
    line: int = 0
    default_export: bool = False

    @property
    def callable_from_outside(self) -> bool:
        return self.visibility == "public"

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
        """All checked paths lack a call or reference to the target."""
        return self.calls_it is False


def _callers(
    targets: set[str],
    parent_source: dict[str, str],
    *,
    parent_package: str = "",
    default_export_from: str = "",
    max_symbols: int = 12,
    owners: set[str] | frozenset[str] = frozenset(),
) -> BridgeResult:
    """Which functions call or export any name in `targets`.

    `owners` are the classes the targets are methods of. A parent that names such a
    class without calling the method has registered it — as a service, an event
    listener, a handler — and the framework calls the method itself.
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

    patterns = {(language, target): decl.call_pattern(target, language)
                for language in languages for target in targets}

    found: list[BridgeSymbol] = []
    sites = 0
    aliases_by_path: dict[str, dict[str, list[tuple[int, int]]]] = {}
    for path, text in parent_source.items():
        language = decl.language_of(path)
        if language is None:
            continue
        aliases = (_default_imports(text, default_export_from)
                   if language == decl.JS and default_export_from else {})
        aliases_by_path[path] = aliases
        scan_targets = targets | aliases.keys()
        default_exports = decl.default_export_names(text) if language == decl.JS else set()
        parsed: list | None = None
        for target in scan_targets:
            pattern = patterns.get((language, target)) or decl.call_pattern(target, language)
            for match in pattern.finditer(text):
                sites += 1
                if parsed is None:
                    parsed = decl.declarations(path, text)
                enclosing = decl.enclosing_in(parsed, match.start())
                if enclosing is None:
                    continue
                if enclosing.name in scan_targets:
                    # A function calling its own name is recursion. A method of another
                    # class with the same name is a different function: Yaml::parse
                    # calling $parser->parse() is the entry point, not a loop.
                    before = text[max(0, match.start() - 10):match.start() + 1]
                    if not enclosing.owner or re.search(r"(?:\$this->|self::|static::|\bthis\.)\s*$",
                                                        before[:-1] if before else ""):
                        continue
                symbol = BridgeSymbol(enclosing.name, enclosing.owner, enclosing.visibility,
                                      path, enclosing.line, enclosing.name in default_exports)
                if not any(str(s) == str(symbol) for s in found):
                    found.append(symbol)
                if len(found) >= max_symbols:
                    break
            if len(found) >= max_symbols:
                break
        if len(found) >= max_symbols:
            break

    # Passing an API through is a path too: Express, for example, exposes
    # bodyParser.urlencoded as exports.urlencoded without calling it here.
    for path, text in parent_source.items():
        if decl.language_of(path) != decl.JS:
            continue
        aliases = aliases_by_path.get(path, {})
        default_exports = decl.default_export_names(text)
        if not any(target in text for target in targets | aliases.keys()):
            continue
        for target in targets:
            name = re.escape(target)
            forwarded = re.search(
                rf"\b(?:module\s*\.\s*)?exports\s*\.\s*{name}\s*=\s*"
                rf"(?:[A-Za-z_$][\w$]*\s*\.\s*)?{name}(?![\w$])", text)
            if forwarded is not None:
                found.append(BridgeSymbol(target, file=path,
                                          line=text.count("\n", 0, forwarded.start()) + 1,
                                          default_export=target in default_exports))
        for alias in aliases.keys() & default_exports:
            exported = re.search(rf"\bmodule\s*\.\s*exports\s*=\s*{re.escape(alias)}\b", text)
            if exported is not None:
                found.append(BridgeSymbol(alias, file=path,
                                          line=text.count("\n", 0, exported.start()) + 1,
                                          default_export=True))
        for declaration in decl.declarations(path, text):
            if declaration.name in targets and declaration.public:
                found.append(BridgeSymbol(declaration.name, declaration.owner,
                                          declaration.visibility, path, declaration.line,
                                          declaration.name in default_exports))
    found = list({(s.file, str(s)): s for s in found}.values())

    if not sites and not found:
        # A reference may be a forwarded export or alias that the simple call
        # parser cannot follow. It must remain unknown, not a negative fact.
        referenced = any(
            re.search(rf"(?<![\w$]){re.escape(target)}(?![\w$])", text)
            for target in targets for text in parent_source.values())
        if not referenced:
            referenced = any(
                any(not any(start <= match.start() < end for start, end in spans)
                    for match in re.finditer(rf"(?<![\w$]){re.escape(alias)}(?![\w$])",
                                             parent_source[path]))
                for path, aliases in aliases_by_path.items() for alias, spans in aliases.items())
        if referenced:
            return BridgeResult(
                detail=f"{parent_package or 'посредник'} упоминает {label}, "
                       "но статический вызов или реэкспорт не удалось разрешить")
        implicit = sorted(targets & _IMPLICIT)
        if implicit:
            return BridgeResult(
                detail=(f"путь к уязвимой функции идёт через {', '.join(implicit[:3])} — такой метод "
                        "вызывает сам язык (объект как функция, `new`, приведение, доступ по ключу), "
                        f"а не код по имени; отсутствие вызова в {parent_package or 'посреднике'} "
                        "ничего не доказывает"))
        registered = sorted(
            short for short in {_short_class(o) for o in owners} if short
            and any(re.search(rf"(?<![\w$]){re.escape(short)}(?![\w$])", text)
                    for text in parent_source.values()))
        if registered:
            return BridgeResult(
                detail=(f"{parent_package or 'посредник'} не вызывает {label} по имени, но ссылается "
                        f"на класс {', '.join(registered[:3])} — так фреймворк подключает сервисы, "
                        "слушатели событий и обработчики и вызывает их методы сам; "
                        "по именам путь не проследить"))
        return BridgeResult(
            calls_it=False, call_sites=0,
            detail=(f"{parent_package or 'пакет-посредник'} нигде не вызывает "
                    f"{label} и не ссылается на него — путь через него не найден"))

    public = [s for s in found if s.callable_from_outside]
    action = (f"вызывает {label} в {sites} месте(ах)" if sites
              else f"экспортирует или передаёт наружу {label}")
    return BridgeResult(
        calls_it=True, symbols=found, call_sites=sites,
        detail=(f"{parent_package or 'посредник'} {action}; наружу открыто: "
                f"{', '.join(str(s) for s in public[:4]) or 'ничего публичного'}"))


def _short_class(name: str) -> str:
    r"""`Symfony\Component\X\Listener` or `pkg.Listener` → `Listener`."""
    return re.split(r"[\\.]", (name or "").strip())[-1]


def entry_points(function: str, source: dict[str, str], *, package: str = "",
                 max_steps: int = 8, max_symbols: int = 24) -> list[BridgeSymbol]:
    """Public functions of one package from which `function` is reached inside it.

    The flaw is often in a private helper no application calls; the application
    calls a public function above it — `Yaml::parse` over `Parser::parseBlock`,
    `load` over `storeMappingPair`. A call of one of these is a call of the flaw,
    and they are the names a search of the application has to look for.

    Name-based, like the bridge: a path the package takes only through a callback
    or a dynamic dispatch is missed, so an empty list proves nothing.
    """
    if not function or not source:
        return []
    found: list[BridgeSymbol] = []
    frontier, seen = {function}, {function}
    for _ in range(max_steps):
        if not frontier:
            break
        result = _callers(frontier, source, parent_package=package, max_symbols=max_symbols)
        if not result.calls_it:
            break
        for symbol in result.public_symbols:
            if not any(str(s) == str(symbol) for s in found):
                found.append(symbol)
        # Public callers keep being followed: an application may call either
        # `Yaml::parse` or the `Parser::parse` it delegates to.
        frontier = {s.function for s in result.symbols} - seen
        seen |= frontier
    return found


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
    max_internal_steps: int = 4,
    origin_package: str = "",
    vulnerable_class: str = "",
) -> BridgeWalk:
    """Follow the flaw outward along `chain`, package by package, toward the app."""
    if not vulnerable_function:
        return BridgeWalk(unknown=True, detail="уязвимая функция не определена")

    targets = {vulnerable_function}
    carried = [BridgeSymbol(vulnerable_function, vulnerable_class)]
    if not chain:
        return BridgeWalk(targets=carried, unknown=True,
                          detail="цепочка посредников пуста")

    def stopped(detail: str, hops: int) -> BridgeWalk:
        return BridgeWalk(targets=carried, hops=hops, unknown=True, detail=detail)

    packages = ([origin_package] if origin_package else []) + chain
    for depth, package in enumerate(packages, 1):
        parent_depth = depth - bool(origin_package)
        if parent_depth > max_depth:
            return stopped(
                f"цепочка глубже {max_depth} посредников — дальше не прослеживаем",
                parent_depth - 1)

        source = source_of(package)
        if not source:
            return stopped(
                f"{package} не установлен в дереве проекта — "
                "путь через него не прослежен",
                max(parent_depth - 1, 0))

        frontier = set(targets)
        seen = set(frontier)
        public: list[BridgeSymbol] = []
        steps = 0
        imported_default = (packages[depth - 2] if depth > 1
                            and any(s.default_export and s.function in targets for s in carried)
                            else "")
        # The package that declares the classes names them too: only a parent's
        # reference to them is a registration.
        owners = ({s.klass for s in carried if s.klass}
                  if not (origin_package and depth == 1) else set())
        while frontier and steps < max_internal_steps:
            result = _callers(frontier, source, parent_package=package,
                              default_export_from=imported_default if frontier & targets else "",
                              max_symbols=max_symbols, owners=owners if frontier == targets else set())
            if result.calls_it is None:
                return stopped(result.detail, max(parent_depth, 0))
            if result.calls_it is False:
                if steps == 0:
                    if origin_package and depth == 1:
                        return stopped(
                            f"уязвимая функция не найдена в установленном {package}; "
                            "публичный вход определить нельзя", 0)
                    return BridgeWalk(hops=parent_depth, closed=True, detail=result.detail)
                break

            steps += 1
            for symbol in result.public_symbols:
                if not any((s.file, str(s)) == (symbol.file, str(symbol)) for s in public):
                    public.append(symbol)
            private = {s.function for s in result.symbols if not s.callable_from_outside}
            frontier = private - seen
            seen.update(frontier)

        if not public:
            return stopped(
                f"{package} вызывает искомое, но за {steps} внутренних шаг(ов) "
                "публичный вход не найден", max(parent_depth, 0))

        carried = public[:max_symbols]
        targets = {s.function for s in carried}

    return BridgeWalk(
        targets=carried, hops=len(chain),
        detail=(f"путь по именам через {len(chain)} посредник(ов): "
                f"{' -> '.join(chain)}; уверенность падает с каждым шагом, "
                "граф вызовов это не подтверждал"))
