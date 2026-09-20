"""Step 3: is the vulnerable symbol actually present in this repository?"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..testpaths import is_test
from ..context.detection import DEFAULT_SOURCE_SUFFIXES, DetectionError, get_source_suffixes

log = logging.getLogger(__name__)

_INTERNAL_SEGMENT = re.compile(r"(?:^|/)internal(?:/|$)")

_SKIP_DIRS = {
    ".git", "vendor", "node_modules", "venv", ".venv", "target", "build",
    "dist", "__pycache__", ".idea", ".vscode", ".tox", ".mypy_cache",
}


def _skip_path(path: Path) -> bool:
    """Generated triage reports are not application source or configuration."""
    return bool(_SKIP_DIRS.intersection(path.parts)) or any(
        part.lower().startswith("appsec-out") for part in path.parts
    )


_MAX_FILES = 8000
_MAX_BYTES = 600_000

_LINE_COMMENT = re.compile(r"(?://|#).*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.DOTALL)


def package_namespaces(ecosystem: str, package: str) -> list[str]:
    """How this package's code is named where it gets used."""
    name = (package or "").strip()
    if not name:
        return []
    key = (ecosystem or "").strip().lower()
    if key in ("composer", "packagist", "php"):
        vendor, _, project = name.partition("/")
        def camel(part: str) -> str:
            return "".join(bit[:1].upper() + bit[1:] for bit in re.split(r"[-_.]", part) if bit)
        out = [camel(vendor)]
        if project:
            out.append(f"{camel(vendor)}\\{camel(project)}")
        return [o for o in out if o]
    # A scoped npm package must match its complete coordinate.
    return [name]


def _first_file_matching(
    root: Path, ecosystem: str, patterns: list[re.Pattern[str]]
) -> tuple[Path | None, int] | None:
    """First first-party file matching any pattern, as (relative path, index)."""
    try:
        suffixes = get_source_suffixes([root], for_ecosystem=ecosystem)
    except DetectionError:
        suffixes = DEFAULT_SOURCE_SUFFIXES
    files, _ = _source_files(root, suffixes)
    if not files:
        return None

    for path in files:
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for index, pattern in enumerate(patterns):
            if pattern.search(text):
                return path.relative_to(root), index
    return None, -1


def installed_namespaces(root: Path | str, ecosystem: str, package: str) -> list[str]:
    """The names the installed package actually declares, from its own composer.json."""
    import json

    if (ecosystem or "").strip().lower() not in ("composer", "packagist", "php") or not package:
        return []
    manifest = Path(root) / "vendor" / package / "composer.json"
    try:
        autoload = (json.loads(manifest.read_text(encoding="utf-8")) or {}).get("autoload") or {}
    except (OSError, ValueError, AttributeError):
        return []
    names: list[str] = []
    for kind in ("psr-4", "psr-0"):
        for prefix in (autoload.get(kind) or {}):
            name = str(prefix).strip().strip("\\")
            if name and name not in names:
                names.append(name)
    # Classmap: global classes with no namespace, often in "classmap": ["lib/"]
    for entry in (autoload.get("classmap") or []):
        path = Path(root) / "vendor" / package / str(entry)
        if not path.exists():
            continue
        if path.is_file() and path.suffix == ".php":
            files_to_scan = [path]
        else:
            files_to_scan = list(path.rglob("*.php")) if path.is_dir() else []
        for php_file in files_to_scan[:20]:  # cap at 20 files
            try:
                text = php_file.read_text(encoding="utf-8", errors="replace")
                # Extract global class names: class TCPDF, class Foo_Bar
                for match in re.finditer(r"^\s*(?:abstract\s+|final\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)", text, re.MULTILINE):
                    name = match.group(1)
                    if name and name not in names:
                        names.append(name)
            except OSError:
                continue
    return names


def package_usage(root: Path | str, ecosystem: str, package: str) -> tuple[bool | None, str, bool]:
    """(used, detail, test_only): is this package named in first-party production code?"""
    names = package_namespaces(ecosystem, package)
    names += [n for n in installed_namespaces(root, ecosystem, package) if n not in names]
    if not names:
        return None, "имя пакета не разобрано", False

    patterns = [re.compile(rf"(?<![\w\\]){re.escape(n)}(?![\w])", re.IGNORECASE) for n in names]
    root = Path(root)
    try:
        suffixes = get_source_suffixes([root], for_ecosystem=ecosystem)
    except DetectionError:
        suffixes = DEFAULT_SOURCE_SUFFIXES
    files, _ = _source_files(root, suffixes)
    if not files:
        return None, "в проекте нет файлов на языке пакета", False

    test_hit = ""
    for path in files:
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        index = next((i for i, pattern in enumerate(patterns) if pattern.search(text)), None)
        if index is None:
            continue
        rel = path.relative_to(root).as_posix()
        if is_test(rel):
            test_hit = test_hit or f"{names[index]} встречается в {rel}"
            continue
        return True, f"{names[index]} встречается в {rel}", False
    if test_hit:
        return False, f"{test_hit} — только в тестовом коде", True
    return False, f"ни одно из имён ({', '.join(names)}) не встречается в коде проекта", False


def import_path_used(
    root: Path | str, ecosystem: str, paths: list[str] | tuple[str, ...]
) -> tuple[bool | None, str]:
    """Is any of these exact import paths brought in by first-party code?"""
    wanted = [p for p in paths if p and not _INTERNAL_SEGMENT.search(p)]
    if not wanted:
        if any(paths):
            return None, ("уязвимый код лежит во внутреннем пакете "
                          f"({', '.join(p for p in paths if p)}) — снаружи он "
                          "не импортируется по правилам языка, "
                          "отсутствие импорта ничего не доказывает")
        return None, "путь пакета неизвестен"

    alternation = "|".join(re.escape(p) for p in sorted(set(wanted), key=len, reverse=True))
    pattern = re.compile(rf"""["'](?:{alternation})(?:/[^"']*)?["']""")
    hit = _first_file_matching(Path(root), ecosystem, [pattern])
    if hit is None:
        return None, "в проекте нет файлов на языке пакета"
    path, _ = hit
    if path is None:
        return False, f"ни один из путей ({', '.join(wanted)}) не импортируется в коде проекта"
    return True, f"импортируется в {path}"


class SymbolPresence(str, Enum):
    """What the search established."""

    CALLED = "called"
    CALL_UNCONFIRMED = "call_unconfirmed"
    REFERENCED = "referenced"
    ABSENT = "absent"
    NOT_SEARCHABLE = "not_searchable"
    NOT_DISTRIBUTED = "not_distributed"


@dataclass(slots=True)
class Hit:
    file: str
    line: int
    text: str
    in_tests: bool = False
    column: int = 0

    def __str__(self) -> str:
        return f"{self.file}:{self.line}" + (" (тест)" if self.in_tests else "")


@dataclass(slots=True)
class PresenceResult:
    presence: SymbolPresence
    symbol: str = ""
    hits: list[Hit] = field(default_factory=list)
    files_scanned: int = 0
    truncated: bool = False
    detail: str = ""

    @property
    def found(self) -> bool:
        return self.presence in (SymbolPresence.CALLED,
                                 SymbolPresence.CALL_UNCONFIRMED,
                                 SymbolPresence.REFERENCED)

    @property
    def only_in_tests(self) -> bool:
        """Every call site is test code, so nothing an attacker can reach."""
        return bool(self.hits) and all(hit.in_tests for hit in self.hits)

    @property
    def production_hits(self) -> list[Hit]:
        return [hit for hit in self.hits if not hit.in_tests]


def _strip_comments(text: str) -> str:
    """Blank the comments, keeping every line where it was."""
    text = _BLOCK_COMMENT.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    return "\n".join(_LINE_COMMENT.sub("", line) for line in text.splitlines())


_DECLARATION_LINE = re.compile(
    r"^\s*(?:@\w+\s*)*"
    r"(?:(?:public|protected|private|static|final|abstract|readonly|async|"
    r"export|default|func|function|def|fn|sub)\s+)*"
    r"(?:func|function|def|fn)\b"
    r"|^\s*func\s*\([^)]*\)\s*\w+\s*\("
    r"|^\s*(?:export\s+)?(?:const|let|var)\s+\w+\s*=\s*(?:async\s*)?"
    r"(?:function\b|\([^)]*\)\s*=>)",
    re.IGNORECASE,
)


def _declares_a_function(line: str) -> bool:
    return bool(_DECLARATION_LINE.match(line))


def _call_patterns(function: str) -> re.Pattern[str]:
    """Call syntax for the languages we scan, in one alternation."""
    name = re.escape(function)
    declaration = r"(?<!function )(?<!def )(?<!func )(?<!fn )"
    return re.compile(
        rf"(?:->|::|\.|\$)\s*{name}\s*\("
        rf"|{declaration}(?<![\w$>:.]){name}\s*\(",
        re.IGNORECASE,
    )


_UBIQUITOUS = {
    "__construct", "__destruct", "__invoke", "__toString", "__get", "__set",
    "clear", "close", "count", "create", "delete", "execute", "filter", "flush",
    "format", "get", "getattribute", "getname", "gettype", "getvalue", "handle",
    "init", "load", "log", "match", "merge", "open", "parse", "process", "read",
    "render", "reset", "resolve", "run", "save", "send", "set", "start", "stop",
    "update", "validate", "write",
}


def _is_ubiquitous(function: str) -> bool:
    return function.strip().lower() in _UBIQUITOUS


def _class_pattern(klass: str) -> re.Pattern[str]:
    """A class name, allowing the PHP namespace separator in front of it."""
    name = re.escape(klass)
    return re.compile(rf"(?<![\w$]){name}(?![\w])")


def _class_is_bound(klass: str, text: str) -> bool:
    """Is *this* class in scope, rather than the word appearing somewhere?"""
    name = re.escape(klass)
    qualified = rf"\\?(?:[\w\\]*\\)?{name}"
    binding = re.compile(
        rf"(?:^|\n)\s*(?:use|import|from)\s+[^\n;]*(?<![\w]){name}(?![\w])"
        rf"|(?<![\w$])new\s+{qualified}\s*\("
        rf"|(?<![\w$\\]){qualified}\s*::"
        rf"|(?::|\|)\s*{qualified}(?![\w])"
        rf"|(?<![\w$]){name}\s+\$[\w]+",
    )
    return bool(binding.search(text))


def _package_is_imported(package: str, text: str) -> bool:
    """Does this file bring the package in at all?"""
    if not package:
        return True
    name = package.strip()
    candidates = {re.escape(name)}
    alternation = "|".join(sorted(candidates))
    pattern = re.compile(
        rf"""(?:require\s*\(\s*['"](?:{alternation})(?:/[^'"]*)?['"]\s*\))"""
        rf"""|(?:from\s+['"](?:{alternation})(?:/[^'"]*)?['"])"""
        rf"""|(?:import\s+['"](?:{alternation})(?:/[^'"]*)?['"])"""
        rf"""|(?:^\s*(?:import|from)\s+(?:{alternation})\b)"""
        rf"""|(?:['"][^'"\s]*(?:{alternation})[^'"\s]*['"]\s*$)""",
        re.MULTILINE,
    )
    return bool(pattern.search(text))


_FILE_LISTS: dict[tuple[str, frozenset], tuple[list[Path], bool]] = {}


def _source_files(root: Path, suffixes: set[str]) -> tuple[list[Path], bool]:
    """First-party files of these types, listed once per run."""
    key = (str(root), frozenset(suffixes))
    if key in _FILE_LISTS:
        return _FILE_LISTS[key]

    files: list[Path] = []
    truncated = False
    for parent, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d.lower() not in _SKIP_DIRS and not d.lower().startswith("appsec-out")]
        for name in filenames:
            if len(files) >= _MAX_FILES:
                truncated = True
                break
            if Path(name).suffix.lower() in suffixes:
                files.append(Path(parent) / name)
        if truncated:
            break

    _FILE_LISTS[key] = (files, truncated)
    return files, truncated


_USE_ALIAS = re.compile(r"^\s*use\s+\\?([\w\\]+)\s+as\s+(\w+)\s*;", re.MULTILINE | re.IGNORECASE)


def _class_aliases(text: str) -> dict[str, str]:
    """`use Vendor\\Pkg\\Yaml as SfYaml;` → {"sfyaml": "yaml"}: the alias names that class."""
    return {alias.lower(): name.rpartition("\\")[2].lower() for name, alias in _USE_ALIAS.findall(text)}


def _call_on_this_class(line: str, call_re: re.Pattern[str], static_re: re.Pattern[str] | None,
                        klass: str, aliases: dict[str, str]) -> re.Match[str] | None:
    """The first call on the line that is not a static call naming a different class."""
    foreign: list[tuple[int, int]] = []
    if static_re is not None:
        own = {klass.lower(), "self", "static", "parent"}
        for named in static_re.finditer(line):
            short = named.group(1).rpartition("\\")[2].lower()
            if short not in own and aliases.get(short) != klass.lower():
                foreign.append((named.start(), named.end()))
    for match in call_re.finditer(line):
        if not any(start <= match.start() < end for start, end in foreign):
            return match
    return None


def find_symbol(
    root: Path | str,
    function: str = "",
    klass: str = "",
    file_hint: str = "",
    *,
    not_distributed: bool = False,
    max_hits: int = 25,
    ecosystem: str = "",
    package: str = "",
) -> PresenceResult:
    """Search `root` for a call to `function`, or a reference to `klass`."""
    label = f"{klass}::{function}" if klass and function else (function or klass or file_hint)
    if not_distributed:
        return PresenceResult(
            SymbolPresence.NOT_DISTRIBUTED, label,
            detail="уязвимый код не входит в устанавливаемый пакет",
        )
    if not (function or klass or file_hint):
        return PresenceResult(
            SymbolPresence.NOT_SEARCHABLE, "",
            detail="для этой CVE не определён уязвимый символ",
        )

    root = Path(root)
    if not root.exists():
        return PresenceResult(SymbolPresence.NOT_SEARCHABLE, label,
                              detail=f"путь {root} не существует")

    try:
        suffixes = get_source_suffixes([root], for_ecosystem=ecosystem)
    except DetectionError:
        suffixes = DEFAULT_SOURCE_SUFFIXES
    files, truncated = _source_files(root, suffixes)
    if not files:
        return PresenceResult(
            SymbolPresence.ABSENT, label, [], 0, truncated,
            detail=(f"в проекте нет файлов на языке пакета "
                    f"({', '.join(sorted(suffixes))}) — вызывать неоткуда"))
    call_re = _call_patterns(function) if function else None
    class_re = _class_pattern(klass) if klass else None
    static_re = (re.compile(rf"(?<![\w$\\])\\?((?:[A-Za-z_]\w*\\)*[A-Za-z_]\w*)\s*::\s*{re.escape(function)}\s*\(",
                            re.IGNORECASE)
                 if klass and function else None)
    tail = file_hint.lstrip("./").lower() if file_hint else ""

    calls: list[Hit] = []
    unbound: list[Hit] = []
    refs: list[Hit] = []
    for path in files:
        try:
            if path.stat().st_size > _MAX_BYTES:
                continue
            raw = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        rel = str(path.relative_to(root))
        if tail and rel.lower().endswith(tail):
            refs.append(Hit(rel, 1, f"файл совпадает с {file_hint}"))

        if function and function.lower() not in raw.lower() and not (klass and klass in raw):
            continue

        body = _strip_comments(raw)
        if klass:
            anchored = _class_is_bound(klass, body)
        else:
            anchored = _package_is_imported(package, body)
        in_tests = is_test(rel)
        aliases = _class_aliases(body) if static_re is not None else {}

        for number, line in enumerate(body.splitlines(), 1):
            if _declares_a_function(line):
                continue
            if call_re is not None and (match := _call_on_this_class(line, call_re, static_re, klass, aliases)):
                column = line.find(function, match.start()) if function else match.start()
                hit = Hit(rel, number, line.strip()[:160], in_tests,
                          column if column >= 0 else match.start())
                (calls if anchored else unbound).append(hit)
            elif class_re is not None and class_re.search(line):
                refs.append(Hit(rel, number, line.strip()[:160], in_tests))
            if len(calls) >= max_hits:
                break
        if len(calls) >= max_hits:
            break

    if calls:
        return PresenceResult(SymbolPresence.CALLED, label, calls[:max_hits],
                              len(files), truncated,
                              detail=f"вызов найден в {len(calls)} месте(ах)")
    if unbound:
        return PresenceResult(
            SymbolPresence.CALL_UNCONFIRMED, label, unbound[:max_hits],
            len(files), truncated,
            detail=(f"метод {function} вызывается, но класс объекта не подтверждён — "
                    f"{klass} не импортирован в этих файлах; вызов может идти через "
                    "интерфейс или контейнер"))
    if refs:
        detail = "символ упоминается, но вызова не найдено"
        if klass and function and _is_ubiquitous(function):
            detail = (f"имя {function} встречается, но класса {klass} нет в этих файлах — "
                      "совпадение по одному имени слишком общее, чтобы считать вызовом")
        return PresenceResult(SymbolPresence.REFERENCED, label, refs[:max_hits],
                              len(files), truncated, detail=detail)
    return PresenceResult(
        SymbolPresence.ABSENT, label, [], len(files), truncated,
        detail=(f"вызова {label} нет в {len(files)} файлах проекта; "
                "функция может вызываться внутри библиотеки"),
    )
