"""Step 3: is the vulnerable symbol actually present in this repository?

Strictly, and without a model. The question has an exact answer in the text of
the tree, so nothing here infers, weighs or guesses — it either points at a line
or reports that it found none.

Three rules keep the answer honest:

*A call, not a mention.* `matchesDomain` inside a comment, a changelog entry or
a string is not a use of it. Only call syntax counts, and comment bodies are
removed before matching.

*Our code, not the library's.* Every dependency's own source calls its own
internal functions; matching inside `vendor/` or `node_modules/` would report
every advisory as present. Those trees are excluded, and when a repository ships
no lockfile-installed tree at all the search is simply over first-party files.

*Absence is not a closure by itself.* Most vulnerable functions are library
internals that no application calls directly — the caller reaches them through
public API several frames up. So "not found" is reported as `ABSENT` and left
for the caller to interpret, never as "not vulnerable".
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

_INTERNAL_SEGMENT = re.compile(r"(?:^|/)internal(?:/|$)")

_SKIP_DIRS = {
    ".git", "vendor", "node_modules", "venv", ".venv", "target", "build",
    "dist", "__pycache__", ".idea", ".vscode", ".tox", ".mypy_cache",
}

_SUFFIXES = {".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py",
             ".go", ".rb", ".java", ".kt", ".cs"}

_ECOSYSTEM_SUFFIXES = {
    "composer": {".php"}, "packagist": {".php"}, "php": {".php"},
    "npm": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "node": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "javascript": {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"},
    "pypi": {".py"}, "python": {".py"}, "pip": {".py"},
    "go": {".go"}, "golang": {".go"},
    "maven": {".java", ".kt"}, "java": {".java", ".kt"},
    "nuget": {".cs"}, "rubygems": {".rb"}, "gem": {".rb"},
}

_TEST_PARTS = re.compile(
    r"(^|[\\/])(tests?|spec|specs|__tests__|testing|fixtures?|e2e)([\\/]|$)", re.I)
_TEST_FILE = re.compile(r"(Test|Spec)\.[a-z]+$|(^|[\\/])(test|spec)_", re.I)

_MAX_FILES = 8000
_MAX_BYTES = 600_000

_LINE_COMMENT = re.compile(r"(?://|#).*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def package_namespaces(ecosystem: str, package: str) -> list[str]:
    """How this package's code is named where it gets used.

    A composer package `guzzlehttp/guzzle` is written as `GuzzleHttp\\` in an
    import; an npm package is written as its own name. Both are what a file has
    to contain for the package to be in play at all.
    """
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
    return [name, name.rsplit("/", 1)[-1]]


def _first_file_matching(
    root: Path, ecosystem: str, patterns: "list[re.Pattern[str]]"
) -> "tuple[Path | None, int] | None":
    """First first-party file matching any pattern, as (relative path, index).

    `None` means the question could not be asked — no files of this language —
    which is a different answer from "asked and found nothing", reported as
    `(None, -1)`. Shared by the two "is it used" scans, which differ only in the
    pattern they carry and the sentence they write about the result.
    """
    suffixes = _ECOSYSTEM_SUFFIXES.get((ecosystem or "").strip().lower(), _SUFFIXES)
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


def package_is_used(root: Path | str, ecosystem: str, package: str) -> tuple[bool | None, str]:
    """Is this package referenced anywhere in first-party code at all?

    Deliberately coarse and deliberately conservative. A `true` says nothing on
    its own — the package is used, which the lockfile already implied. A `false`
    is the useful direction: nothing in the repository names this library, so no
    code path of ours enters it. Frameworks can still reach a package through a
    container or autoloading, so this is evidence rather than proof, and it is
    reported as such.
    """
    names = package_namespaces(ecosystem, package)
    if not names:
        return None, "имя пакета не разобрано"

    patterns = [re.compile(rf"(?<![\w\\]){re.escape(n)}(?![\w])", re.I) for n in names]
    hit = _first_file_matching(Path(root), ecosystem, patterns)
    if hit is None:
        return None, "в проекте нет файлов на языке пакета"
    path, index = hit
    if path is None:
        return False, f"ни одно из имён ({', '.join(names)}) не встречается в коде проекта"
    return True, f"{names[index]} встречается в {path}"


def import_path_used(
    root: Path | str, ecosystem: str, paths: "list[str] | tuple[str, ...]"
) -> tuple[bool | None, str]:
    """Is any of these exact import paths brought in by first-party code?

    Finer than `package_is_used`, and the difference is the whole verdict for a
    package-level advisory. A module can be present through one sub-package while
    the vulnerable one is never imported: `golang.org/x/crypto` is used via
    `bcrypt`, but `golang.org/x/crypto/openpgp` is a different import path and may
    be absent. Matching the module name would call that used; matching the path
    does not.

    A path matches itself or a deeper path under it (`openpgp/packet`), never a
    sibling (`bcrypt`), because the boundary after the path is a quote or a slash.
    """
    wanted = [p for p in paths if p and not _INTERNAL_SEGMENT.search(p)]
    if not wanted:
        if any(paths):
            # Go forbids importing a path with an `internal/` segment from
            # outside its subtree, so first-party code cannot name it however
            # much it uses the code: pgx's SQL-injection flaw lives in
            # `pgx/v5/internal/sanitize`, reached through the public API the
            # project does import. Absence proves nothing here, and reporting it
            # as absence closed a finding govulncheck could see being called.
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
    """What the search established. No value here means "safe"."""

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
    """Blank the comments, keeping every line where it was.

    Replacing a block comment with a single space collapses it, and every line
    after it is then reported one number too low — which was measured: a hit
    was reported at `ApplicationImageOption.php:16`, where the file holds a
    Doctrine attribute and nothing resembling the symbol. A verdict a reviewer
    cannot find in the named line is worse than no verdict.
    """
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
    re.I,
)


def _declares_a_function(line: str) -> bool:
    return bool(_DECLARATION_LINE.match(line))


def _call_patterns(function: str) -> re.Pattern[str]:
    """Call syntax for the languages we scan, in one alternation.

    A declaration is not a call, and they look alike: `public function login(`
    contains `login(`. Measured on an unseen project — a controller's own
    `login()` action was reported as a call to `Security::login` from
    symfony/security-bundle. Any project whose method happens to share a name
    with a vulnerable one would have been reported the same way.

    PHP method names are case-insensitive; the flag costs nothing elsewhere
    because the alternatives are anchored on the name itself.
    """
    name = re.escape(function)
    declaration = r"(?<!function )(?<!def )(?<!func )(?<!fn )"
    return re.compile(
        rf"(?:->|::|\.|\$)\s*{name}\s*\("
        rf"|{declaration}(?<![\w$>:.]){name}\s*\(",
        re.I,
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
    """A class name, allowing the PHP namespace separator in front of it.

    `use GuzzleHttp\\Cookie\\SetCookie;` is the ordinary way a class is named,
    so a backslash before it must not disqualify the match — only a word
    character or a sigil, which would make it part of a longer identifier.
    """
    name = re.escape(klass)
    return re.compile(rf"(?<![\w$]){name}(?![\w])")


def _class_is_bound(klass: str, text: str) -> bool:
    """Is *this* class in scope, rather than the word appearing somewhere?

    The weak form — the name occurring anywhere in the file — was measured to
    fail: `Request::create` was reported in a Doctrine entity because the word
    "Request" appeared in an unrelated context. What binds a class is an import,
    an instantiation, a static call or a type annotation, so those are what
    count.
    """
    name = re.escape(klass)
    binding = re.compile(
        rf"(?:^|\n)\s*(?:use|import|from)\s+[^\n;]*(?<![\w]){name}(?![\w])"
        rf"|(?<![\w$])new\s+\\?[\w\\]*{name}\s*\("
        rf"|(?<![\w$])\\?[\w\\]*{name}\s*::"
        rf"|(?::|\|)\s*\\?[\w\\]*{name}(?![\w])"
        rf"|(?<![\w$]){name}\s+\$[\w]+",
    )
    return bool(binding.search(text))


def _package_is_imported(package: str, text: str) -> bool:
    """Does this file bring the package in at all?

    The analogue of class binding for languages without one. `json5.push` in a
    file that never requires json5 is `Array.prototype.push`; the import is what
    makes the name belong to the library.

    Scoped names are matched by their full form, so `@scope/pkg` does not match
    a different `pkg`, and Go's module paths are matched on the last segment as
    well because that is what the identifier is called in code.
    """
    if not package:
        return True
    name = package.strip()
    tail = name.rsplit("/", 1)[-1]
    candidates = {re.escape(name)} | ({re.escape(tail)} if tail != name else set())
    alternation = "|".join(sorted(candidates))
    pattern = re.compile(
        rf"""(?:require\s*\(\s*['"](?:{alternation})(?:/[^'"]*)?['"]\s*\))"""
        rf"""|(?:from\s+['"](?:{alternation})(?:/[^'"]*)?['"])"""
        rf"""|(?:import\s+['"](?:{alternation})(?:/[^'"]*)?['"])"""
        rf"""|(?:^\s*(?:import|from)\s+(?:{alternation})\b)"""
        rf"""|(?:['"][^'"\s]*(?:{alternation})[^'"\s]*['"]\s*$)""",
        re.M,
    )
    return bool(pattern.search(text))


_FILE_LISTS: dict[tuple[str, frozenset], tuple[list[Path], bool]] = {}


def _source_files(root: Path, suffixes: set[str]) -> tuple[list[Path], bool]:
    """First-party files of these types, listed once per run.

    Pruned during the walk rather than filtered after it: `rglob` descends into
    `vendor/` and `node_modules/` before the skip test rejects what it found, and
    those trees are usually far larger than the first-party code they sit beside.

    Memoised per process — the same listing is asked for on every searched
    symbol and by both "is it used" scans, and the tree cannot change mid-run.
    Nothing is kept across runs; this is a pipeline, not a cache.
    """
    key = (str(root), frozenset(suffixes))
    if key in _FILE_LISTS:
        return _FILE_LISTS[key]

    files: list[Path] = []
    truncated = False
    for parent, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d.lower() not in _SKIP_DIRS]
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
    """Search `root` for a call to `function`, or a reference to `klass`.

    `file_hint` is the path inside the *package*, used only when the advisory
    names no function; it is matched against the tail of first-party paths, which
    is how a vendored or copied file would show up.
    """
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

    suffixes = _ECOSYSTEM_SUFFIXES.get(ecosystem.strip().lower(), _SUFFIXES)
    files, truncated = _source_files(root, suffixes)
    if not files:
        return PresenceResult(
            SymbolPresence.ABSENT, label, [], 0, truncated,
            detail=(f"в проекте нет файлов на языке пакета "
                    f"({', '.join(sorted(suffixes))}) — вызывать неоткуда"))
    call_re = _call_patterns(function) if function else None
    class_re = _class_pattern(klass) if klass else None
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
        in_tests = bool(_TEST_PARTS.search(rel) or _TEST_FILE.search(rel))

        for number, line in enumerate(body.splitlines(), 1):
            if _declares_a_function(line):
                continue
            if call_re is not None and (match := call_re.search(line)):
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
