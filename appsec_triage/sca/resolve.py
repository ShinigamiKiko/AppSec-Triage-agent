"""Step 2, live: the advisory's vulnerable symbol, extracted by the model."""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ..prompts import registry
from . import cassette, registries
from .advisories import Advisory

log = logging.getLogger(__name__)

_TIMEOUT = 45
_MAX_DIFF = 60_000
_SKIP_IN_DIFF = re.compile(
    r"(^|/)(tests?|spec|fixtures?|samples?|docs?)/|CHANGELOG|\.md$", re.IGNORECASE)
_NOT_SHIPPED = re.compile(r"(^|/)(samples?|tests?|docs?|examples?)/", re.IGNORECASE)

SYSTEM = registry.step("symbol")

SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["vulnerable_function", "vulnerable_class", "vulnerable_file",
                 "what_changed", "evidence", "why", "precondition",
                 "precondition_quote", "precondition_tokens",
                 "precondition_where", "precondition_decidable"],
    "properties": {
        "vulnerable_function": {"type": "string"},
        "vulnerable_class": {"type": "string"},
        "vulnerable_file": {"type": "string"},
        "what_changed": {"type": "string"},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
        "precondition": {"type": "string"},
        "precondition_quote": {"type": "string"},
        "precondition_tokens": {"type": "array", "items": {"type": "string"}},
        "precondition_where": {"type": "string"},
        "precondition_decidable": {"type": "boolean"},
    },
}


@dataclass(slots=True)
class VulnerableSymbol:
    """What to look for in a repository, for one advisory."""

    advisory_id: str
    package: str = ""
    function: str = ""
    klass: str = ""
    file: str = ""
    grounded_in_fix: bool = False
    listed_in_advisory: bool = False
    named_by_model: bool = False
    candidates: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    package_paths: tuple[str, ...] = field(default_factory=tuple)
    what_changed: str = ""
    quotes_a_changed_line: bool = False
    declared_in_installed: bool | None = None
    existed_before_fix: bool | None = None
    confirmed_in_source: bool = False

    @property
    def strength(self) -> str:
        """How well the name is corroborated, in words a report can print."""
        if not self.function:
            return self.note or "символ не определён"
        if self.listed_in_advisory:
            listed = ", ".join(f"{k}.{f}" if k else f for f, k in self.candidates[:6])
            return f"перечислено в advisory как уязвимые символы: {listed}"
        if self.named_by_model:
            listed = ", ".join(f for f, _ in self.candidates[:6])
            return (f"публичные точки входа названы моделью (ничем не подтверждены, "
                    f"взяты как зацепка для поиска): {listed}")
        if self.declared_in_installed and self.grounded_in_fix:
            return "подтверждено дважды: фикс правил эту функцию, и она есть в установленной версии"
        if self.declared_in_installed:
            return "функция есть в установленной версии, но фикс её не упоминает"
        if self.grounded_in_fix and self.declared_in_installed is None:
            return "фикс правил эту функцию; установленной версии на диске нет, сверить не с чем"
        if self.grounded_in_fix:
            return "фикс правил эту функцию"
        return "имя ничем не подтверждено"
    not_distributed: bool = False
    aliases: tuple[str, ...] = field(default_factory=tuple)
    evidence: str = ""
    note: str = ""
    steps: int = 0
    precondition: str = ""
    precondition_quote: str = ""
    precondition_problem: str = ""
    precondition_tokens: tuple[str, ...] = field(default_factory=tuple)
    precondition_where: str = ""
    precondition_decidable: bool = True
    scope: str = ""
    advisory_context: str = ""
    required_actions: tuple[str, ...] = field(default_factory=tuple)
    search_targets: tuple[str, ...] = field(default_factory=tuple)
    source_stage: str = ""

    @property
    def usable(self) -> bool:
        return bool(self.function or self.file) and not self.not_distributed

    def __str__(self) -> str:
        if self.function:
            return f"{self.klass}::{self.function}" if self.klass else self.function
        return self.file or "(нет символа)"


def _fetch(url: str) -> str | None:
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "appsec-triage"})
        with cassette.urlopen(request, timeout=_TIMEOUT) as response:
            return response.read(4 * 1024 * 1024).decode("utf-8", errors="replace")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.debug("could not fetch %s: %s", url, exc)
        return None


def _source_only(diff: str) -> str:
    """Whole files, tests and docs dropped — never a diff cut mid-file."""
    files, current, skip = [], [], False
    for line in diff.splitlines():
        if line.startswith("diff --git"):
            if current and not skip:
                files.append("\n".join(current))
            current, skip = [line], False
        else:
            if line.startswith("+++ b/"):
                skip = bool(_SKIP_IN_DIFF.search(line))
            current.append(line)
    if current and not skip:
        files.append("\n".join(current))

    out = ""
    for chunk in files:
        if len(out) + len(chunk) > _MAX_DIFF:
            break
        out += chunk + "\n"
    return out


def fix_diff(advisory: Advisory) -> tuple[str, str]:
    """The best fix reference that yields a readable diff, and its url."""
    for url in advisory.fix_refs[:4]:
        raw = _fetch(url if url.endswith((".diff", ".patch")) else url + ".diff")
        if not raw or len(raw) < 120:
            continue
        trimmed = _source_only(raw)
        if trimmed.strip():
            return trimmed, url
    return "", ""


def _declaration_pattern(name: str) -> re.Pattern[str]:
    """How the languages we scan spell "this function is defined here"."""
    escaped = re.escape(name)
    return re.compile(
        rf"(?:function\s+&?\s*{escaped}\s*\()"
        rf"|(?:\b(?:async\s+)?def\s+{escaped}\s*\()"
        rf"|(?:\b{escaped}\s*[:=]\s*(?:async\s+)?function\b)"
        rf"|(?:\b{escaped}\s*[:=]\s*(?:async\s+)?\([^)]*\)\s*=>)"
        rf"|(?:\bfunc\s+(?:\([^)]*\)\s*)?{escaped}\s*\()",
        re.IGNORECASE,
    )


def _quotes_a_changed_line(evidence: str | None, diff: str) -> bool:
    """Is the quote a line the fix added or removed, rather than context?"""
    quote = (evidence or "").strip()
    if not diff:
        return True
    if not quote:
        return False
    if quote[0] not in "+-":
        return any(line[1:].strip() == quote
                   for line in diff.splitlines()
                   if line[:1] in "+-" and not line.startswith(("+++", "---")))
    return quote in diff


def _quotes_the_advisory(quote: str | None, text: str) -> bool:
    """Is this quote actually in the advisory, rather than a plausible summary?"""
    wanted = " ".join((quote or "").split())
    if not wanted:
        return False
    return " ".join((text or "").split()).lower().find(wanted.lower()) >= 0


def _existed_before_fix(name: str, diff: str) -> bool | None:
    """Did this function exist before the fix, judged from the diff alone?"""
    if not name or not diff:
        return None

    pattern = re.compile(rf"(?<![\w]){re.escape(name)}(?![\w])")
    before = added = False
    for line in diff.splitlines():
        if line.startswith(("+++", "---", "diff --git", "index ")):
            continue
        if not pattern.search(line):
            continue
        if line.startswith("+"):
            added = True
        else:
            before = True
    if before:
        return True
    return False if added else None


def _in_text(name: str, text: str) -> bool:
    """Whole-word occurrence, so `read` does not match `readData`."""
    if not name or not text:
        return False
    return bool(re.search(rf"(?<![\w]){re.escape(name)}(?![\w])", text))


def _declared(name: str, files: dict[str, str]) -> list[str]:
    if not name:
        return []
    pattern = _declaration_pattern(name)
    return [path for path, text in files.items() if pattern.search(text)]


_MAX_LISTED = 40
_IDENTIFIER = re.compile(r"^[A-Za-z_$][\w$]*$")
_LOOKS_LIKE_A_FILE = re.compile(
    r"\.(?:js|mjs|cjs|ts|php|py|go|rb|java|json|min\.js)$", re.IGNORECASE)

_JS_DIFF_DECL = re.compile(
    r"\bfunction\s*\*?\s*([A-Za-z_$][\w$]*)\s*\(|"
    r"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?(?:function\b|\([^)]*\)\s*=>)|"
    r"\b([A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?function\b|"
    r"\b([A-Za-z_$][\w$]*)\s*\([^)]*\)\s*\{"
)
_JS_DIFF_SKIP = {
    "if", "for", "while", "switch", "catch", "return", "function", "constructor",
    "get", "set", "async", "then", "map", "filter", "reduce",
}


_DIFF_DECLARATIONS = {
    "npm": _JS_DIFF_DECL,
    "node": _JS_DIFF_DECL,
    "javascript": _JS_DIFF_DECL,
    "yarn": _JS_DIFF_DECL,
    "python": re.compile(r"\b(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("),
    "pypi": re.compile(r"\b(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\("),
    "php": re.compile(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\("),
    "composer": re.compile(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\("),
    "packagist": re.compile(r"\bfunction\s+&?\s*([A-Za-z_]\w*)\s*\("),
    "go": re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "golang": re.compile(r"\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\("),
    "ruby": re.compile(r"\bdef\s+([A-Za-z_]\w*[!?=]?)"),
    "rubygems": re.compile(r"\bdef\s+([A-Za-z_]\w*[!?=]?)"),
    "java": re.compile(r"\b(?:class|interface|enum)\s+([A-Za-z_]\w*)|"
                        r"\b([A-Za-z_]\w*)\s*\([^)]*\)\s*\{"),
    "kotlin": re.compile(r"\b(?:class|interface|object)\s+([A-Za-z_]\w*)|"
                          r"\bfun\s+([A-Za-z_]\w*)\s*\("),
}


def _diff_symbols(diff: str, ecosystem: str) -> list[str]:
    """Extract pre-existing function/class names from a fix diff."""
    pattern = _DIFF_DECLARATIONS.get((ecosystem or "").strip().lower())
    if not diff or pattern is None:
        return []
    names: list[str] = []
    chunks = [line for line in diff.splitlines()
              if not line.startswith(("+++", "---", "diff --git", "index ", "+"))]
    for line in chunks:
        text = line.removeprefix("-")
        context = text.split("@@", 1)[-1]
        for match in pattern.finditer(context):
            name = next((group for group in match.groups() if group), "")
            if (name and name not in _JS_DIFF_SKIP and name not in names
                    and _existed_before_fix(name, diff) is not False):
                names.append(name)
            if len(names) >= _MAX_LISTED:
                return names
    return names


def _candidate_symbol(advisory: Advisory, names: list[str]) -> VulnerableSymbol | None:
    """Turn deterministic npm names into explicitly unconfirmed search candidates."""
    names = [name for name in names if _IDENTIFIER.match(name)]
    if not names or len(names) > _MAX_LISTED:
        return None
    symbol = VulnerableSymbol(
        advisory_id=advisory.advisory_id, package=advisory.package,
        aliases=tuple(advisory.aliases), function=names[0],
        candidates=tuple((name, "") for name in names),
        package_paths=tuple(advisory.import_paths),
        evidence=f"advisory/diff search candidates: {', '.join(names[:8])}"[:300],
        source_stage="diff",
    )
    symbol.note = ("кандидаты извлечены из текста advisory или fix diff; "
                   "наличие вызова в проекте проверяется отдельно")
    return symbol

_LAST_RESORT = registry.step("symbol-last-resort")

_LAST_RESORT_SCHEMA = {
    "type": "object",
    "required": ["names"],
    "properties": {
        "names": {"type": "array", "items": {"type": "string"}},
        "klass": {"type": "string"},
        "why": {"type": "string"},
    },
}


def _carry_context(base: VulnerableSymbol, fallback: VulnerableSymbol) -> VulnerableSymbol:
    """Move what the model established onto a symbol that replaced its name."""
    fallback.precondition = base.precondition
    fallback.precondition_quote = base.precondition_quote
    fallback.precondition_problem = base.precondition_problem
    fallback.precondition_tokens = base.precondition_tokens
    fallback.precondition_where = base.precondition_where
    fallback.precondition_decidable = base.precondition_decidable
    fallback.what_changed = base.what_changed or fallback.what_changed
    fallback.scope = base.scope or fallback.scope
    fallback.advisory_context = base.advisory_context or fallback.advisory_context
    fallback.required_actions = base.required_actions or fallback.required_actions
    fallback.search_targets = base.search_targets or fallback.search_targets
    fallback.source_stage = base.source_stage or fallback.source_stage
    if base.note:
        fallback.note = f"{base.note}; {fallback.note}"
    return fallback


def _named_candidates(advisory: Advisory) -> VulnerableSymbol | None:
    """The description's own function names, as things to search for."""
    names = [n for n in advisory.named_symbols if n]
    if not names or len(names) > _MAX_LISTED:
        return None

    symbol = VulnerableSymbol(
        advisory_id=advisory.advisory_id, package=advisory.package,
        aliases=tuple(advisory.aliases), function=names[0],
        candidates=tuple((name, "") for name in names),
        package_paths=tuple(advisory.import_paths),
        evidence=f"названы в описании: {', '.join(names[:8])}"[:300],
        source_stage="advisory",
    )
    symbol.note = ("имена взяты из описания advisory, а не из курируемого списка — "
                   f"ищем: {', '.join(names[:6])}")
    return symbol


def _listed_symbols(advisory: Advisory) -> VulnerableSymbol | None:
    """The advisory's own symbol list, turned into things to search for."""
    prefix = (advisory.package or "").strip("/")
    candidates: list[tuple[str, str]] = []
    foreign = 0
    for entry in advisory.symbols:
        cut = entry.find(".", entry.rfind("/") + 1)
        path, name = (entry[:cut], entry[cut + 1:]) if cut > 0 else ("", entry)
        if prefix and not (path == prefix or path.startswith(prefix + "/")):
            foreign += 1
            continue
        klass, _, function = name.rpartition(".")
        if not function or not function[0].isupper():
            continue
        if klass and not klass[0].isupper():
            klass = ""
        pair = (function, klass)
        if pair not in candidates:
            candidates.append(pair)

    if not candidates or len(candidates) > _MAX_LISTED:
        log.debug("%s: перечислено %d символов, использовать нельзя",
                  advisory.advisory_id, len(advisory.symbols))
        return None

    function, klass = candidates[0]
    symbol = VulnerableSymbol(
        advisory_id=advisory.advisory_id, package=advisory.package,
        aliases=tuple(advisory.aliases), function=function, klass=klass,
        candidates=tuple(candidates), listed_in_advisory=True, grounded_in_fix=True,
        package_paths=tuple(advisory.import_paths),
        evidence=f"ecosystem_specific.imports: {', '.join(advisory.symbols[:8])}"[:300],
        source_stage="osv",
    )
    symbol.note = symbol.strength
    if foreign:
        symbol.note += (f"; ещё {foreign} символов принадлежат другим модулям "
                        "и в поиск не берутся")
    return symbol


class SymbolResolver:
    """Advisory in, symbol out."""

    def __init__(self, client, *, roots: list[Path] | None = None) -> None:
        self._client = client
        self._roots = [Path(r) for r in (roots or [])]
        self._sources: dict[tuple[str, str, str], dict[str, str]] = {}

    def _source_for(self, ecosystem: str, package: str, version: str = "") -> dict[str, str]:
        """The installed package, read once per run and only when it is there."""
        key = (ecosystem.lower(), package.lower(), version)
        cached = self._sources.get(key)
        if cached:
            return cached
        for root in self._roots:
            files = registries.package_source(ecosystem, package, version, root)
            if files:
                self._sources[key] = files
                return files
        return {}

    def extract_context(self, advisory: Advisory, version: str = "") -> VulnerableSymbol | None:
        """Run only the advisory-context fallback, without project SCA or verdicts."""
        diff, diff_url = fix_diff(advisory)
        return self._context_resort(advisory, version, diff, diff_url)

    def _ask(self, user: str) -> dict:
        try:
            return json.loads(self._client.complete(SYSTEM, user, json_schema=SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - provider/schema failures are intentionally fail-soft
            log.warning("symbol extraction failed: %s", exc)
            return {"vulnerable_function": "", "vulnerable_class": "",
                    "vulnerable_file": "", "evidence": "", "why": f"ошибка модели: {exc}"}

    @staticmethod
    def _name(answer: dict) -> str:
        return (answer.get("vulnerable_function") or "").split("::")[-1].strip().rstrip("()")

    def _last_resort(self, advisory: Advisory, version: str) -> VulnerableSymbol | None:
        """Ask the model to name the package's public entry points."""
        if self._client is None:
            return None
        prompt = "\n".join([
            f"Package: {advisory.package} ({advisory.ecosystem})",
            f"Installed version: {version or 'unknown'}",
            f"Advisory: {advisory.advisory_id}",
            f"Summary: {advisory.summary}", "",
            "=== ADVISORY TEXT ===",
            advisory.details or "(нет текста)",
        ])
        try:
            answer = json.loads(self._client.complete(
                _LAST_RESORT, prompt, json_schema=_LAST_RESORT_SCHEMA).text)
        except Exception as exc:  # noqa: BLE001 - one dead call, not the run
            log.warning("last-resort naming failed for %s: %s", advisory.advisory_id, exc)
            return None

        klass = (answer.get("klass") or "").split("\\")[-1].strip()
        names: list[str] = []
        for value in answer.get("names") or []:
            name = str(value).split("::")[-1].split(".")[-1].strip().rstrip("()")
            if name and _IDENTIFIER.match(name) and name not in names:
                names.append(name)
        if not names:
            return None

        symbol = VulnerableSymbol(
            advisory_id=advisory.advisory_id, package=advisory.package,
            aliases=tuple(advisory.aliases), function=names[0], klass=klass,
            candidates=tuple((name, klass) for name in names[:6]),
            package_paths=tuple(advisory.import_paths), named_by_model=True,
            evidence=(answer.get("why") or "")[:300],
            source_stage="last_resort",
        )
        symbol.note = symbol.strength
        return symbol

    def _context_resort(
        self, advisory: Advisory, version: str, diff: str, diff_url: str,
    ) -> VulnerableSymbol | None:
        """Ask the model to recover the advisory context when extraction stalled."""
        if self._client is None:
            return None
        schema = {
            "type": "object", "additionalProperties": False,
            "required": ["scope", "symbols", "file", "what_changed", "preconditions",
                          "required_actions", "search_targets", "evidence", "unresolved"],
            "properties": {
                "scope": {"type": "string", "enum": [
                    "function", "file", "package", "configuration", "action", "unknown"]},
                "symbols": {"type": "array", "items": {"type": "object",
                    "additionalProperties": False, "required": ["name", "class", "file", "evidence"],
                    "properties": {"name": {"type": "string"}, "class": {"type": "string"},
                                   "file": {"type": "string"}, "evidence": {"type": "string"}}}},
                "file": {"type": "string"},
                "what_changed": {"type": "string"},
                "preconditions": {"type": "array", "items": {"type": "string"}},
                "required_actions": {"type": "array", "items": {"type": "string"}},
                "search_targets": {"type": "array", "items": {"type": "string"}},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "unresolved": {"type": "array", "items": {"type": "string"}},
            },
        }
        prompt = "\n".join([
            "Extract factual context from this dependency advisory for a later code search.",
            "Do not decide whether the scanned application is affected.",
            "Do not recommend upgrading the package.",
            "If the whole package is affected, use scope=package. If exploitation requires an action",
            "or runtime setting, put it in required_actions or preconditions.",
            ("Every evidence item must be copied verbatim from the advisory or diff. "
            "Never paraphrase evidence."),
            f"Advisory IDs: {advisory.advisory_id}, {', '.join(advisory.aliases)}",
            f"Package: {advisory.package} ({advisory.ecosystem})",
            f"Language hint: {advisory.ecosystem or 'unknown'}",
            f"Installed version: {version or 'unknown'}",
            f"References: {', '.join(advisory.fix_refs) or 'none'}",
            f"Fix URL: {diff_url or 'none'}", "",
            "=== ADVISORY SUMMARY ===", advisory.summary or "(none)",
            "=== ADVISORY DETAILS ===", advisory.details or "(none)",
            "=== FIX DIFF ===", diff or "(not available)",
        ])
        try:
            answer = json.loads(self._client.complete(
                "You extract dependency advisory context only.", prompt, json_schema=schema).text)
        except Exception as exc:  # noqa: BLE001 - fallback must not break triage
            log.warning("advisory context extraction failed for %s: %s", advisory.advisory_id, exc)
            return None

        symbols = [item for item in answer.get("symbols") or [] if isinstance(item, dict)]
        names = []
        for item in symbols:
            name = str(item.get("name") or "").split("::")[-1].split(".")[-1].strip().rstrip("()")
            if name and _IDENTIFIER.match(name) and name not in names:
                names.append(name)
        targets = []
        for value in answer.get("search_targets") or []:
            value = str(value).strip()
            if value and len(value) <= 160 and value not in targets:
                targets.append(value)
        for name in names:
            if name not in targets:
                targets.append(name)
        scope = str(answer.get("scope") or "unknown")
        file = str(answer.get("file") or "").strip()
        source_text = f"{advisory.text}\n{diff}"
        raw_evidence = list(answer.get("evidence") or [])
        raw_evidence.extend(str(item.get("evidence") or "") for item in symbols)
        evidence = [
            str(value).strip() for value in raw_evidence
            if str(value).strip() and " ".join(str(value).split()).lower()
            in " ".join(source_text.split()).lower()
        ]
        preconditions = [str(x).strip() for x in answer.get("preconditions") or [] if str(x).strip()]
        actions = tuple(str(x).strip() for x in answer.get("required_actions") or [] if str(x).strip())
        if not names and scope == "function":
            scope = "unknown"
        if names and scope == "package":
            scope = "function"
        klass = (str(symbols[0].get("class") or "").split("\\")[-1].strip()
                 if symbols else "")
        if klass.lower() in {"function", "method", "class", "unknown", "none"}:
            klass = ""
        symbol = VulnerableSymbol(
            advisory_id=advisory.advisory_id, package=advisory.package,
            aliases=tuple(advisory.aliases), function=names[0] if names else "",
            klass=klass, file=file,
            candidates=tuple((name, "") for name in names),
            package_paths=tuple(advisory.import_paths),
            scope=scope,
            advisory_context=(str(answer.get("what_changed") or "").strip()[:500]
                              + ("; unresolved: " + "; ".join(map(str, answer.get("unresolved") or []))
                                 if answer.get("unresolved") else "")),
            required_actions=actions,
            search_targets=tuple(targets[:20]),
            source_stage="llm",
            evidence="; ".join(evidence)[:500],
            what_changed=str(answer.get("what_changed") or "").strip()[:300],
        )
        symbol.precondition = "; ".join(preconditions)[:300]
        symbol.note = (f"контекст advisory извлечён агентом: scope={scope}; "
                       f"искать: {', '.join(targets[:12]) or 'не определено'}")
        return symbol

    def resolve(self, advisory: Advisory, version: str = "") -> VulnerableSymbol:
        base = VulnerableSymbol(
            advisory_id=advisory.advisory_id, package=advisory.package,
            aliases=tuple(advisory.aliases),
            package_paths=tuple(advisory.import_paths),
        )
        if advisory.symbols:
            listed = _listed_symbols(advisory)
            if listed is not None:
                return listed
        if advisory.import_paths and not advisory.symbols and not advisory.fix_refs:
            context = self._context_resort(advisory, version, "", "")
            if context is not None:
                return context
            base.note = ("уязвим весь пакет, без конкретной функции — "
                         "решается по факту импорта уязвимого пути")
            return base
        if not advisory.usable:
            context = self._context_resort(advisory, version, "", "")
            if context is not None:
                return context
            base.note = advisory.problem or "advisory без текста и без ссылки на фикс"
            return base

        diff, diff_url = fix_diff(advisory)
        diff_names = _diff_symbols(diff, advisory.ecosystem)
        prompt = [f"Advisory: {advisory.advisory_id}", f"Package: {advisory.package}",
                  f"Vulnerable version: {version or 'unknown'}",
                  f"Summary: {advisory.summary}", "", "=== ADVISORY TEXT ===",
                   advisory.details or "(нет текста)"]
        if diff:
            prompt += ["", f"=== FIX DIFF ({diff_url}) ===", diff]
        if diff_names:
            prompt += ["", "=== SEARCH CANDIDATES FROM FIX DIFF ===",
                       ", ".join(diff_names),
                       ("Use these only as candidates for repository search. "
                        "Do not treat them as proof that the application is affected.")]
        user = "\n".join(prompt)

        answer = self._ask(user)
        name = self._name(answer)
        steps = 1

        grounded = _in_text(name, diff) or _in_text(name, advisory.text)
        changed = _quotes_a_changed_line(answer.get("evidence"), diff)

        if name and diff and not (grounded and changed):
            steps = 2
            problem = ("appears neither in the fix nor in the advisory text"
                       if not grounded else
                       "is quoted from a line the fix did not touch")
            answer = self._ask(
                user + f"\n\n=== CORRECTION ===\n`{name}` {problem}. A fix changes the "
                "vulnerable function's own code, so quote a line that starts with `+` "
                "or `-` from inside it. A function that appears only in unchanged "
                "context is the one that was bypassed, not the one that was wrong. "
                "Name that function, or return an empty `vulnerable_function`.")
            name = self._name(answer)
            grounded = _in_text(name, diff) or _in_text(name, advisory.text)
            changed = _quotes_a_changed_line(answer.get("evidence"), diff)

        if name and _LOOKS_LIKE_A_FILE.search(name):
            answer["vulnerable_file"] = answer.get("vulnerable_file") or name
            name = ""

        klass = (answer.get("vulnerable_class") or "").split("\\")[-1].strip()
        path = (answer.get("vulnerable_file") or "").strip()

        base.function = name
        base.klass = klass
        base.file = path
        base.evidence = (answer.get("evidence") or "")[:300]
        if diff_names:
            all_names = [name] + [candidate for candidate in diff_names if candidate != name]
            base.candidates = tuple((candidate, "") for candidate in all_names)
            base.source_stage = "diff"
        installed: dict[str, str] = {}
        if name and registries.supported(advisory.ecosystem):
            installed = self._source_for(advisory.ecosystem, advisory.package, version)
        declared = bool(_declared(name, installed)) if installed else None
        existed = _existed_before_fix(name, diff)

        base.steps = steps
        base.grounded_in_fix = bool(name) and grounded
        base.what_changed = (answer.get("what_changed") or "").strip()[:300]
        base.quotes_a_changed_line = bool(name) and changed
        base.declared_in_installed = declared
        base.existed_before_fix = existed
        condition = (answer.get("precondition") or "").strip()[:300]
        quote = (answer.get("precondition_quote") or "").strip()
        if condition and not _quotes_the_advisory(quote, advisory.text):
            base.precondition_problem = (
                f"условие «{condition[:80]}» отброшено: в тексте advisory его нет "
                "дословно, а формулировка модели меняется от прогона к прогону")
            condition = ""

        base.precondition = condition
        base.precondition_quote = quote if condition else ""
        base.precondition_tokens = tuple(
            str(t).strip() for t in (answer.get("precondition_tokens") or []) if str(t).strip()
        ) if condition else ()
        base.precondition_where = (
            (answer.get("precondition_where") or "").strip()[:200] if condition else "")
        base.precondition_decidable = bool(answer.get("precondition_decidable", True))

        if name and existed is False:
            base.note = (f"{name} появляется в фиксе только в добавленных строках — "
                         "этой функции нет в уязвимой версии, искать по ней нечего")
            base.function = ""
            base.klass = ""
        elif name and declared is False:
            base.note = (f"{name} не объявлен в {advisory.package}@{version}, "
                         "как он установлен в проекте — искать по нему нельзя")
            base.function = ""
            base.klass = ""
        elif name and diff and not grounded:
            base.note = (f"{name} не встречается ни в коммите с исправлением, ни в "
                         "тексте advisory — имя не подтверждено, поиск по нему не ведётся")
            base.function = ""
            base.klass = ""
        elif name and diff and not changed:
            base.note = (f"цитата по {name} взята из строки, которую фикс не менял — "
                         "похоже на обойдённый валидатор, а не на уязвимую функцию")
            base.function = ""
            base.klass = ""
        elif name:
            base.note = base.strength

        if not name and path and _NOT_SHIPPED.search(path):
            base.not_distributed = True
            base.note = f"{path} — путь, который менеджер пакетов не устанавливает"
        if not name and not path:
            base.note = base.note or (answer.get("why") or "")[:200]

        if not base.function and not base.not_distributed:
            context = self._context_resort(advisory, version, diff, diff_url)
            if context is not None and (context.function or context.file or context.scope != "unknown"):
                return _carry_context(base, context)

        if not base.function and not base.not_distributed:
            names = list(advisory.named_symbols)
            for candidate in diff_names:
                if candidate not in names:
                    names.append(candidate)
            named = _candidate_symbol(advisory, names) if diff_names else _named_candidates(advisory)
            if named is not None:
                return _carry_context(base, named)

        if not base.function and not base.not_distributed:
            guessed = self._last_resort(advisory, version)
            if guessed is not None:
                return _carry_context(base, guessed)
        return base
