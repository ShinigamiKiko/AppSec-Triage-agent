"""Step 2, live: the advisory's vulnerable symbol, extracted by the model.

Nothing is prepared in advance. For a package the scanner reports, the databases
are queried, the fix the advisory points at is fetched, and the model reads both
to name the one function whose code was wrong. The answer is then checked
against the published source of the affected version, which is the part that
makes it usable: a name that is not declared in the code the project installs
cannot be found in that project either.

Three failure modes were measured while building this, and each is handled here
rather than left to the prompt:

*The bypassed validator.* Advisory prose names the check that was evaded far
more often than the caller that misused it. Naming the validator detects
nothing — the patched version calls it too — so the rule is stated explicitly
and was verified to change the answer on the Twig path-traversal advisory.

*The symbol introduced by the fix.* A new helper cannot exist in the vulnerable
version, so it is worthless for detection. This is caught by the source check,
not by asking the model to be careful: `findCharSet` passed every textual test
and is absent from the affected release.

*The library's own naming convention.* An advisory says the `column` filter; the
release declares `twig_array_column`. The model cannot guess that, so when a
name is absent the real declarations are offered back and it picks from them.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import registries
from .advisories import Advisory
from .source_cache import PackageSourceCache, SourceSnapshot

log = logging.getLogger(__name__)

_TIMEOUT = 45
_MAX_DIFF = 60_000
_SKIP_IN_DIFF = re.compile(
    r"(^|/)(tests?|spec|fixtures?|samples?|docs?)/|CHANGELOG|\.md$", re.I)
_DECL = re.compile(
    r"(?:function\s+&?\s*|(?:async\s+)?def\s+|func\s+)([A-Za-z_][A-Za-z0-9_]*)\s*\("
    r"|([A-Za-z_][A-Za-z0-9_]*)\s*[:=]\s*(?:async\s+)?(?:function\b|\([^)]*\)\s*=>)")
_NOT_SHIPPED = re.compile(r"(^|/)(samples?|tests?|docs?|examples?)/", re.I)

SYSTEM = """You identify what a scanner should look for in the source of a
vulnerable library version, given a known vulnerability.

You get the advisory text, and usually the commit that fixed it. Name the
**one** function or method whose own code was wrong in the *vulnerable* version.

Two traps, both common:

1. **The bypassed validator.** Advisory prose usually names the check that was
   evaded — "`validateName` could be bypassed", "the sanitiser did not catch".
   That function is not the flaw. The flaw is in the **caller** that called it
   wrongly, too late, or not at all. The patched version still calls the
   validator, so naming it detects nothing.
2. **The new helper.** A fix often adds a function, or moves code into one. A
   function introduced by the fix does not exist in the vulnerable version, so
   it can never be found there. Name the function the code came **from**.

Ask yourself: in the *unpatched* file, which function's body would I read to see
the mistake? That is the answer.

If the flaw is not inside a library function at all — a bundled sample script, a
default property value, a configuration entry — leave `vulnerable_function`
empty and put the affected path in `vulnerable_file` instead. A file is a valid
answer; an empty answer with neither is not.

Many advisories only bite under a condition — user-supplied templates are
rendered, external XML entities are enabled, untrusted data is deserialised, a
non-default option is on. State that condition too, and say whether a
repository could settle it.

Rules:
- `vulnerable_function` is exactly one name, no class prefix, no parentheses.
- `vulnerable_class` is the class it is declared in, if known, else "".
- `vulnerable_file` is a path inside the package, or "".
- `what_changed` says in one sentence what the fix made the code do differently
  — the behaviour, not the name. "The domain comparison became
  case-insensitive", not "matchesDomain was fixed". If you cannot say what
  changed, you have not identified the flaw.
- `evidence`, when a diff is shown, must be a line the fix **added or removed**
  — one that starts with `+` or `-`, copied character-for-character including
  that sign. A context line is not evidence: a validator that was merely
  bypassed appears in the diff untouched, and quoting it is how the wrong
  function gets named. Without a diff, quote the advisory text.
- Never guess a name. Empty is better than plausible.
- `precondition` is one sentence, or "" when the flaw needs no particular
  configuration to be exploitable.
- `precondition_tokens` are concrete strings that would appear in a codebase
  where the condition holds: a function name, an option key, a class. Not prose,
  not regular expressions. Empty if none is specific enough to search for.
- `precondition_where` names where a person should look — a config file kind, a
  framework setting, a deployment manifest.
- `precondition_decidable` is false when the answer lives outside the source
  tree: an environment variable, a runtime default, an operator's choice, a
  calling service. Say false when unsure; a wrong "true" ends in a wrong
  closure, while a wrong "false" only asks a person.

Return one JSON object:
{"vulnerable_function": "...", "vulnerable_class": "...", "vulnerable_file": "...",
 "what_changed": "...", "evidence": "...", "why": "...", "precondition": "...",
 "precondition_tokens": [...], "precondition_where": "...",
 "precondition_decidable": true}"""

SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["vulnerable_function", "vulnerable_class", "vulnerable_file",
                 "what_changed", "evidence", "why", "precondition",
                 "precondition_tokens", "precondition_where",
                 "precondition_decidable"],
    "properties": {
        "vulnerable_function": {"type": "string"},
        "vulnerable_class": {"type": "string"},
        "vulnerable_file": {"type": "string"},
        "what_changed": {"type": "string"},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
        "precondition": {"type": "string"},
        "precondition_tokens": {"type": "array", "items": {"type": "string"}},
        "precondition_where": {"type": "string"},
        "precondition_decidable": {"type": "boolean"},
    },
}

_MAX_RESPONSE_EXCERPT = 320
_MAX_REPAIR_RESPONSE = 4_000


def _response_excerpt(text: str, error: Exception) -> str:
    """Bounded model output around the parse failure for durable diagnostics."""
    position = min(getattr(error, "pos", 0), len(text))
    start = max(0, position - _MAX_RESPONSE_EXCERPT // 2)
    end = min(len(text), start + _MAX_RESPONSE_EXCERPT)
    prefix = "..." if start else ""
    suffix = "..." if end < len(text) else ""
    excerpt = text[start:end].strip().replace("\r", "\\r").replace("\n", "\\n")
    return f"{prefix}{excerpt}{suffix}"


def _parse_json_object(text: str) -> dict:
    """Parse a JSON object, tolerating only wrappers such as code fences.

    DeepSeek's json_object mode does not enforce a schema and occasionally adds
    markdown around an otherwise valid object. We may remove that wrapper, but
    never guess missing commas, quotes, or braces.
    """
    stripped = text.strip()
    try:
        answer = json.loads(stripped)
    except json.JSONDecodeError as original:
        start = stripped.find("{")
        if start < 0:
            raise original
        try:
            answer, _ = json.JSONDecoder().raw_decode(stripped, start)
        except json.JSONDecodeError:
            raise original
    if not isinstance(answer, dict):
        raise ValueError(f"expected one JSON object, got {type(answer).__name__}")
    return answer


@dataclass(slots=True)
class VulnerableSymbol:
    """What to look for in a repository, for one advisory."""

    advisory_id: str
    package: str = ""
    function: str = ""
    klass: str = ""
    file: str = ""
    grounded_in_fix: bool = False
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
        if self.confirmed_in_source:
            return "вызов подтверждён symbol-level сканером"
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
    precondition_tokens: tuple[str, ...] = field(default_factory=tuple)
    precondition_where: str = ""
    precondition_decidable: bool = True
    resolution_error: str = ""

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
        with urllib.request.urlopen(request, timeout=_TIMEOUT) as response:
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
    """How the languages we scan spell "this function is defined here".

    Matching only `function name(` is a PHP habit, and it silently reported
    every Python symbol as absent — `def urlize` is a declaration too, as are
    the several forms JavaScript uses for the same thing. Case-insensitive
    because PHP method names are; the other languages are not harmed by it,
    since the name still has to match.
    """
    escaped = re.escape(name)
    return re.compile(
        rf"(?:function\s+&?\s*{escaped}\s*\()"
        rf"|(?:\b(?:async\s+)?def\s+{escaped}\s*\()"
        rf"|(?:\b{escaped}\s*[:=]\s*(?:async\s+)?function\b)"
        rf"|(?:\b{escaped}\s*[:=]\s*(?:async\s+)?\([^)]*\)\s*=>)"
        rf"|(?:\bfunc\s+(?:\([^)]*\)\s*)?{escaped}\s*\()",
        re.I,
    )


def _quotes_a_changed_line(evidence: str | None, diff: str) -> bool:
    """Is the quote a line the fix added or removed, rather than context?

    The distinction is the whole difference between the flaw and the check it
    evaded: a bypassed validator appears in the diff untouched, so a quote from
    an unchanged line is evidence of nothing. With no diff there is nothing to
    hold the quote against, and the answer stands on the advisory text instead.
    """
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


def _existed_before_fix(name: str, diff: str) -> bool | None:
    """Did this function exist before the fix, judged from the diff alone?

    A diff carries both versions: removed lines and context lines are the file
    as it was, added lines are the file as it became. So a name that appears
    only on `+` lines was introduced by the fix and cannot be in the vulnerable
    release — `findCharSet` was exactly that, and searching a project for it
    could only ever come back empty.

    This answers what reading the installed package answered, without the
    package: the diff is already here, and it is the same for every project.
    """
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


def _similar(name: str, files: dict[str, str], limit: int = 25) -> list[tuple[str, str]]:
    low = name.lower()
    hits: dict[str, str] = {}
    for path, text in files.items():
        for first, second in _DECL.findall(text):
            decl = first or second
            plain = decl.lower()
            if plain and (low in plain or plain.endswith(low) or plain.split("_")[-1] == low):
                hits.setdefault(decl, path)
    return sorted(hits.items())[:limit]


class SymbolResolver:
    """Advisory in, symbol out. One model call, two when the name is not found."""

    def __init__(
        self,
        client,
        *,
        roots: list[Path] | None = None,
        source_cache: PackageSourceCache | None = None,
    ) -> None:
        self._client = client
        self._roots = [Path(r) for r in (roots or [])]
        self._sources: dict[tuple[str, str, str], dict[str, str]] = {}
        self._snapshots: dict[tuple[str, str, str], SourceSnapshot] = {}
        self._source_cache = source_cache

    @staticmethod
    def _source_key(ecosystem: str, package: str, version: str) -> tuple[str, str, str]:
        return ecosystem.lower(), package.lower(), version.lstrip("v")

    def source_snapshot(self, ecosystem: str, package: str, version: str = "") -> SourceSnapshot:
        """Local installed source first, then one exact-version remote archive."""
        key = self._source_key(ecosystem, package, version)
        cached = self._snapshots.get(key)
        if cached is not None:
            return SourceSnapshot(
                ecosystem=cached.ecosystem,
                package=cached.package,
                version=cached.version,
                files=cached.files,
                source_url=cached.source_url,
                archive_sha256=cached.archive_sha256,
                problem=cached.problem,
                cache_status="cache_hit",
            )

        for root in self._roots:
            directory = registries.locate(root, ecosystem, package)
            files = registries.package_source(ecosystem, package, version, root)
            if files:
                snapshot = SourceSnapshot(
                    ecosystem, package, version, files,
                    source_url=directory.resolve().as_uri() if directory else str(root.resolve()),
                    cache_status="local",
                )
                self._snapshots[key] = snapshot
                self._sources[key] = files
                return snapshot

        if self._source_cache is None:
            snapshot = SourceSnapshot(
                ecosystem, package, version,
                problem="package is not installed and remote source cache is disabled",
                cache_status="unavailable",
            )
        else:
            snapshot = self._source_cache.snapshot(ecosystem, package, version)
        self._snapshots[key] = snapshot
        if snapshot.files:
            self._sources[key] = snapshot.files
        return snapshot

    def _source_for(self, ecosystem: str, package: str, version: str = "") -> dict[str, str]:
        """The installed package, read once per run and only when it is there.

        Held per process and thrown away with it: advisories cluster hard on a
        few packages — 53 CVEs across 16 packages on one real project — and
        re-reading the same directory once per CVE is pure waste. An empty
        result is not remembered, so a tree that appears later is still seen.
        """
        key = self._source_key(ecosystem, package, version)
        cached = self._sources.get(key)
        if cached:
            return cached
        return self.source_snapshot(ecosystem, package, version).files

    @staticmethod
    def _failed_answer(error: str) -> dict:
        return {
            "vulnerable_function": "",
            "vulnerable_class": "",
            "vulnerable_file": "",
            "evidence": "",
            "why": error,
        }

    def _ask(self, user: str) -> tuple[dict, str]:
        raw = ""
        try:
            raw = self._client.complete(SYSTEM, user, json_schema=SCHEMA).text
            return _parse_json_object(raw), ""
        except Exception as exc:
            if not raw:
                error = f"symbol extraction request failed: {exc}"
                log.warning(error)
                return self._failed_answer(error), error
            first_error = exc

        log.info("symbol extraction JSON repair round: %s", first_error)
        failure_context = _response_excerpt(raw, first_error)
        repair_user = (
            f"{user}\n\n=== JSON CORRECTION REQUIRED ===\n"
            "Your previous answer was not valid JSON. Return the same answer as exactly one "
            "valid JSON object. Include every required field, escape backslashes and quotes "
            "correctly, and emit no markdown or prose outside the object. Do not preserve invalid "
            "punctuation. JSON does not support `=>`: when a source-code expression is useful as "
            "a token, quote the entire expression as one JSON string. Every precondition_tokens "
            "item must be a JSON string.\n\n"
            f"Parser error: {first_error}\n"
            f"Text around the error: {failure_context!r}\n\n"
            "Previous invalid answer:\n"
            f"{raw[:_MAX_REPAIR_RESPONSE]}"
        )
        repaired_raw = ""
        try:
            repaired_raw = self._client.complete(SYSTEM, repair_user, json_schema=SCHEMA).text
            return _parse_json_object(repaired_raw), ""
        except Exception as repair_exc:
            error = (
                f"symbol extraction returned invalid JSON twice: first={first_error}; "
                f"repair={repair_exc}; first_response={_response_excerpt(raw, first_error)!r}; "
                f"repair_response={_response_excerpt(repaired_raw, repair_exc)!r}"
            )
            log.warning(error)
            return self._failed_answer(error), error

    @staticmethod
    def _name(answer: dict) -> str:
        return (answer.get("vulnerable_function") or "").split("::")[-1].strip().rstrip("()")

    def resolve(self, advisory: Advisory, version: str = "") -> VulnerableSymbol:
        base = VulnerableSymbol(
            advisory_id=advisory.advisory_id, package=advisory.package,
            aliases=tuple(advisory.aliases),
        )
        if not advisory.usable:
            base.note = advisory.problem or "advisory без текста и без ссылки на фикс"
            return base

        diff, diff_url = fix_diff(advisory)
        prompt = [f"Advisory: {advisory.advisory_id}", f"Package: {advisory.package}",
                  f"Vulnerable version: {version or 'unknown'}",
                  f"Summary: {advisory.summary}", "", "=== ADVISORY TEXT ===",
                  advisory.details or "(нет текста)"]
        if diff:
            prompt += ["", f"=== FIX DIFF ({diff_url}) ===", diff]
        user = "\n".join(prompt)

        answer, resolution_error = self._ask(user)
        name = self._name(answer)
        steps = 1

        grounded = _in_text(name, diff) or _in_text(name, advisory.text)
        changed = _quotes_a_changed_line(answer.get("evidence"), diff)

        if name and diff and not (grounded and changed):
            steps = 2
            problem = ("appears neither in the fix nor in the advisory text"
                       if not grounded else
                       "is quoted from a line the fix did not touch")
            answer, resolution_error = self._ask(
                user + f"\n\n=== CORRECTION ===\n`{name}` {problem}. A fix changes the "
                "vulnerable function's own code, so quote a line that starts with `+` "
                "or `-` from inside it. A function that appears only in unchanged "
                "context is the one that was bypassed, not the one that was wrong. "
                "Name that function, or return an empty `vulnerable_function`.")
            name = self._name(answer)
            grounded = _in_text(name, diff) or _in_text(name, advisory.text)
            changed = _quotes_a_changed_line(answer.get("evidence"), diff)

        klass = (answer.get("vulnerable_class") or "").split("\\")[-1].strip()
        path = (answer.get("vulnerable_file") or "").strip()

        base.function = name
        base.klass = klass
        base.file = path
        base.evidence = (answer.get("evidence") or "")[:300]
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
        base.precondition = (answer.get("precondition") or "").strip()[:300]
        base.precondition_tokens = tuple(
            str(t).strip() for t in (answer.get("precondition_tokens") or []) if str(t).strip())
        base.precondition_where = (answer.get("precondition_where") or "").strip()[:200]
        base.precondition_decidable = bool(answer.get("precondition_decidable", True))
        base.resolution_error = resolution_error

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
        return base
