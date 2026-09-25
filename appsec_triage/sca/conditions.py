"""What has to be true for the flaw to be exploitable here — checked, or handed over."""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from ..context.detection import DEFAULT_SOURCE_SUFFIXES, DetectionError, get_source_suffixes
from ..prompts import registry
from ..testpaths import is_test

log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "vendor", "node_modules", "venv", ".venv", "target",
              "build", "dist", "__pycache__"}
_MAX_FILES = 8000
_MAX_BYTES = 600_000
# Inventories list every package and word a scanner met; they configure nothing, so a
# condition "found" in one is found nowhere.
_GENERATED_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                    "composer.lock", "go.sum", "poetry.lock", "pipfile.lock", "cargo.lock",
                    "packages.lock.json", "bom.json", "sbom.json"}
_GENERATED_SUFFIXES = (".cdx.json", ".spdx.json", ".slices.json", ".sbom.json")
# A line that only comments on the code does not switch anything on. Docblock lines are
# not skipped — annotations there (`@Route(requirements=...)`) are configuration — and
# neither are PHP attributes, `#[...]`.
_COMMENT_LINE = re.compile(r"^\s*(?:#(?!\[)|;|//|<!--|\{#)")
_HITS_PER_PART = 3


class ConditionState(str, Enum):
    HOLDS = "holds"
    ABSENT = "absent"
    EXTERNAL = "external"
    INFRASTRUCTURE = "infrastructure"
    NONE = "none"


@dataclass(slots=True)
class Condition:
    """One precondition, and what became of checking it."""

    state: ConditionState = ConditionState.NONE
    statement: str = ""
    tokens: list[str] = field(default_factory=list)
    where: str = ""
    hits: list[str] = field(default_factory=list)
    reason: str = ""
    source: str = ""

    @property
    def needs_a_person(self) -> bool:
        return self.state is ConditionState.EXTERNAL

    def render(self) -> str:
        if self.state is ConditionState.NONE:
            return ""
        if self.state is ConditionState.HOLDS:
            return (f"условие выполняется: {self.statement} "
                    f"(найдено: {', '.join(self.hits[:3])})")
        if self.state is ConditionState.ABSENT:
            return (f"условие не выполняется: {self.statement} — "
                    f"в коде нет ни одного из: {', '.join(self.tokens[:5])}")
        if self.state is ConditionState.INFRASTRUCTURE:
            owner = self.where or "команда, которая эксплуатирует эту систему"
            return (f"EXTERNAL / ИНФРАСТРУКТУРА — к этому сервису не относится.\n"
                    f"    что должно быть верно: {self.statement}\n"
                    f"    владелец: {owner}\n"
                    f"    почему не приложение: {self.reason}")
        return (f"условие не проверено — из репозитория не видно "
                f"(на вердикт по версии не влияет).\n"
                f"    что должно быть верно: {self.statement}\n"
                f"    что искать: {', '.join(self.tokens[:6]) or 'не определено'}\n"
                f"    где смотреть: {self.where or 'конфигурация окружения и деплой'}\n"
                f"    почему нельзя решить здесь: {self.reason}")



_DEPLOY_SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["verdict", "evidence", "why"],
    "properties": {
        "verdict": {"type": "string",
                    "enum": ["holds", "absent", "infrastructure", "unknown"]},
        "evidence": {"type": "string"},
        "why": {"type": "string"},
    },
}


def check_against_deployment(condition: Condition, deployment, client) -> Condition:
    """Offer an undecidable condition to the declared deployment facts."""
    if client is None or condition.state is not ConditionState.EXTERNAL:
        return condition

    material = "\n".join([
        f"=== CONDITION THE ADVISORY REQUIRES ===\n{condition.statement}",
        f"where to look: {condition.where or 'не указано'}", "",
        "=== WHERE THIS APPLICATION RUNS (declared) ===",
        deployment.render(),
    ])
    try:
        answer = json.loads(
            client.complete(registry.step("deployment"), material, json_schema=_DEPLOY_SCHEMA).text)
    except Exception as exc:  # noqa: BLE001 - one failed call, not the run
        log.debug("deployment question failed: %s", exc)
        return condition

    quote = (answer.get("evidence") or "").strip()
    if not quote or quote not in material:
        log.debug("discarding ungrounded deployment answer")
        return condition

    verdict = (answer.get("verdict") or "unknown").strip().lower()
    why = (answer.get("why") or "")[:200]
    if verdict == "absent":
        return Condition(ConditionState.ABSENT, condition.statement, condition.tokens,
                         condition.where, hits=[f"деплой: {quote[:100]}"],
                         reason=f"по описанию среды: {why}", source="deployment")
    if verdict == "holds":
        return Condition(ConditionState.HOLDS, condition.statement, condition.tokens,
                         condition.where, hits=[f"деплой: {quote[:100]}"],
                         reason=f"по описанию среды: {why}", source="deployment")
    if verdict == "infrastructure":
        return Condition(ConditionState.INFRASTRUCTURE, condition.statement,
                         condition.tokens, condition.where,
                         hits=[f"деплой: {quote[:100]}"], reason=why, source="deployment")
    return condition


def _files(root: Path, suffixes: set[str]):
    out = []
    for path in root.rglob("*"):
        if len(out) >= _MAX_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in suffixes:
            continue
        if (_SKIP_DIRS.intersection(path.parts)
                or any(part.lower().startswith("appsec-out") for part in path.parts)):
            continue
        # A condition met only in tests or in a local compose file is not met in
        # production: `--host` in docker-compose is a developer's `yarn dev`.
        if is_test(path.relative_to(root).as_posix()):
            continue
        name = path.name.lower()
        if name in _GENERATED_NAMES or name.endswith(_GENERATED_SUFFIXES):
            continue
        out.append(path)
    return out


def _first_code_match(pattern: re.Pattern[str], text: str) -> re.Match[str] | None:
    """The first match on a line that is code or configuration, not a comment."""
    for match in pattern.finditer(text):
        start = text.rfind("\n", 0, match.start()) + 1
        end = text.find("\n", match.end())
        if not _COMMENT_LINE.match(text[start:end if end >= 0 else len(text)]):
            return match
    return None


def _searchable(token: str) -> bool:
    """A token a text search can tell apart: `.+` or `in` is in every file."""
    return len(re.findall(r"\w", token)) >= 3


_IDENTIFIER = re.compile(r"^[A-Za-z_][\w\\]*$")


def _pattern(token: str) -> re.Pattern[str]:
    """An identifier with a capital is a class or a constant: `Date` the constraint, not
    `date.timezone` or `$date`. Anything else — a key, a word, a header such as
    `X-Forwarded-For` that code writes in any case — is matched in any case."""
    exact = bool(_IDENTIFIER.match(token)) and any(c.isupper() for c in token)
    return re.compile(rf"(?<![\w]){re.escape(token)}(?![\w])", 0 if exact else re.IGNORECASE)


def _parts(tokens: list[str], groups) -> list[list[str]]:
    """The parts of a condition, each a list of alternatives; all parts must hold."""
    parts = [[t.strip() for t in group if t and _searchable(t.strip())][:8] for group in (groups or ())]
    parts = [part for part in parts if part]
    return parts or ([tokens] if tokens else [])


def check(
    roots: list[Path],
    statement: str,
    tokens: list[str],
    where: str = "",
    *,
    decidable: bool = True,
    groups=None,
) -> Condition:
    """Look for `tokens` in the project, or say why the answer is not here.

    `groups` splits the tokens by the parts of the condition that must hold at once
    ("the sandbox is on" and "a template uses join"): the condition holds only where
    every part is found, and a part found nowhere makes it absent. Without groups the
    tokens are one part, any of them enough.
    """
    tokens = [t.strip() for t in tokens if t and _searchable(t.strip())][:12]
    parts = _parts(tokens, groups)
    if parts and not tokens:
        tokens = [t for part in parts for t in part][:12]
    if not statement:
        return Condition(ConditionState.NONE)
    if not decidable or not tokens:
        return Condition(
            ConditionState.EXTERNAL, statement, tokens, where,
            reason=("условие задаётся вне кода репозитория (окружение, деплой, "
                    "смежный сервис)" if not decidable
                    else "advisory не даёт ни одного конкретного символа или "
                         "настройки, по которым это можно проверить"))
    if not roots:
        return Condition(ConditionState.EXTERNAL, statement, tokens, where,
                         reason="не задан ни один корень исходников — искать негде")

    from .framework_detectors import detect_framework_condition

    detected = detect_framework_condition([Path(root) for root in roots], tokens)
    if detected is not None:
        return Condition(
            ConditionState(detected.state), statement, tokens, where,
            hits=[detected.evidence] if detected.evidence else [],
            reason=detected.reason, source="detector",
        )

    try:
        suffixes = get_source_suffixes(roots, include_configs=True)
    except DetectionError:
        suffixes = DEFAULT_SOURCE_SUFFIXES

    compiled = [[(token, _pattern(token)) for token in part] for part in parts]
    found: list[list[str]] = [[] for _ in parts]
    scanned = 0
    for root in roots:
        for path in _files(Path(root), suffixes):
            if all(len(hits) >= _HITS_PER_PART for hits in found):
                break
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for index, part in enumerate(compiled):
                if len(found[index]) >= _HITS_PER_PART:
                    continue
                for token, pattern in part:
                    match = _first_code_match(pattern, text)
                    if match:
                        line = text.count("\n", 0, match.start()) + 1
                        found[index].append(f"{path.relative_to(root)}:{line} ({token})")
                        break
    if not scanned:
        return Condition(ConditionState.EXTERNAL, statement, tokens, where,
                         reason="в корнях исходников не оказалось файлов для поиска")
    missing = [part for part, hits in zip(parts, found) if not hits]
    if not missing:
        return Condition(ConditionState.HOLDS, statement, tokens, where,
                         [hit for hits in found for hit in hits][:6], source="text")
    absent = [token for part in missing for token in part]
    reason = f"просмотрено {scanned} файлов"
    if len(parts) > 1:
        reason += (f"; не найдена часть условия ({', '.join(absent[:5])}), "
                   "а условие требует всех частей сразу")
    return Condition(ConditionState.ABSENT, statement, absent, where, reason=reason, source="text")
