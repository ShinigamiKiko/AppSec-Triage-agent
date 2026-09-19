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

log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "vendor", "node_modules", "venv", ".venv", "target",
              "build", "dist", "__pycache__"}
_MAX_FILES = 8000
_MAX_BYTES = 600_000


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


DEPLOYMENT_SYSTEM = registry.step("deployment")

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
            client.complete(DEPLOYMENT_SYSTEM, material, json_schema=_DEPLOY_SCHEMA).text)
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
        out.append(path)
    return out


def check(
    roots: list[Path],
    statement: str,
    tokens: list[str],
    where: str = "",
    *,
    decidable: bool = True,
) -> Condition:
    """Look for `tokens` in the project, or say why the answer is not here."""
    tokens = [t.strip() for t in tokens if t and t.strip()][:12]
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

    patterns = [(token, re.compile(rf"(?<![\w]){re.escape(token)}(?![\w])", re.IGNORECASE))
                for token in tokens]
    hits: list[str] = []
    scanned = 0
    for root in roots:
        for path in _files(Path(root), suffixes):
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            scanned += 1
            for token, pattern in patterns:
                match = pattern.search(text)
                if match:
                    line = text.count("\n", 0, match.start()) + 1
                    hits.append(f"{path.relative_to(root)}:{line} ({token})")
                    break
            if len(hits) >= 5:
                break
    if hits:
        return Condition(ConditionState.HOLDS, statement, tokens, where, hits, source="text")
    if not scanned:
        return Condition(ConditionState.EXTERNAL, statement, tokens, where,
                         reason="в корнях исходников не оказалось файлов для поиска")
    return Condition(ConditionState.ABSENT, statement, tokens, where,
                     reason=f"просмотрено {scanned} файлов", source="text")
