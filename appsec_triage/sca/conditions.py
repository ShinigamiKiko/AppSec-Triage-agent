"""What has to be true for the flaw to be exploitable here — checked, or handed over.

Many advisories only bite under a configuration. A twig sandbox escape needs the
application to render templates it did not write; an XXE needs external entity
loading left on; a deserialisation flaw needs untrusted input to be
deserialised. Where that condition is decidable from the repository it decides
the finding as firmly as a missing call does.

Where it is not — the setting lives in an environment variable, a deployment
manifest, a runtime default, another team's service — the honest output is not a
guess and not `unknown`. It is a statement that this is external, with enough
detail for a person to settle it in a minute: what has to be true, which symbol
or setting expresses it, and where to look.

The tokens are supplied by the model from the advisory text; the search for them
is deterministic. So the model decides what question to ask, and the repository
decides the answer.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

log = logging.getLogger(__name__)

_SKIP_DIRS = {".git", "vendor", "node_modules", "venv", ".venv", "target",
              "build", "dist", "__pycache__"}
_SUFFIXES = {".php", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".go",
             ".rb", ".java", ".kt", ".cs",
             ".yaml", ".yml", ".xml", ".ini", ".json", ".neon", ".toml", ".env"}
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


DEPLOYMENT_SYSTEM = """You decide whether a deployment fact settles one
precondition of a vulnerability.

You are given the condition the advisory requires, and a description of where
the application runs — declared by the team that operates it, not inferred.

Answer `holds` when the deployment shows the condition is met, `absent` when it
shows it is not, `infrastructure` when the condition is about a system this
application does not own, and `unknown` otherwise. Unknown is the common and
correct answer: most conditions are about the code, not the platform.

`infrastructure` means the fix belongs to somebody else: the configuration of an
LDAP server, TLS on a load balancer, encryption settings of a managed database,
a firewall rule. The application cannot change any of those, and leaving such a
finding in a developer's queue guarantees nobody acts on it. It is not a
closure — the risk stands and the owner changes.

Do not use it for anything the application configures itself, even when that
configuration concerns an external system: a client library's own TLS options,
its certificate verification, its timeouts are the application's to set.

Be strict about what a platform can decide. "Reachable from the internet",
"listens on a privileged port", "runs as root", "a local user session exists" —
these the deployment answers. Whether untrusted data reaches a parser, whether
user-supplied templates are rendered, whether a setting is enabled in code —
these it does not, whatever the description says.

`evidence` must be one line copied character-for-character from the deployment
description or its facts. An answer whose quote does not appear verbatim is
discarded.

Return one JSON object:
{"verdict": "holds|absent|infrastructure|unknown", "evidence": "...", "why": "..."}"""

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
    """Offer an undecidable condition to the declared deployment facts.

    A precondition the repository cannot answer is not always a question for a
    person: "reachable from the internet" is answered by the ingress, "listens
    on a privileged port" by the pod spec. Only conditions already marked
    EXTERNAL come here — one the code settled stays settled — and the answer is
    held to the same quoting rule as everything else.
    """
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
                         reason=f"по описанию среды: {why}")
    if verdict == "holds":
        return Condition(ConditionState.HOLDS, condition.statement, condition.tokens,
                         condition.where, hits=[f"деплой: {quote[:100]}"],
                         reason=f"по описанию среды: {why}")
    if verdict == "infrastructure":
        return Condition(ConditionState.INFRASTRUCTURE, condition.statement,
                         condition.tokens, condition.where,
                         hits=[f"деплой: {quote[:100]}"], reason=why)
    return condition


def _files(root: Path):
    out = []
    for path in root.rglob("*"):
        if len(out) >= _MAX_FILES:
            break
        if not path.is_file() or path.suffix.lower() not in _SUFFIXES:
            continue
        if _SKIP_DIRS.intersection(path.parts):
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
    """Look for `tokens` in the project, or say why the answer is not here.

    `decidable` is the model's judgement that the repository could settle this
    at all. When it says no, no amount of searching turns that into an answer,
    and the finding is handed to a person with instructions rather than being
    silently downgraded.
    """
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

    patterns = [(token, re.compile(rf"(?<![\w]){re.escape(token)}(?![\w])", re.I))
                for token in tokens]  # noqa: E501 - kept flat for readability
    hits: list[str] = []
    scanned = 0
    for root in roots:
        for path in _files(Path(root)):
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
        return Condition(ConditionState.HOLDS, statement, tokens, where, hits)
    if not scanned:
        return Condition(ConditionState.EXTERNAL, statement, tokens, where,
                         reason="в корнях исходников не оказалось файлов для поиска")
    return Condition(ConditionState.ABSENT, statement, tokens, where,
                     reason=f"просмотрено {scanned} файлов")
