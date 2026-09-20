"""Prompt registry: pick the CWE-specific prompt, fall back to base."""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from ..config import REPO_ROOT

PROMPTS_ROOT = REPO_ROOT / "prompts"
TRAINING_CONTEXT_PATH = PROMPTS_ROOT / "training-context.md"
_FRONT_MATTER = re.compile(r"^---\s*\n(.*?)\n---\s*\n", re.DOTALL)


@dataclass(slots=True, frozen=True)
class Prompt:
    id: str
    version: str
    applies_to: tuple[str, ...]
    body: str
    extends: str | None
    includes: tuple[str, ...]
    shared: bool
    kind: str | None
    path: Path

    @property
    def is_catch_all(self) -> bool:
        return "*" in self.applies_to


class PromptError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def training_context() -> str:
    """Load trusted, project-specific context attached to every model request."""
    try:
        text = TRAINING_CONTEXT_PATH.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise PromptError(f"{TRAINING_CONTEXT_PATH}: context not read ({exc})") from exc
    if not text:
        raise PromptError(f"{TRAINING_CONTEXT_PATH}: context is empty")
    return text


# The report is read in Russian, so the model writes its prose in Russian. What
# it must NOT translate is anything that is checked character by character: a
# quote is verified verbatim against the input it came from, and a translated
# quote fails that check and is thrown away along with the reasoning it carried.
_ANSWER_LANGUAGE = """## Язык ответа

Все объяснения, обоснования и выводы пиши по-русски.

Оставляй без перевода, ровно как во входных данных:
- цитаты (поля `quote`, `evidence` и любые другие дословные выдержки);
- имена функций, классов, методов, файлов, пакетов, версий;
- идентификаторы advisory (CVE, GHSA, GO-), сообщения сканеров, значения полей.

Цитата сверяется с исходным текстом посимвольно. Переведённая цитата не
проходит сверку, и вместе с ней отбрасывается весь вывод, который на неё
опирался. Если цитата на английском — так её и приводи."""


def _with_training_context(system: str) -> str:
    return ("\n\n---\n\n## Project-specific context\n\n" + training_context()
            + "\n\n---\n\n" + system + "\n\n---\n\n" + _ANSWER_LANGUAGE)


def _parse(path: Path) -> Prompt:
    text = path.read_text(encoding="utf-8")
    m = _FRONT_MATTER.match(text)
    if not m:
        raise PromptError(f"{path}: missing YAML front matter (--- id/version/applies_to ---)")
    meta = yaml.safe_load(m.group(1)) or {}
    for key in ("id", "version", "applies_to"):
        if key not in meta:
            raise PromptError(f"{path}: front matter is missing required key '{key}'")
    return Prompt(
        id=str(meta["id"]),
        version=str(meta["version"]),
        applies_to=tuple(str(c).upper() for c in meta["applies_to"]),
        body=text[m.end():].strip(),
        extends=meta.get("extends"),
        includes=tuple(meta.get("includes") or []),
        shared=bool(meta.get("shared", False)),
        kind=(str(meta["kind"]) if meta.get("kind") else None),
        path=path,
    )


@lru_cache(maxsize=8)
def load_pack(pack: str = "default") -> dict[str, Prompt]:
    root = PROMPTS_ROOT / pack
    if not root.is_dir():
        available = sorted(p.name for p in PROMPTS_ROOT.iterdir() if p.is_dir()) if PROMPTS_ROOT.is_dir() else []
        raise PromptError(f"no prompt pack '{pack}' at {root}. Available: {available}")
    prompts = {p.id: p for p in (_parse(f) for f in sorted(root.glob("*.md")))}
    if "base" not in prompts:
        raise PromptError(f"prompt pack '{pack}' has no base.md")
    return prompts


def normalize_cwe(cwe: str | None) -> str | None:
    if not cwe:
        return None
    m = re.search(r"(\d+)", str(cwe))
    return f"CWE-{m.group(1)}" if m else str(cwe).upper()


def resolve(cwe: str | None, pack: str = "default", kind: str | None = None) -> Prompt:
    """Most specific prompt for this finding: `kind` first, then CWE, then base."""
    prompts = load_pack(pack)
    if kind:
        for prompt in prompts.values():
            if prompt.kind == kind:
                return prompt
    key = normalize_cwe(cwe)
    if key:
        matches = [p for p in prompts.values() if key in p.applies_to and not p.is_catch_all and not p.shared]
        if matches:
            return min(matches, key=lambda p: len(p.applies_to))
    return prompts["base"]


def render_system(
    cwe: str | None, pack: str = "default", stack_section: str = "", kind: str | None = None
) -> tuple[str, Prompt]:
    """Compose the system prompt: base + CWE specialization + stack conventions."""
    prompt = resolve(cwe, pack, kind)
    parts: list[str] = []
    if prompt.kind and not prompt.extends:
        parts.append(load_pack(pack)["base"].body)
    if prompt.extends:
        parent = load_pack(pack).get(prompt.extends)
        if parent is None:
            raise PromptError(f"{prompt.path}: extends unknown prompt '{prompt.extends}'")
        parts.append(parent.body)
    parts.append(prompt.body)
    for frag_id in prompt.includes:
        fragment = load_pack(pack).get(frag_id)
        if fragment is None:
            raise PromptError(f"{prompt.path}: includes unknown fragment '{frag_id}'")
        parts.append(fragment.body)
    if stack_section:
        parts.append(stack_section)
    return _with_training_context("\n\n---\n\n".join(parts)), prompt


@lru_cache(maxsize=32)
def step(name: str) -> str:
    """The system prompt for one dependency-triage step, by file name."""
    path = PROMPTS_ROOT / "sca" / f"{name}.md"
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PromptError(f"{path}: промпт шага не прочитан ({exc})") from exc
    match = _FRONT_MATTER.match(text)
    body = text[match.end():] if match else text
    if not body.strip():
        raise PromptError(f"{path}: промпт пуст")
    return _with_training_context(body.strip())


def coverage(pack: str = "default") -> dict[str, str]:
    """CWE -> prompt id, for the report and for spotting gaps."""
    out: dict[str, str] = {}
    for p in load_pack(pack).values():
        if p.shared:
            continue
        for cwe in p.applies_to:
            if cwe != "*":
                out[cwe] = p.id
    return dict(sorted(out.items()))
