"""An advisory's resolved symbol, kept between runs.

Resolving reads the advisory and the installed package, never the project's code: the
same advisory, version, model, prompts and resolver code give the same answer, so a CI
run can take it from the previous one. The cache lives in `APPSEC_CACHE_DIR` (unset —
no cache) and its key covers every one of those inputs, so any change is a miss.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import logging
import os
import tempfile
from functools import lru_cache
from pathlib import Path

from ..prompts.registry import PROMPTS_ROOT
from .resolve import VulnerableSymbol

log = logging.getLogger(__name__)

_SCHEMA = 1
# The code that turns an advisory into a symbol: a change to it is a change of answer.
_CODE = ("resolve.py", "declarations.py", "resolve_cache.py")


def directory() -> Path | None:
    raw = os.getenv("APPSEC_CACHE_DIR", "").strip()
    return Path(raw) / "resolve" if raw else None


@lru_cache(maxsize=1)
def _inputs_hash() -> str:
    digest = hashlib.sha256()
    here = Path(__file__).resolve().parent
    files = [here / name for name in _CODE]
    files += sorted((PROMPTS_ROOT / "sca").glob("*.md")) + sorted((PROMPTS_ROOT / "context").glob("*.md"))
    for path in files:
        digest.update(path.name.encode("utf-8"))
        try:
            digest.update(path.read_bytes())
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest()


def key(advisory, version: str, model: str, installed: bool) -> str:
    try:
        material = dataclasses.asdict(advisory)
    except TypeError:
        material = {"id": getattr(advisory, "advisory_id", ""), "text": getattr(advisory, "text", "")}
    payload = json.dumps([_SCHEMA, _inputs_hash(), material, version, model, installed],
                         sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:40]


def _tuples(value):
    return tuple(_tuples(v) for v in value) if isinstance(value, list) else value


def load(cache_key: str) -> VulnerableSymbol | None:
    folder = directory()
    if folder is None:
        return None
    try:
        data = json.loads((folder / f"{cache_key}.json").read_text(encoding="utf-8"))
        return VulnerableSymbol(**{name: _tuples(value) for name, value in data.items()})
    except (OSError, ValueError, TypeError):
        return None


def store(cache_key: str, symbol: VulnerableSymbol) -> None:
    folder = directory()
    if folder is None:
        return
    try:
        folder.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=folder, delete=False,
                                         suffix=".tmp") as handle:
            json.dump(dataclasses.asdict(symbol), handle, ensure_ascii=False)
        os.replace(handle.name, folder / f"{cache_key}.json")
    except OSError as exc:
        log.info("resolve cache not written: %s", exc)
