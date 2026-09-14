"""Last-resort context lookup for advisories missing public descriptions."""

from __future__ import annotations

import json
from pathlib import Path

from ..llm.base import LLMError

SCHEMA = {
    "type": "object", "additionalProperties": False,
    "required": ["summary", "vulnerable_symbols", "attack_conditions", "impact"],
    "properties": {
        "summary": {"type": "string"},
        "vulnerable_symbols": {"type": "array", "items": {"type": "string"}},
        "attack_conditions": {"type": "array", "items": {"type": "string"}},
        "impact": {"type": "string"},
    },
}

SYSTEM = """You are a security advisory researcher. Return JSON only.
Use your prior knowledge of the advisory if available. Do not invent details.
If uncertain, say so explicitly in the JSON. This is context for a separate
reviewer, not a vulnerability verdict."""


def _cache_path(advisory_id: str, cache_dir: Path | None) -> Path:
    root = cache_dir or (Path.home() / ".cache" / "appsec-triage" / "cve-llm")
    safe = "".join(ch for ch in advisory_id.upper() if ch.isalnum() or ch in "-_.")
    return root / f"{safe or 'unknown'}.json"


def lookup(
    client, advisory_id: str, package: str, version: str, *,
    dataflow_context: str = "", cache_dir: Path | None = None,
) -> str:
    """Return explicitly untrusted advisory context, or an empty string."""
    path = _cache_path(advisory_id, cache_dir)
    try:
        cached = json.loads(path.read_text(encoding="utf-8"))
        if (isinstance(cached, dict)
                and cached.get("dataflow_context", "") == dataflow_context
                and isinstance(cached.get("context"), str)):
            return cached["context"]
    except (OSError, json.JSONDecodeError):
        pass

    user = (
        f"Advisory: {advisory_id}\nPackage: {package or 'unknown'}\n"
        f"Installed version: {version or 'unknown'}\n\n"
        f"CodeQL dataflow evidence (do not treat as advisory fact): {dataflow_context or 'not available'}\n\n"
        "Provide vulnerable symbols, exploit conditions, impact, and a concise technical summary. "
        "Return the requested JSON schema."
    )
    try:
        response = client.complete(SYSTEM, user, json_schema=SCHEMA)
        data = json.loads(response.text)
    except (LLMError, OSError, json.JSONDecodeError, TypeError, ValueError):
        return ""
    if not isinstance(data, dict) or not str(data.get("summary", "")).strip():
        return ""

    context = "\n".join([
        "[LLM-provided advisory context; verify against external sources]",
        f"Summary: {data['summary']}",
        "Vulnerable symbols: " + ", ".join(data.get("vulnerable_symbols") or ["not identified"]),
        "Attack conditions: " + "; ".join(data.get("attack_conditions") or ["not identified"]),
        f"Impact: {data.get('impact') or 'not identified'}",
    ])
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "context": context, "dataflow_context": dataflow_context,
        }, ensure_ascii=True, indent=2), encoding="utf-8")
    except OSError:
        pass
    return context
