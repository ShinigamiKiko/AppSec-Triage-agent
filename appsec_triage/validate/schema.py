"""The JSON contract, and a tolerant parser for models that don't honour it.

`VERDICT_SCHEMA` is handed to the provider for constrained decoding where the
provider supports it (Ollama `format`, OpenAI `json_schema`). DeepSeek only gets
`json_object`, so the salvage path below matters there in practice.
"""

from __future__ import annotations

import json
import re
from typing import Any

from pydantic import ValidationError

from ..models import Verdict

VERDICT_SCHEMA: dict[str, Any] = {
    "type": "object",
    "additionalProperties": False,
    "required": [
        "verdict",
        "evidence_class",
        "confidence",
        "confidence_rationale",
        "exploitability",
        "impact",
        "cwe",
        "vulnerable_symbol",
        "dataflow",
        "evidence",
        "reason",
        "missing_information",
        "blocking_question",
        "requires_human_review",
    ],
    "properties": {
        "verdict": {"type": "string", "enum": ["confirmed", "false_positive", "unknown"]},
        "evidence_class": {
            "type": "string",
            "enum": [
                "SECRET_VALUE",
                "IDENTIFIER_ONLY",
                "TEST_PLACEHOLDER",
                "EXPLOITABLE_DATAFLOW",
                "SANITIZED_DATAFLOW",
                "INSUFFICIENT_CONTEXT",
            ],
        },
        "confidence": {"type": "number", "minimum": 0.0, "maximum": 1.0},
        "exploitability": {"type": "string", "enum": ["trivial", "moderate", "difficult"]},
        "impact": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
        "confidence_rationale": {
            "type": "string",
            "description": "Why this number: what you are sure of, and what keeps it from being higher.",
        },
        "cwe": {"type": ["string", "null"]},
        "vulnerable_symbol": {
            "type": "object",
            "additionalProperties": False,
            "required": ["name", "kind", "location", "why"],
            "properties": {
                "name": {
                    "type": "string",
                    "description": (
                        "The exact call, literal, algorithm or config key this finding is about, "
                        "copied verbatim from the input, e.g. 'stmt.executeQuery' or "
                        "'MessageDigest.getInstance(\"MD5\")' or 'new Random()'."
                    ),
                },
                "kind": {
                    "type": "string",
                    "enum": ["sink", "api_call", "literal", "generator", "algorithm", "config_key"],
                },
                "location": {"type": ["string", "null"], "description": "file:line, copied from the input."},
                "why": {
                    "type": "string",
                    "description": "One sentence: why this symbol is dangerous — or why it is harmless here.",
                },
            },
        },
        "dataflow": {
            "type": "array",
            "description": (
                "The path, one hop per step, ordered. Reconstruct ONLY from the TRACE and CODE "
                "sections you were given. If no trace was provided, return an empty array — "
                "do not invent hops."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["order", "role", "location", "code", "explanation", "tainted"],
                "properties": {
                    "order": {"type": "integer"},
                    "role": {"type": "string", "enum": ["source", "propagation", "sanitizer", "sink"]},
                    "location": {"type": ["string", "null"]},
                    "code": {"type": ["string", "null"], "description": "Exact quote from the input, or null."},
                    "explanation": {"type": "string"},
                    "tainted": {"type": "boolean", "description": "Is the value still attacker-controlled here?"},
                },
            },
        },
        "evidence": {
            "type": "array",
            "description": (
                "The lines your verdict rests on. `quote` is copied character-for-character "
                "from the input and is checked against it; `why` is your explanation of what "
                "that line proves. A description in `quote` fails verification and costs you "
                "the verdict."
            ),
            "items": {
                "type": "object",
                "additionalProperties": False,
                "required": ["quote", "why"],
                "properties": {
                    "quote": {
                        "type": "string",
                        "description": (
                            "VERBATIM text from the input above. Copy it, do not describe it. "
                            "Right: \"$cmd = shell_exec( 'ping  ' . $target );\". "
                            "Wrong: \"user input is concatenated into a shell command\"."
                        ),
                    },
                    "why": {
                        "type": "string",
                        "description": "What this line establishes. Prose goes here.",
                    },
                },
            },
        },
        "reason": {"type": "string"},
        "missing_information": {"type": "array", "items": {"type": "string"}},
        "blocking_question": {
            "type": ["string", "null"],
            "description": (
                "Required when verdict is `unknown`: the ONE fact about THIS finding that would "
                "settle it, phrased so a human knows exactly which file or function to open. "
                "Must be specific to the code you were shown. Null for any other verdict."
            ),
        },
        "requires_human_review": {"type": "boolean"},
    },
}

_FENCE = re.compile(r"```(?:json)?\s*(.*?)```", re.DOTALL)


class SchemaError(ValueError):
    pass


def _salvage(text: str) -> str:
    """Recover the JSON object from a model that wrapped or prefaced it."""
    if m := _FENCE.search(text):
        return m.group(1).strip()
    start = text.find("{")
    if start == -1:
        raise SchemaError(f"no JSON object in response: {text[:200]!r}")
    depth, in_str, esc = 0, False, False
    for i, ch in enumerate(text[start:], start):
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    raise SchemaError(f"unbalanced JSON object in response: {text[:200]!r}")


_BAD_ESCAPE = re.compile(r'\\(?![\\/"bfnrtu])')


def _fix_escapes(text: str) -> str:
    """Double any backslash that is not the start of a valid JSON escape."""
    return _BAD_ESCAPE.sub(r"\\\\", text)


def parse_verdict(text: str) -> Verdict:
    raw = text.strip()
    try:
        return _build(json.loads(raw))
    except json.JSONDecodeError:
        pass

    for repair in (_salvage(raw), _fix_escapes(raw), _fix_escapes(_salvage(raw))):
        try:
            data = json.loads(repair)
        except json.JSONDecodeError:
            continue
        return _build(data)

    raise SchemaError(f"response is not valid JSON after repair: {raw[:300]!r}")


def _build(data: object) -> Verdict:

    if not isinstance(data, dict):
        raise SchemaError(f"expected a JSON object, got {type(data).__name__}")

    if isinstance(data.get("verdict"), str):
        data["verdict"] = data["verdict"].strip().lower()
    if isinstance(data.get("evidence_class"), str):
        data["evidence_class"] = data["evidence_class"].strip().upper()
    if isinstance(data.get("evidence"), list):
        data["evidence"] = [
            {"quote": e, "why": ""} if isinstance(e, str) else e
            for e in data["evidence"]
            if isinstance(e, (str, dict))
        ]

    for key in ("evidence", "missing_information", "dataflow"):
        val = data.get(key)
        if isinstance(val, str):
            data[key] = [{"quote": val, "why": ""}] if key == "evidence" else ([val] if key != "dataflow" else [])
        elif val is None:
            data[key] = []
    if isinstance(data.get("dataflow"), list):
        steps = [s for s in data["dataflow"] if isinstance(s, dict)]
        step_keys = set(VERDICT_SCHEMA["properties"]["dataflow"]["items"]["properties"]) | {"grounded"}
        for i, raw_step in enumerate(steps, 1):
            for alias, ours in (("step", "order"), ("type", "role"), ("why", "explanation")):
                if ours not in raw_step and alias in raw_step:
                    raw_step[ours] = raw_step[alias]
            for key in list(raw_step):
                if key not in step_keys:
                    del raw_step[key]
            raw_step.setdefault("order", i)
            role = str(raw_step.get("role", "propagation")).strip().lower()
            raw_step["role"] = role if role in ("source", "propagation", "sanitizer", "sink") else "propagation"
        data["dataflow"] = sorted(steps, key=lambda s: s.get("order", 0))
    if isinstance(data.get("vulnerable_symbol"), str):
        data["vulnerable_symbol"] = {"name": data["vulnerable_symbol"], "kind": "api_call"}
    if isinstance(data.get("vulnerable_symbol"), dict):
        sym = data["vulnerable_symbol"]
        sym_keys = set(VERDICT_SCHEMA["properties"]["vulnerable_symbol"]["properties"])
        for key in list(sym):
            if key not in sym_keys:
                del sym[key]
        kind = str(sym.get("kind", "api_call")).strip().lower()
        valid = VERDICT_SCHEMA["properties"]["vulnerable_symbol"]["properties"]["kind"]["enum"]
        sym["kind"] = kind if kind in valid else "api_call"
        if not sym.get("name"):
            data["vulnerable_symbol"] = None
    if isinstance(data.get("evidence"), list):
        data["evidence"] = [
            {"quote": e["quote"], "why": str(e.get("why") or e.get("explanation") or "")}
            for e in data["evidence"]
            if isinstance(e, dict) and e.get("quote")
        ]
    if not data.get("evidence") and isinstance(data.get("dataflow"), list):
        seen: set[str] = set()
        data["evidence"] = [
            {"quote": code, "why": str(step.get("explanation") or "")}
            for step in data["dataflow"]
            if isinstance(code := step.get("code"), str) and code.strip() and not (code in seen or seen.add(code))
        ]
    data.setdefault("requires_human_review", True)
    data.setdefault("reason", "")
    allowed = set(VERDICT_SCHEMA["properties"])
    data = {k: v for k, v in data.items() if k in allowed}

    try:
        return Verdict.model_validate(data)
    except ValidationError as exc:
        raise SchemaError(f"verdict failed schema validation: {exc}") from exc
