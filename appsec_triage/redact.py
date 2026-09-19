"""Send a secret's shape to the model, never the secret."""

from __future__ import annotations

import re

from .context.heuristics import shannon_entropy

_QUOTED = re.compile(r"""(?P<head>\s*(?:=>|:=|[:=])\s*)(?P<q>["'])(?P<value>[^"'\n]{12,})(?P=q)""")
_CONFIG_VALUE = re.compile(r"""(?P<head>^[ \t]*[\w.\-]+[ \t]*[:=][ \t]*)(?P<value>[A-Za-z0-9+/_-]{16,}={0,2})[ \t]*$""", re.MULTILINE)

_ENTROPY_FLOOR = 3.6
_MIN_LENGTH = 16


def _describe(value: str) -> str:
    kinds = []
    if re.fullmatch(r"[0-9a-f]+", value, re.IGNORECASE):
        kinds.append("hex")
    elif re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", value):
        kinds.append("base64-ish")
    else:
        kinds.append("mixed")
    if any(c.isupper() for c in value) and any(c.islower() for c in value):
        kinds.append("mixed-case")
    if any(c.isdigit() for c in value):
        kinds.append("digits")
    return (
        f"<REDACTED {len(value)} chars, {', '.join(kinds)}, "
        f"entropy {shannon_entropy(value):.2f} — high-entropy, not a dictionary word>"
    )


def redact_secrets(text: str | None) -> tuple[str | None, int]:
    """Replace high-entropy assigned values with a description."""
    if not text:
        return text, 0

    count = 0

    def swap(m: re.Match[str]) -> str:
        nonlocal count
        value = m.group("value")
        if any(c.isspace() for c in value):
            return m.group(0)
        if len(value) < _MIN_LENGTH or shannon_entropy(value) < _ENTROPY_FLOOR:
            return m.group(0)
        if value.startswith(("http://", "https://", "/", "./", "amqp://", "postgres")):
            return m.group(0)
        count += 1
        quote = m.groupdict().get("q") or ""
        return f"{m.group('head')}{quote}{_describe(value)}{quote}"

    text = _QUOTED.sub(swap, text)
    text = _CONFIG_VALUE.sub(swap, text)
    return text, count
