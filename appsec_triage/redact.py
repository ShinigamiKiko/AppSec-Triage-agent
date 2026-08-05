"""Send a secret's shape to the model, never the secret.

Triaging a hardcoded credential means answering "is this a live key or a
placeholder". That question is settled by the *shape* of the value — its length,
its alphabet, how random it looks — together with its name and the file it sits
in. The characters themselves add nothing to the judgement.

They do add risk. On a real project the flagged lines held 32- and 64-character
signing keys and OAuth secrets; sending those to a hosted model puts live
credentials into a third party's request logs, which is the sort of thing a
security tool should not do while looking for exactly that problem.

So high-entropy values are replaced with a description of themselves before the
package is rendered. Low-entropy ones are left alone on purpose: `toor`,
`changeme` and `local` are *evidence of being a placeholder*, and hiding them
would remove the very thing that closes the finding.

Redaction happens in the evidence package, so grounding still works — the model
quotes the redacted line, and that line is what the checker compares against.
"""

from __future__ import annotations

import re

from .context.heuristics import shannon_entropy

_QUOTED = re.compile(r"""(?P<head>\s*(?:=>|:=|[:=])\s*)(?P<q>["'])(?P<value>[^"'\n]{12,})(?P=q)""")
_CONFIG_VALUE = re.compile(r"""(?P<head>^[ \t]*[\w.\-]+[ \t]*[:=][ \t]*)(?P<value>[A-Za-z0-9+/_-]{16,}={0,2})[ \t]*$""", re.M)

_ENTROPY_FLOOR = 3.6
_MIN_LENGTH = 16


def _describe(value: str) -> str:
    kinds = []
    if re.fullmatch(r"[0-9a-f]+", value, re.I):
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
    """Replace high-entropy assigned values with a description. Returns the count."""
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
