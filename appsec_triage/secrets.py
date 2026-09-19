"""A credential-shaped value is a fact, not a judgement."""

from __future__ import annotations

import re

from .context.heuristics import shannon_entropy

_PLACEHOLDER_WORDS = re.compile(
    r"^(?:changeme|change_me|password|passwd|secret|token|example|sample|dummy|test|testing|"
    r"local|localhost|dev|development|root|toor|admin|user|guest|none|null|empty|todo|fixme|"
    r"your[_-]?\w*|my[_-]?\w*|xxx+|foo|bar|baz|placeholder|redacted|hidden|\*+|\.+|-+)$",
    re.IGNORECASE,
)
_TEMPLATE = re.compile(r"^\s*(?:\$\{[^}]*\}|%[^%]+%|\{\{[^}]*\}\}|<[^>]+>|\$[A-Z_]+)\s*$")

_DSN_PASSWORD = re.compile(r"^[a-z][a-z0-9+.\-]*://[^:/@\s]+:(?P<password>[^@/\s]*)@\S+$", re.IGNORECASE)

_MIN_KEY_LENGTH = 16
_MIN_KEY_ENTROPY = 3.5


def classify(value: str | None) -> tuple[str, str]:
    """(verdict, why) for a flagged literal, decided without a model."""
    if value is None:
        return "unclear", "the scanner reported no value to judge"

    raw = value.strip().strip("\"'")
    if not raw:
        return "placeholder", "the assignment is empty — there is no credential here"

    if m := _DSN_PASSWORD.match(raw):
        inner, why = classify(m.group("password"))
        return inner, f"the connection string carries the password `{m.group('password')}`: {why}"
    if _TEMPLATE.match(raw):
        return "placeholder", f"`{raw}` is a template reference, resolved at deploy time, not a value"
    if _PLACEHOLDER_WORDS.match(raw):
        return "placeholder", f"`{raw}` is a dictionary placeholder, not a generated credential"

    if _looks_like_identifier(raw):
        return "placeholder", f"`{raw[:60]}` is an identifier, path or service reference, not a credential"

    entropy = shannon_entropy(raw)
    if len(raw) >= _MIN_KEY_LENGTH and entropy >= _MIN_KEY_ENTROPY and not any(c.isspace() for c in raw):
        return (
            "credential",
            (f"{len(raw)} characters at entropy {entropy:.2f} with no dictionary structure — "
            "this is a generated credential, not a placeholder"),
        )
    if len(raw) < _MIN_KEY_LENGTH and entropy < _MIN_KEY_ENTROPY and _reads_as_a_word(raw):
        return "placeholder", f"`{raw}` is a short dictionary-shaped default, not a generated key"
    return (
        "unclear",
        f"{len(raw)} characters at entropy {entropy:.2f} — neither clearly generated nor clearly a default",
    )


def flagged_value(snippet: str | None, line_hint: str | None = None) -> str | None:
    """The literal on the flagged line, if the line has the shape of an assignment."""
    if not snippet:
        return None
    for line in (line_hint or snippet).splitlines():
        if m := re.search(r"""(?:=>|:=|[:=])\s*["']([^"'\n]*)["']\s*[;,)]?\s*$""", line):
            return m.group(1)
        if m := re.search(r"""(?:=>|:=|[:=])[ \t]*([^\n]*?)[ \t]*;?[ \t]*$""", line):
            return m.group(1)
    return None


_SEGMENTS = re.compile(r"[._/\\@:-]+")


def _looks_like_identifier(value: str) -> bool:
    """Is this a name rather than a generated secret?"""
    if value.startswith(("/", "@", "\\", "./", "%", "$")) or "\\" in value:
        return True
    if re.search(r"\.(php|ya?ml|json|xml|twig|html?|js|ts|png|jpe?g|svg|sql|txt|md)$", value, re.IGNORECASE):
        return True

    parts = [p for p in _SEGMENTS.split(value) if p]
    if len(parts) < 2:
        return False
    wordy = sum(1 for p in parts if p.isalpha() and len(p) >= 2 and (p.islower() or p.isupper() or p.istitle()))
    return wordy == len(parts)


def _reads_as_a_word(value: str) -> bool:
    """Letters, optionally with a trailing counter — `minio123`, `local`, `admin1`."""
    return bool(re.fullmatch(r"[A-Za-z]+[0-9]{0,4}", value))
