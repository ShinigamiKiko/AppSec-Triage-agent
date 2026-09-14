"""A credential-shaped value is a fact, not a judgement.

Two things make this class different from every other one the pipeline handles.

**Reachability is irrelevant.** A key committed to a repository has leaked
whether or not any code path reaches it. Asking "is it used" answers a question
nobody needs: the remediation is rotation either way.

**Being wrong is asymmetric.** Calling a live key a placeholder hides a leak
until someone else finds it. Calling a placeholder live costs one glance. So the
only judgement made here is the one that can be made deterministically — a
dictionary word, a known template marker, a short low-entropy string is a
placeholder; anything else is reported as what it is and handed to a human with
the two questions that actually settle it.

No model call. The value never leaves the process, which also means it cannot
end up in a hosted provider's request log — the failure this whole class is
about.
"""

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
    """(verdict, why) for a flagged literal, decided without a model.

    `placeholder` closes the finding. `credential` reports it. `unclear` is for
    values that are neither obviously one nor the other — short but random, or
    long but wordy — and goes to a human rather than being guessed at.
    """
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
    """The literal on the flagged line, if the line has the shape of an assignment.

    Two forms, and the order matters. A quoted literal is taken as written. An
    unquoted one is everything to the end of the line, which is what a config
    file means — an earlier version stopped at the first bracket and read
    `%env(MAILER_URL)%` as nothing at all, then reported "no value to judge"
    about a line that plainly had one. The empty assignment is a real answer too:
    `APP_SECRET=` holds no credential, and saying so closes the finding.
    """
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
    """Is this a name rather than a generated secret?

    Entropy alone cannot tell them apart: `check_credentials` (17 chars) and
    `c66P9yWptBX79edHcglIw7NFyse35be` (31 chars, a real hardcoded HMAC key)
    score similarly. Structure can. A name is made of dictionary segments joined
    by delimiters; a generated key has no such seams — measured on a real
    project this rejected constant names, route paths, fully-qualified class
    names and container references while keeping every actual key.
    """
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
    """Letters, optionally with a trailing counter — `minio123`, `local`, `admin1`.

    A generated credential interleaves case and digits (`Xk92mPqRs7`); a typed
    default does not. That difference is what makes it safe to close the short
    values, and unsafe to close them on length alone.
    """
    return bool(re.fullmatch(r"[A-Za-z]+[0-9]{0,4}", value))
