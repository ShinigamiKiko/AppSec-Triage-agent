"""How much it costs when a weakness class turns out to be real.

Kept apart from both the queue and the checks because both need it and neither
owns it. This is *consequence*, not likelihood and not the scanner's severity —
that one was measured to be a poor signal, since Semgrep records it on the rule
rather than the result and 207 of 296 findings on a real project arrived as
`unknown` severity.
"""

from __future__ import annotations

CWE_WEIGHT: dict[str, int] = {
    "CWE-94": 30, "CWE-95": 30, "CWE-98": 30, "CWE-502": 30, "CWE-78": 30, "CWE-77": 28,
    "CWE-89": 26, "CWE-90": 24, "CWE-91": 22, "CWE-917": 24, "CWE-643": 22, "CWE-943": 24,
    "CWE-798": 24, "CWE-259": 22, "CWE-321": 26, "CWE-256": 20, "CWE-522": 22,
    "CWE-287": 26, "CWE-306": 26, "CWE-208": 18,
    "CWE-918": 24, "CWE-22": 22, "CWE-23": 22, "CWE-611": 22, "CWE-434": 26,
    "CWE-295": 20, "CWE-319": 18, "CWE-327": 14, "CWE-328": 12, "CWE-326": 14,
    "CWE-347": 22, "CWE-916": 20,
    "CWE-79": 18, "CWE-352": 18, "CWE-601": 16,
    "CWE-330": 14, "CWE-338": 14,
    "CWE-489": 8, "CWE-942": 12, "CWE-703": 2, "CWE-400": 10, "CWE-20": 10,
}

DEFAULT_WEIGHT = 12


def weight(cwe: str | None) -> int:
    """Unclassified findings get the default rather than zero: an unknown class
    is not a harmless one, and treating it as such is how things get skipped."""
    return CWE_WEIGHT.get((cwe or "").upper(), DEFAULT_WEIGHT)
