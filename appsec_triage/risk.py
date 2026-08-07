"""Runtime risk context supplied by the CI job, never by the service repository."""

from __future__ import annotations

import os
from collections.abc import Mapping

from .models import RiskContext

_VARIABLES = {
    "internet_exposed": "TRIAGE_INTERNET_EXPOSED",
    "auth_required": "TRIAGE_AUTH_REQUIRED",
    "business_critical": "TRIAGE_BUSINESS_CRITICAL",
}


def _tri_state(name: str, environ: Mapping[str, str], warnings: list[str]) -> bool | None:
    raw = environ.get(name)
    if raw is None or not raw.strip() or raw.strip().lower() == "unknown":
        return None
    value = raw.strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    warnings.append(f"{name}={raw!r} is invalid; expected true, false, or unknown")
    return None


def load(environ: Mapping[str, str] | None = None) -> RiskContext:
    """Read per-service facts and attach the shared Kubernetes platform baseline."""
    values = os.environ if environ is None else environ
    warnings: list[str] = []
    parsed = {
        field: _tri_state(variable, values, warnings)
        for field, variable in _VARIABLES.items()
    }
    return RiskContext(**parsed, warnings=warnings)
