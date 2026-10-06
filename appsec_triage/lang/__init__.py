"""Per-language rules for finding a package's imports and calls in project code.

One package per language (`go/`, `php/`, `js/`), each with its rules and its
stop-list (`builtins.txt`). The project-level functions here walk the files once
and apply the rules of whichever language each file is written in.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from .base import Bindings, CallMatch, LanguageRules
from .frameworks import DetectorResult, FrameworkDetector
from .go import GoRules
from .go import frameworks as go_frameworks
from .js import JavaScriptRules
from .js import frameworks as js_frameworks
from .js.aliases import FALLBACK_ALIASES, resolve_local
from .php import PhpRules
from .php import frameworks as php_frameworks

log = logging.getLogger(__name__)

_RULES: tuple[LanguageRules, ...] = (JavaScriptRules(), PhpRules(), GoRules())
# Every extension some language's rules read. A search or an audit that lists
# extensions of its own drifts from this one and stops opening files the rules can read.
SOURCE_SUFFIXES: frozenset[str] = frozenset().union(*(rules.suffixes for rules in _RULES))
_DETECTORS: tuple[FrameworkDetector, ...] = (
    *js_frameworks.DETECTORS, *php_frameworks.DETECTORS, *go_frameworks.DETECTORS)


def rules_for_path(path: str | Path) -> LanguageRules | None:
    suffix = Path(str(path)).suffix.lower()
    return next((r for r in _RULES if suffix in r.suffixes), None)


def rules_for_ecosystem(ecosystem: str) -> LanguageRules | None:
    name = (ecosystem or "").strip().lower()
    return next((r for r in _RULES if name in r.ecosystems), None)


@dataclass(slots=True)
class FileScan:
    rel: str
    text: str
    rules: LanguageRules
    bindings: Bindings = field(default_factory=Bindings)


def bind_project(files: list[FileScan], package: str, *, namespaces: list[str] | None = None,
                 aliases: dict[str, list[str]] | None = None) -> None:
    """Fill each file's bindings, following JS re-exports one module deep.

    A wrapper module (`utils/http.ts` exporting a configured client instance)
    is how most projects use an HTTP client; without this step every call
    through the wrapper would look unbound.
    """
    aliases = aliases or dict(FALLBACK_ALIASES)
    for scan in files:
        scan.bindings = scan.rules.bindings(scan.text, package, namespaces=namespaces)
    by_rel = {scan.rel: scan for scan in files}
    exported: dict[str, set[str]] = {}
    for scan in files:
        if not scan.bindings.empty:
            names = scan.rules.exports_bound(scan.text, scan.bindings)
            if names:
                exported[scan.rel] = names
    if not exported:
        return
    for scan in files:
        grew = False
        for spec, original, local in scan.rules.local_imports(scan.text):
            target = resolve_local(spec, scan.rel, by_rel, aliases)
            if target and original in exported.get(target, ()):
                scan.bindings.receivers.add(local)
                grew = True
        if grew:
            scan.rules._derive(scan.text, scan.bindings)


def detect_framework_condition(
    roots: list[Path], tokens: list[str]
) -> DetectorResult | None:
    """Try each language's framework detectors; return the first decided result."""
    if not roots or not tokens:
        return None
    
    for detector in _DETECTORS:
        try:
            result = detector.detect(roots, tokens)
            if result is not None and result.state in ("holds", "absent", "external"):
                log.info(
                    "framework detector: %s → %s (%s)",
                    detector.__class__.__name__, result.state, result.evidence[:80]
                )
                return result
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "%s raised %s: %s",
                detector.__class__.__name__, type(exc).__name__, exc
            )
    
    return None
