"""Source file extension detection from APPSEC_ECOSYSTEMS environment variable."""

import os
import logging
from pathlib import Path

log = logging.getLogger(__name__)

ECOSYSTEM_SUFFIXES = {
    "npm": {".js", ".jsx", ".ts", ".tsx", ".vue", ".svelte", ".astro", ".mjs", ".cjs"},
    "composer": {".php"},
    "packagist": {".php"},
    "pypi": {".py"},
    "python": {".py"},
    "go": {".go"},
    "golang": {".go"},
    "maven": {".java", ".kt"},
    "java": {".java", ".kt"},
    "rubygems": {".rb"},
    "cargo": {".rs"},
    "nuget": {".cs"},
}

CONFIG_SUFFIXES = {".yaml", ".yml", ".json", ".toml", ".ini", ".env", ".xml", ".neon"}
# Templates call a language's code by name (`|spaceless`, `{{ format_args(...) }}`), but
# no parser here reads them: they join the text searches that also read configuration,
# never the language rules that parse imports.
TEMPLATE_SUFFIXES = {
    "npm": {".hbs", ".handlebars", ".ejs", ".pug"},
    "composer": {".twig"},
    "packagist": {".twig"},
    "pypi": {".jinja", ".jinja2", ".j2"},
    "python": {".jinja", ".jinja2", ".j2"},
}
DEFAULT_SOURCE_SUFFIXES = set().union(*ECOSYSTEM_SUFFIXES.values(), CONFIG_SUFFIXES,
                                      *TEMPLATE_SUFFIXES.values())


class DetectionError(RuntimeError):
    """Raised when APPSEC_ECOSYSTEMS is not set or contains unknown ecosystems."""


def get_source_suffixes(
    roots: list[Path],
    *,
    for_ecosystem: str | None = None,
    include_configs: bool = False,
) -> set[str]:
    """Determine source file extensions for searching."""
    # Specific ecosystem (searching for a specific package)
    if for_ecosystem:
        key = for_ecosystem.strip().lower()
        if key not in ECOSYSTEM_SUFFIXES:
            raise DetectionError(
                f"Unknown ecosystem '{for_ecosystem}'. "
                f"Supported: {', '.join(sorted(ECOSYSTEM_SUFFIXES))}"
            )
        return ECOSYSTEM_SUFFIXES[key].copy()
    
    # Global search - all ecosystems from ENV
    raw = os.getenv("APPSEC_ECOSYSTEMS")
    if not raw or not raw.strip():
        raise DetectionError(
            "APPSEC_ECOSYSTEMS environment variable is not set. "
            "Set it in your .gitlab-ci.yml, for example:\n"
            "  variables:\n"
            "    APPSEC_ECOSYSTEMS: npm,pypi"
        )
    
    ecosystems = [eco.strip().lower() for eco in raw.split(",") if eco.strip()]
    if not ecosystems:
        raise DetectionError(
            f"APPSEC_ECOSYSTEMS is empty: {raw!r}. "
            "Provide comma-separated ecosystem names."
        )
    
    suffixes = set()
    for eco in ecosystems:
        if eco not in ECOSYSTEM_SUFFIXES:
            raise DetectionError(
                f"Unknown ecosystem '{eco}' in APPSEC_ECOSYSTEMS={raw!r}. "
                f"Supported: {', '.join(sorted(ECOSYSTEM_SUFFIXES))}"
            )
        suffixes.update(ECOSYSTEM_SUFFIXES[eco])
    
    if include_configs:
        suffixes.update(CONFIG_SUFFIXES)
        for eco in ecosystems:
            suffixes.update(TEMPLATE_SUFFIXES.get(eco, ()))
    
    log.info("Using ecosystems from APPSEC_ECOSYSTEMS: %s → %d extensions", raw, len(suffixes))
    return suffixes
