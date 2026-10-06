"""Nuxt and Next: SSR mode, modules and components, read from the framework config."""

from __future__ import annotations

import re
from pathlib import Path

from ..frameworks import DetectorResult, FrameworkDetector, clean_comments, project_files
from .rules import JavaScriptRules

_MAX_COMPONENT_FILES = 4000
_MAX_BYTES = 600_000
_STRING = re.compile(r"""(['"`])(?:\\.|(?!\1).)*\1""", re.DOTALL)


def _top_level_values(text: str, name: str) -> set[str]:
    """`true`/`false` given to `name` as a property of the config object itself.

    `routeRules: {'/admin/**': {ssr: false}}` and `$development: {ssr: false}` switch
    one route or one environment, not the application: only depth one counts.
    """
    # Braces inside strings are text, not structure; blank them, keeping the offsets.
    bare = _STRING.sub(lambda m: m.group(1) + " " * (len(m.group(0)) - 2) + m.group(1), text)
    values: set[str] = set()
    for match in re.finditer(rf"""['"]?{re.escape(name)}['"]?\s*:\s*(true|false)\b""", text, re.IGNORECASE):
        if bare.count("{", 0, match.start()) - bare.count("}", 0, match.start()) == 1:
            values.add(match.group(1).lower())
    return values


def _dynamic_result(text: str, token: str, name: str) -> DetectorResult | None:
    """Return external when a setting is sourced from runtime configuration."""
    match = re.search(
        rf"(?:{re.escape(token)}.{{0,180}}(?:process\.env|import\.meta\.env)|"
        rf"(?:process\.env|import\.meta\.env).{{0,180}}{re.escape(token)})",
        text, re.IGNORECASE | re.DOTALL,
    )
    if match:
        return DetectorResult(
            "external", evidence=f"{name}: {match.group(0)[:180].strip()}",
            reason=f"значение {token} зависит от переменной окружения",
            file=name,
        )
    return None


class NuxtDetector(FrameworkDetector):
    """Nuxt.js configuration parser for SSR, modules, and component usage."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        """Check nuxt.config.{ts,js,mjs} for SSR mode and specific components."""
        for root in roots:
            for name in ("nuxt.config.ts", "nuxt.config.js", "nuxt.config.mjs"):
                config_path = root / name
                if not config_path.is_file():
                    continue
                
                try:
                    text = clean_comments(config_path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                
                # SSR mode check
                if "ssr" in [t.lower() for t in tokens]:
                    dynamic = _dynamic_result(text, "ssr", name)
                    if dynamic:
                        return dynamic
                    # The application's own `ssr`, not one route's or one environment's.
                    ssr = _top_level_values(text, "ssr")
                    if ssr == {"false"}:
                        return DetectorResult(
                            "absent",
                            evidence=f"{name}: ssr: false",
                            reason="Nuxt is running in client-only mode; server-side rendering is disabled",
                            file=str(config_path.relative_to(root))
                        )
                    if ssr == {"true"}:
                        return DetectorResult(
                            "holds",
                            evidence=f"{name}: ssr: true",
                            reason="Nuxt SSR is explicitly enabled",
                            file=str(config_path.relative_to(root))
                        )
                
                # Component usage check (UForm, UAuthForm, etc.)
                if any(t.startswith("U") and t[1:2].isupper() for t in tokens):
                    # Search for the components in the project's own source files
                    component_names = [t for t in tokens if t.startswith("U") and t[1:2].isupper()]
                    found, complete = self._search_components(root, component_names)
                    if found:
                        return DetectorResult(
                            "holds",
                            evidence="; ".join(found[:3]),
                            reason=f"Components {', '.join(component_names[:3])} are used",
                            file="source files"
                        )
                    if not complete:
                        # Not every file was read: "not found" is not "not used".
                        return None
                    return DetectorResult(
                        "absent",
                        evidence=f"searched {component_names[:3]} in the project's source files",
                        reason=f"Components {', '.join(component_names[:3])} not found in source",
                        file="source tree"
                    )
                
                # SVGO configuration
                if "removeScripts" in tokens or "svgo" in [t.lower() for t in tokens]:
                    dynamic = _dynamic_result(text, "svgo", name)
                    if dynamic:
                        return dynamic
                    # Match: svgo: false, svgo: { ... }, svgoConfig
                    svgo_false = re.search(r"""['"]?svgo['"]?\s*:\s*false""", text, re.IGNORECASE)
                    if svgo_false:
                        return DetectorResult(
                            "absent",
                            evidence=f"{name}: svgo: false",
                            reason="SVGO optimization is disabled in nuxt.config",
                            file=str(config_path.relative_to(root))
                        )
                    
                    # Check for removeScripts in svgo config block
                    svgo_config = re.search(
                        r"""svgo\s*:\s*\{([^}]+)\}""", text, re.IGNORECASE | re.DOTALL
                    )
                    if svgo_config:
                        config_block = svgo_config.group(1)
                        if "removeScripts" in config_block:
                            return DetectorResult(
                                "holds",
                                evidence=f"{name}: svgo config contains removeScripts",
                                reason="SVGO removeScripts plugin is configured",
                                file=str(config_path.relative_to(root))
                            )
        
        return None  # Nuxt not detected
    
    def _search_components(self, root: Path, component_names: list[str]) -> tuple[list[str], bool]:
        """(where the components are named, whether every source file was read).

        A component is used as `<UForm>`, as `<u-form>`, lazily (`<LazyUForm>`), from a
        render function or by `resolveComponent('UForm')` — in a template or in a script,
        so every first-party source file is read and any spelling of the name counts.
        """
        spellings: list[str] = []
        for name in component_names:
            kebab = re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()
            spellings += [rf"(?:Lazy)?{re.escape(name)}", rf"(?:lazy-)?{re.escape(kebab)}"]
        pattern = re.compile(r"(?<![\w-])(" + "|".join(spellings) + r")(?![\w-])")

        files, complete = project_files(root, tuple(JavaScriptRules.suffixes), _MAX_COMPONENT_FILES)
        found: list[str] = []
        for path in files:
            try:
                if path.stat().st_size > _MAX_BYTES:
                    complete = False
                    continue
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                complete = False
                continue
            match = pattern.search(text)
            if match:
                line = text.count("\n", 0, match.start()) + 1
                found.append(f"{path.relative_to(root).as_posix()}:{line} (<{match.group(1)}>)")
                if len(found) >= 3:
                    break
        return found, complete


class NextDetector(FrameworkDetector):
    """Next.js configuration parser."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        for root in roots:
            config_path = next((root / name for name in (
                "next.config.js", "next.config.mjs", "next.config.ts"
            ) if (root / name).is_file()), None)
            if config_path is None:
                continue
            
            try:
                text = clean_comments(config_path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            
            # SSR/SSG check
            if "ssr" in [t.lower() for t in tokens] or "ssg" in [t.lower() for t in tokens]:
                # Next.js is SSR by default; check for output: 'export'
                if re.search(r"""output\s*:\s*['"]export['"]""", text):
                    return DetectorResult(
                        "absent",
                        evidence=f"{config_path.name}: output: 'export'",
                        reason="Next.js is configured for static export (SSG), not SSR",
                        file=str(config_path.relative_to(root))
                    )
        
        return None


DETECTORS: tuple[FrameworkDetector, ...] = (NuxtDetector(), NextDetector())
