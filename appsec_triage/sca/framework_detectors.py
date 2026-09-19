"""Framework-aware configuration detectors for advisory preconditions."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

log = logging.getLogger(__name__)


@dataclass(slots=True)
class DetectorResult:
    """What a framework detector found."""
    state: str
    evidence: str = ""
    reason: str = ""
    file: str = ""
    
    @property
    def decided(self) -> bool:
        return self.state in ("holds", "absent")


def _clean_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


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


class FrameworkDetector:
    """Base class for framework-specific configuration readers."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        """Return a decided result, or None when this framework is not present."""
        raise NotImplementedError


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
                    text = _clean_comments(config_path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                
                # SSR mode check
                if "ssr" in [t.lower() for t in tokens]:
                    dynamic = _dynamic_result(text, "ssr", name)
                    if dynamic:
                        return dynamic
                    # Match: ssr: false, ssr:false, "ssr": false
                    ssr_false = re.search(r"""['"]?ssr['"]?\s*:\s*false""", text, re.IGNORECASE)
                    if ssr_false:
                        return DetectorResult(
                            "absent",
                            evidence=f"{name}: ssr: false",
                            reason="Nuxt is running in client-only mode; server-side rendering is disabled",
                            file=str(config_path.relative_to(root))
                        )
                    ssr_true = re.search(r"""['"]?ssr['"]?\s*:\s*true""", text, re.IGNORECASE)
                    if ssr_true:
                        return DetectorResult(
                            "holds",
                            evidence=f"{name}: ssr: true",
                            reason="Nuxt SSR is explicitly enabled",
                            file=str(config_path.relative_to(root))
                        )
                
                # Component usage check (UForm, UAuthForm, etc.)
                if any(t.startswith("U") and t[1:2].isupper() for t in tokens):
                    # Search for component usage in .vue files
                    component_names = [t for t in tokens if t.startswith("U") and t[1:2].isupper()]
                    found = self._search_components(root, component_names)
                    if found:
                        return DetectorResult(
                            "holds",
                            evidence="; ".join(found[:3]),
                            reason=f"Components {', '.join(component_names[:3])} are used",
                            file="source files"
                        )
                    return DetectorResult(
                        "absent",
                        evidence=f"searched {component_names[:3]} in .vue files",
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
    
    def _search_components(self, root: Path, component_names: list[str]) -> list[str]:
        """Search for component usage in .vue files."""
        found = []
        pattern = re.compile(
            r"<(" + "|".join(re.escape(c) for c in component_names) + r")[\s/>]",
            re.IGNORECASE
        )
        
        count = 0
        for vue_file in root.rglob("*.vue"):
            if count >= 100:  # limit search
                break
            if any(skip in vue_file.parts for skip in ("node_modules", ".nuxt", "dist")):
                continue
            try:
                text = vue_file.read_text(encoding="utf-8", errors="replace")
                match = pattern.search(text)
                if match:
                    line = text[:match.start()].count("\n") + 1
                    found.append(f"{vue_file.relative_to(root)}:{line} (<{match.group(1)}>)")
                    if len(found) >= 3:
                        break
                count += 1
            except OSError:
                continue
        
        return found


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
                text = _clean_comments(config_path.read_text(encoding="utf-8", errors="replace"))
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


class SymfonyDetector(FrameworkDetector):
    """Symfony YAML configuration parser."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        for root in roots:
            # Check config/packages/*.yaml
            config_dir = root / "config" / "packages"
            if not config_dir.is_dir():
                continue
            
            yaml_files = list(config_dir.glob("prod/*.yaml")) + list(config_dir.glob("*.yaml"))
            yaml_files += list(config_dir.glob("production/*.yaml"))
            for yaml_file in yaml_files:
                try:
                    text = yaml_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                try:
                    yaml.safe_load(text)
                except yaml.YAMLError:
                    continue
                
                for token in tokens:
                    if token in text:
                        if re.search(rf"{re.escape(token)}\s*:\s*[^\n]*%env\(", text, re.IGNORECASE):
                            return DetectorResult(
                                "external", evidence=f"{yaml_file.name}: {token} uses %env(...)",
                                reason=f"значение {token} задаётся окружением Symfony",
                                file=str(yaml_file.relative_to(root)),
                            )
                        # Check if it's set to true/false/enabled/disabled
                        pattern = re.compile(
                            rf"{re.escape(token)}\s*:\s*(true|false|enabled|disabled|yes|no)",
                            re.IGNORECASE
                        )
                        match = pattern.search(text)
                        if match:
                            value = match.group(1).lower()
                            is_enabled = value in ("true", "enabled", "yes")
                            return DetectorResult(
                                "holds" if is_enabled else "absent",
                                evidence=f"{yaml_file.name}: {match.group(0)}",
                                reason=f"Symfony configuration sets {token} to {value}",
                                file=str(yaml_file.relative_to(root))
                            )
        
        return None


class LaravelDetector(FrameworkDetector):
    """Laravel configuration parser."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        for root in roots:
            config_dir = root / "config"
            if not config_dir.is_dir():
                continue
            
            # Laravel stores config in config/*.php
            for php_file in config_dir.glob("*.php"):
                try:
                    text = _clean_comments(php_file.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                
                for token in tokens:
                    # Match: 'key' => true, "key" => false, etc.
                    pattern = re.compile(
                        rf"""['"]{re.escape(token)}['"]\s*=>\s*(true|false|env\s*\()""",
                        re.IGNORECASE
                    )
                    match = pattern.search(text)
                    if match:
                        value = match.group(1).lower()
                        if value == "env(":
                            return DetectorResult(
                                "external", evidence=f"{php_file.name}: {match.group(0)}",
                                reason=f"значение {token} задаётся через Laravel env()",
                                file=str(php_file.relative_to(root)),
                            )
                        is_enabled = value == "true"
                        return DetectorResult(
                            "holds" if is_enabled else "absent",
                            evidence=f"{php_file.name}: {match.group(0)}",
                            reason=f"Laravel config sets {token} to {value}",
                            file=str(php_file.relative_to(root))
                        )
        
        return None


class GoDetector(FrameworkDetector):
    """Go main.go / configuration parser."""
    
    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        for root in roots:
            # Search main.go, cmd/*/main.go, and config files
            candidates = list(root.glob("main.go"))
            candidates.extend(root.glob("cmd/*/main.go"))
            candidates.extend(root.glob("**/*.go"))
            
            for go_file in candidates[:50]:  # limit search
                if any(skip in go_file.parts for skip in ("vendor", "testdata")):
                    continue
                
                try:
                    text = _clean_comments(go_file.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    continue
                
                for token in tokens:
                    # Look for: token := true, token = false, token: true
                    assignments = re.findall(
                        rf"\b{re.escape(token)}\s*[:=]+\s*(?:true|false|[A-Za-z_]\w*)",
                        text, re.IGNORECASE,
                    )
                    if len(assignments) > 1:
                        return DetectorResult(
                            "external",
                            evidence=f"{go_file.relative_to(root)}: {token} assigned multiple times",
                            reason=f"значение {token} может быть переприсвоено во время выполнения",
                            file=str(go_file.relative_to(root)),
                        )
                    pattern = re.compile(
                        rf"\b{re.escape(token)}\s*[:=]+\s*(true|false|[A-Za-z_]\w*)",
                        re.IGNORECASE
                    )
                    match = pattern.search(text)
                    if match:
                        value = match.group(1).lower()
                        if value not in ("true", "false"):
                            return DetectorResult(
                                "external", evidence=f"{go_file.relative_to(root)}: {match.group(0)}",
                                reason=f"значение {token} вычисляется в Go-коде",
                                file=str(go_file.relative_to(root)),
                            )
                        is_enabled = value == "true"
                        line = text[:match.start()].count("\n") + 1
                        return DetectorResult(
                            "holds" if is_enabled else "absent",
                            evidence=f"{go_file.relative_to(root)}:{line}: {match.group(0)}",
                            reason=f"Go code sets {token} to {value}",
                            file=str(go_file.relative_to(root))
                        )
        
        return None


# Registry of all detectors
_DETECTORS: list[FrameworkDetector] = [
    NuxtDetector(),
    NextDetector(),
    SymfonyDetector(),
    LaravelDetector(),
    GoDetector(),
]


def detect_framework_condition(
    roots: list[Path], tokens: list[str]
) -> DetectorResult | None:
    """Try each detector; return the first decided result."""
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
