"""Symfony (config/packages/*.yaml) and Laravel (config/*.php) settings."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from ..frameworks import DetectorResult, FrameworkDetector, clean_comments


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
                    text = clean_comments(php_file.read_text(encoding="utf-8", errors="replace"))
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


DETECTORS: tuple[FrameworkDetector, ...] = (SymfonyDetector(), LaravelDetector())
