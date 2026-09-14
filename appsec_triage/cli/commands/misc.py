"""Small informational and provider commands."""

from __future__ import annotations

import argparse

from ... import scanners
from ...config import ConfigError, list_providers, load_provider_config
from ...prompts import registry


def cmd_scanners(_: argparse.Namespace) -> int:
    for name, avail in scanners.probe_all().items(): print(f"{'✓' if avail.usable else '✗'} {name:<10} {avail}")
    print("\nRunning a scanner executes third-party code over the target tree.")
    return 0


def cmd_providers(_: argparse.Namespace) -> int:
    for name in list_providers():
        try:
            cfg = load_provider_config(name)
            key = "no key needed" if cfg.kind == "ollama" else ("key set" if cfg.api_key else "KEY MISSING")
            print(f"{name:<10} kind={cfg.kind:<9} model={cfg.model:<28} json={cfg.json_mode:<14} {key}")
        except ConfigError as exc: print(f"{name:<10} unavailable: {exc}")
    return 0


def cmd_prompts(_: argparse.Namespace) -> int:
    for cwe, prompt_id in registry.coverage().items(): print(f"{cwe:<10} -> {prompt_id}")
    print("\n(any CWE not listed falls back to `base`)")
    return 0
