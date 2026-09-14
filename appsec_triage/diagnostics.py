"""`doctor`: can this machine actually run a scan, and what is missing?

Separate from the CLI because the answer is about the environment, not about
argument parsing — and because it is the first thing to run in a container
before anything is spent on inference.
"""

from __future__ import annotations

import argparse
import os
import shutil
from pathlib import Path

from . import scanners
from .config import (
    ConfigError,
    list_providers,
    load_lsp_config,
    load_pipeline_config,
    load_provider_config,
)
from .prompts import registry


def cmd_doctor(_: argparse.Namespace) -> int:
    ok = True

    print("configs:")
    for label, loader in (("pipeline.yaml", load_pipeline_config), ("lsp.yaml", load_lsp_config)):
        try:
            loader()
            print(f"  {label}: ok")
        except (ConfigError, TypeError, ValueError) as exc:
            ok = False
            print(f"  {label}: FAILED — {exc}")

    print("prompt packs:")
    try:
        pack = registry.load_pack()
        print(f"  default: {len(pack)} prompt(s) — {', '.join(sorted(pack))}")
    except Exception as exc:  # noqa: BLE001 - doctor reports, never raises
        ok = False
        print(f"  FAILED: {exc}")

    print("providers:")
    for name in list_providers():
        try:
            cfg = load_provider_config(name)
            print(f"  {name}: ok ({cfg.kind}/{cfg.model})")
        except ConfigError as exc:
            print(f"  {name}: {exc}")

    print("scanners:")
    usable = 0
    for name, avail in scanners.probe_all().items():
        usable += avail.usable
        print(f"  {name}: {avail}")
    if not usable:
        print("  (none usable — `scan`/`run` need at least one; `triage` still works on existing reports)")

    _doctor_sca()
    _doctor_php()
    _doctor_lsp()
    return 0 if ok else 1


def _doctor_sca() -> None:
    """The dependency half, which has its own toolchain and its own failure.

    cdxgen was load-bearing and unmentioned here: an operator could read a clean
    `doctor`, run a scan, and get a report where every package looked direct
    because the graph was never built.
    """
    from .sca import sbom

    print("зависимости (SCA):")
    found = sbom.available()
    if found:
        print(f"  cdxgen: ok ({found})")
    else:
        print("  cdxgen: MISSING — граф зависимостей построить нечем: "
              "прямые и транзитивные пакеты не различить, а совет «что обновлять» "
              "будет неверным. `npm install -g @cyclonedx/cdxgen`")
    print("  базы уязвимостей: нужен доступ к osv.dev, github.com, "
          "api.first.org (EPSS), cisa.gov (KEV)")


def _doctor_php() -> None:
    """PHP is the one language whose cross-function analysis lives entirely in the
    toolchain checked here: no CodeQL, so phpactor (LSP) and Psalm (taint) are it.
    A silent gap here is why every CWE-89 finding once landed in `unknown`, so the
    diagnostics are explicit rather than folded into the generic scanner probe."""
    print("php toolchain (for PHP targets — phpactor is load-bearing, PHP has no CodeQL):")

    php = shutil.which("php")
    print(f"  php: {'ok (' + php + ')' if php else 'MISSING — required by phpactor and Psalm'}")
    composer = shutil.which("composer")
    print(f"  composer: {'ok' if composer else 'MISSING — needed to install deps in the target for Psalm autoload'}")

    phar = os.environ.get("PHPACTOR_PHAR", "/opt/phpactor.phar")
    if Path(phar).expanduser().is_file():
        print(f"  phpactor (LSP): ok ({phar})")
    elif shutil.which("phpactor"):
        print(f"  phpactor (LSP): ok (on PATH; $PHPACTOR_PHAR unset, config default {phar!r} absent)")
    else:
        print(f"  phpactor (LSP): MISSING — set $PHPACTOR_PHAR or place phpactor.phar at {phar!r}. "
              "Without it PHP loses all cross-function context and CWE-89 falls to `unknown`.")

    try:
        avail = scanners.build_scanner("psalm").available()
        print(f"  psalm (taint): {avail}")
    except (ConfigError, KeyError) as exc:
        print(f"  psalm (taint): unavailable — {exc}")
    print("  note: Psalm needs `composer install`/`dump-autoload` in the target (work on a copy).")


def _doctor_lsp() -> None:
    """Show every configured language server, not only the PHP-specific stack."""
    cfg = load_lsp_config()
    print("language servers (required for php/python/go/ts-js; CodeQL remains the SAST engine):")
    for language, spec in sorted(cfg.servers.items()):
        command = list(spec.get("command") or [])
        executable = command[0] if command else ""
        present = bool(executable and (Path(executable).expanduser().is_file() or shutil.which(executable)))
        mandatory = "required" if language in cfg.required_languages else "optional"
        print(f"  {language} ({mandatory}): {'launcher found' if present else 'MISSING launcher'} — {' '.join(command)}")
