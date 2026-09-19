"""Command-line interface for appsec-triage."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from .. import ingest
from ..config import ConfigError
from ..diagnostics import cmd_doctor as cmd_doctor
from ..prompts import registry
from .commands import bench, misc, reports, scan, triage
from .parser import build_parser

cmd_bench = bench.cmd_bench
cmd_prompts = misc.cmd_prompts
cmd_providers = misc.cmd_providers
cmd_scanners = misc.cmd_scanners
cmd_sbom = scan.cmd_sbom
cmd_scan = scan.cmd_scan
cmd_run = scan.cmd_run
cmd_queue = reports.cmd_queue
cmd_variants = reports.cmd_variants
cmd_triage = triage.cmd_triage


def _force_utf8_streams() -> None:
    """Keep progress glyphs and paths printable on legacy Windows consoles."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, OSError):
            pass


def _load_dotenv(path: Path = Path(".env")) -> None:
    """Load local provider settings without replacing explicit environment values."""
    if not path.is_file():
        return
    try:
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            if key and key not in os.environ:
                os.environ[key] = value.strip().strip("'\"")
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    _force_utf8_streams()
    _load_dotenv()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        return args.func(args)
    except (ConfigError, ingest.IngestError, registry.PromptError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
