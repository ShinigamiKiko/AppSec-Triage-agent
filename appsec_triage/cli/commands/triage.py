"""Triage command."""

from __future__ import annotations

import argparse
from pathlib import Path

from ..common import run_triage


def cmd_triage(args: argparse.Namespace) -> int:
    return run_triage(args, Path(args.input), Path(args.out), [Path(r) for r in args.source_root])
