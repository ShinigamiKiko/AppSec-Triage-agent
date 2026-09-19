"""Running the scanners, not just reading their output."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from ..config import ConfigError, list_scanners, load_scanner_config
from .base import Availability, Scanner, ScannerError, ScanResult
from .tools import REGISTRY


def build_scanner(name: str) -> Scanner:
    try:
        klass = REGISTRY[name]
    except KeyError:
        raise ConfigError(f"unknown scanner '{name}'. Known: {sorted(REGISTRY)}") from None
    return klass(load_scanner_config(name))


def probe_all() -> dict[str, Availability]:
    """What can actually run here, right now."""
    out: dict[str, Availability] = {}
    for name in list_scanners():
        try:
            out[name] = build_scanner(name).available()
        except ConfigError as exc:
            out[name] = Availability(False, detail=str(exc))
    return out


def scan_all(target: Path, scanners: list[str], out_dir: Path, on_start=None) -> list[ScanResult]:
    results: list[ScanResult] = []
    for name in scanners:
        if on_start:
            on_start(name)
        results.append(build_scanner(name).scan(target, out_dir))
    return results


def write_manifest(target: Path, results: list[ScanResult], out_dir: Path) -> Path:
    """Provenance: which tool, which version, which exact argv, how many findings."""
    path = Path(out_dir) / "scan-manifest.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "scanned_at": datetime.now(UTC).isoformat(),
                "target": str(Path(target).resolve()),
                "scans": [r.as_dict() for r in results],
                "total_findings": sum(r.findings for r in results if r.ok),
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    return path


__all__ = [
    "REGISTRY",
    "Availability",
    "ScanResult",
    "Scanner",
    "ScannerError",
    "build_scanner",
    "probe_all",
    "scan_all",
    "write_manifest",
]
