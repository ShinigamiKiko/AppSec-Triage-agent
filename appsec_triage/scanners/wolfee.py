"""Wolfee: SCA findings with source-aware reachability, for every ecosystem."""

from __future__ import annotations

from pathlib import Path

from .base import Scanner, ScannerError

class WolfeeScanner(Scanner):
    """Wolfee SCA scan with source-aware dependency reachability."""

    name = "wolfee"

    @property
    def writes_stdout(self) -> bool:
        return False

    @property
    def success_exit_codes(self) -> frozenset[int]:
        return frozenset(range(256))

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("wolfee"), "version"]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        return [
            self.resolve_binary("wolfee"), "scan", "--reachable", str(target),
            "--format", "sarif", "--output", str(out_file), "--quiet",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise ScannerError("wolfee must run natively; configure binary: with the wolfee executable path")
