"""Opengrep: fast pattern and intra-file taint rules, run before Psalm on PHP code.

It does not replace Psalm. Opengrep reads every file — templates included — in
seconds and finds what a pattern can see; Psalm then follows the data across
functions. Every Opengrep result goes to the model for confirmation (see
`pipeline._model_confirms`): a pattern match is a lead, never a verdict.
"""

from __future__ import annotations

from pathlib import Path

from .base import Availability, Scanner, ScannerError, ScanResult


# Directories no scan of first-party code looks into.
_EXCLUDE = (".git", "node_modules", "venv", ".venv", "vendor", "target", "build", "dist",
            "__pycache__", "var", "appsec-out*")


class OpengrepScanner(Scanner):
    """`opengrep scan` with the rule packs from the scanner profile, SARIF into the out dir."""

    name = "opengrep"

    @property
    def writes_stdout(self) -> bool:
        return False

    def _rules(self) -> list[str]:
        """Rule files or registry packs (`p/security-audit`) as the profile lists them."""
        return [str(Path(rule).expanduser()) if not str(rule).startswith(("p/", "r/")) else str(rule)
                for rule in self.cfg.rules]

    def available(self) -> Availability:
        missing = [rule for rule in self._rules() if not rule.startswith(("p/", "r/")) and not Path(rule).exists()]
        if not self.cfg.rules:
            return Availability(False, detail="no rules configured (`rules:` in configs/scanners/opengrep.yaml)")
        if missing:
            return Availability(False, detail=f"rule file(s) not found: {', '.join(missing)}")
        return super().available()

    def scan(self, target: Path, out_dir: Path) -> ScanResult:
        # Opengrep writes the report itself: a failed run must not leave the previous one
        # behind to be read as this run's result.
        (Path(out_dir) / f"{self.name}{self.output_suffix}").unlink(missing_ok=True)
        return super().scan(target, out_dir)

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("opengrep"), "--version"]

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        argv = [self.resolve_binary("opengrep"), "scan"]
        for rule in self._rules():
            argv += ["--config", rule]
        argv += ["--taint-intrafile", "--dataflow-traces", "--quiet",
                 f"--timeout={self.cfg.per_file_timeout_s}", f"--sarif-output={out_file}"]
        for name in _EXCLUDE:
            argv += ["--exclude", name]
        argv.append(str(target))
        return argv

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise ScannerError("opengrep runs natively here; set `binary:` in configs/scanners/opengrep.yaml")
