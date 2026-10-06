"""Psalm taint analysis, the SAST engine for PHP (CodeQL has no PHP)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from xml.sax.saxutils import quoteattr

from .base import Availability, Scanner, ScanResult

class PsalmScanner(Scanner):
    """Psalm interprocedural taint analysis for PHP."""

    name = "psalm"

    def scan(self, target: Path, out_dir: Path) -> ScanResult:
        target = Path(target).resolve()
        # Psalm writes a file itself: a failed invocation must not reuse an old report.
        try:
            Path(out_dir).mkdir(parents=True, exist_ok=True)
            (Path(out_dir) / f"{self.name}{self.output_suffix}").unlink(missing_ok=True)
        except OSError as exc:
            return ScanResult(scanner=self.name, ok=False, error=f"cannot clear previous Psalm report: {exc}")
        configured = next((target / name for name in ("psalm.xml", "psalm.xml.dist")
                            if (target / name).is_file()), None)
        self._runtime_config = configured
        self._runtime_root = target
        temporary = None
        if configured is None or not (target / "vendor" / "autoload.php").is_file():
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".xml", prefix="psalm-autonomous-", dir=out_dir,
                encoding="utf-8", delete=False,
            ) as handle:
                # vendor/ is read for types through the autoloader, never
                # analysed: the taint paths wanted are the project's own, and
                # analysing an old dependency tree is what makes Psalm crash.
                autoload = target / "vendor" / "autoload.php"
                # Psalm refuses a config naming a directory that is not there,
                # so only the ones this project actually has are listed.
                skip = [target / name for name in ("vendor", "node_modules")
                        if (target / name).is_dir()]
                ignored = "".join(
                    f'      <directory name={quoteattr(str(path))} />\n' for path in skip)
                handle.write(
                    '<?xml version="1.0" encoding="UTF-8"?>\n'
                    '<psalm xmlns="https://getpsalm.org/schema/config" errorLevel="8"'
                    + (f' autoloader={quoteattr(str(autoload))}' if autoload.is_file() else "")
                    + '>\n'
                    '  <projectFiles>\n'
                    f'    <directory name={quoteattr(str(target))} />\n'
                    + (f'    <ignoreFiles>\n{ignored}    </ignoreFiles>\n' if ignored else "")
                    + '  </projectFiles>\n'
                    '</psalm>\n'
                )
                temporary = Path(handle.name)
            self._runtime_config = temporary
            # The project, not the directory the report is written to: --root is
            # what Psalm resolves the analysed tree against.
            self._runtime_root = target
        try:
            return super().scan(target, out_dir)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)

    @property
    def writes_stdout(self) -> bool:
        return False

    @property
    def success_exit_codes(self) -> frozenset[int]:
        """0 clean · 1/2 issues found; `report_health` is the real gate."""
        return frozenset({0, 1, 2})

    def _native_version_argv(self) -> list[str] | None:
        return [self.resolve_binary("psalm"), "--version"]

    def _probe_docker(self) -> Availability:
        return Availability(
            False, detail="psalm is native-only here (autonomous analysis uses the local Psalm binary)"
        )

    def report_health(self, path: Path) -> str | None:
        """Zero taint findings is a real clean result, not a broken run."""
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return f"report is not readable JSON: {exc}"
        if not isinstance(doc, dict) or not isinstance(doc.get("runs"), list) or not doc["runs"]:
            return "report is not SARIF"
        for run in doc["runs"]:
            if not isinstance(run, dict) or not isinstance(run.get("results"), list):
                return "SARIF run has no results array"
            for inv in run.get("invocations") or []:
                if inv.get("executionSuccessful") is False:
                    detail = (inv.get("exitCodeDescription") or "").strip()
                    return f"SARIF reports executionSuccessful=false{': ' + detail if detail else ''}"
        return None

    def _native_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        config = getattr(self, "_runtime_config", None)
        root = getattr(self, "_runtime_root", target)
        return [
            self.resolve_binary("psalm"),
            *( [f"--config={config}"] if config else []),
            "--taint-analysis",
            f"--report={out_file.resolve()}",
            f"--root={root}",
            "--no-progress",
            "--no-cache",
            "--no-diff",
        ]

    def _docker_scan_argv(self, target: Path, out_file: Path) -> list[str]:
        raise NotImplementedError
