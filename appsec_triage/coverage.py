"""What did not run, and what that means the report is missing.

A scan where a scanner failed still produces a clean-looking report: fewer
findings, no errors, exit zero. The reader has no way to tell "we looked and
found little" from "half the tools never ran".

So the failure is translated into the thing a reader actually needs: not
"psalm exited 1", but "PHP taint analysis did not run, so cross-function
dataflow in PHP is not covered by this report".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_COVERAGE = {
    "semgrep": "pattern rules — secrets, PHP injection sinks, JS/TS weaknesses",
    "codeql": "dataflow traces for Go, Python, JS/TS, Java and C-family code",
    "govulncheck": "Go module, package, and vulnerable-symbol reachability",
    "psalm": "PHP taint analysis — cross-function dataflow that semgrep cannot see",
    "cdxgen+osv": "the dependency graph and network advisory lookup (SCA)",
    "gitleaks": "secrets in the working tree and in git history",
}


@dataclass(slots=True)
class Coverage:
    """Which scanners ran, which did not, and what is therefore missing."""

    ran: list[str] = field(default_factory=list)
    failed: list[tuple[str, str]] = field(default_factory=list)
    manifest_found: bool = False

    @property
    def complete(self) -> bool:
        return self.manifest_found and not self.failed

    def gaps(self) -> list[str]:
        """One sentence per failed scanner, in terms of lost coverage."""
        out = []
        for scanner, error in self.failed:
            what = _COVERAGE.get(scanner, "its rule set")
            out.append(f"{scanner} did not run — {what} is missing from this report ({error})")
        return out

    def as_dict(self) -> dict:
        return {
            "scanners_ran": self.ran,
            "scanners_failed": [s for s, _ in self.failed],
            "coverage_complete": self.complete,
            "coverage_gaps": self.gaps(),
        }


def read(scans_dir: Path) -> Coverage:
    """Read the scan manifest beside the reports, if the scan wrote one.

    An absent manifest is not a failure: `triage` can be pointed at reports
    produced elsewhere. It is recorded as "unknown" rather than "complete",
    because claiming full coverage on no evidence is the error this exists to
    prevent.
    """
    cov = Coverage()
    manifest = Path(scans_dir) / "scan-manifest.json"
    if not manifest.is_file():
        return cov

    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cov

    cov.manifest_found = True
    for entry in data.get("scans") or []:
        name = str(entry.get("scanner") or "?")
        if entry.get("ok"):
            cov.ran.append(name)
        else:
            error = str(entry.get("error") or "no reason recorded")
            cov.failed.append((name, error[:200]))
    return cov
