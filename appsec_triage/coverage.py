"""What did not run, and what that means the report is missing."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

_COVERAGE = {
    "codeql": "dataflow traces for Go, Python, JS/TS, Java and C-family code",
    "psalm": "PHP taint analysis — source-to-sink paths across functions",
    "wolfee": "vulnerable dependencies (SCA) with source-aware reachability",
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
    """Read the scan manifest beside the reports, if the scan wrote one."""
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
