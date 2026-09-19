"""Given one confirmed weakness, find the same construct elsewhere."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

_SKIP_DIRS = {
    ".git", "vendor", "node_modules", "venv", ".venv", "target", "build",
    "dist", "__pycache__", ".idea", ".vscode", "var", "cache",
}
_SOURCE_SUFFIXES = {".php", ".js", ".jsx", ".ts", ".tsx", ".py", ".go", ".rb", ".java", ".kt", ".cs", ".rs"}

_MAX_FILES = 6000
_MAX_BYTES = 400_000
_MIN_SHAPE = 12

_NORMALIZE = [
    (re.compile(r"""(["'])(?:\.|(?!\1).)*\1"""), '""'),
    (re.compile(r"\b\d+\b"), "0"),
    (re.compile(r"\$\w+"), "$V"),
    (re.compile(r"(->|\.)\w+(?![\w(])"), r"\1M"),
    (re.compile(r"\s+"), " "),
]


def shape(line: str) -> str:
    """The security-relevant skeleton of a line."""
    out = line.strip()
    for pattern, repl in _NORMALIZE:
        out = pattern.sub(repl, out)
    return out.strip()


def is_distinctive(text: str) -> bool:
    """Would this shape find something, or everything?"""
    if len(text) < _MIN_SHAPE:
        return False
    return bool(re.search(r"\w\s*\(", text) or re.search(r"[=!]==|===|!==", text))


@dataclass(slots=True)
class Variant:
    """A place that looks like a known-real defect, and was never reported."""

    seed_finding_id: str
    seed_location: str
    file_path: str
    line: int
    text: str

    def as_dict(self) -> dict:
        return {
            "seed_finding_id": self.seed_finding_id,
            "seed_location": self.seed_location,
            "file_path": self.file_path,
            "line": self.line,
            "text": self.text,
        }


def _reported(findings) -> set[tuple[str, int]]:
    """Places a scanner already flagged, by (filename, line)."""
    out = set()
    for f in findings:
        name = Path(f.code_context.file_path.replace("\\", "/")).name
        if f.code_context.start_line:
            out.add((name, f.code_context.start_line))
    return out


def seed_is_trustworthy(record) -> tuple[bool, str]:
    """May this confirmation be used to search for more like it?"""
    verdict = record.verdict
    if verdict.confidence_band == "low":
        return False, "measured certainty is low — the evidence behind it did not hold up"
    if any(o.startswith(("hallucinated_evidence", "no_evidence")) for o in record.overrides):
        return False, "nothing in it could be verified against the input"
    return True, (
        "decided without a model" if record.decided_by == "heuristics" else "model verdict, evidence verified"
    )


def search(seeds, findings, roots: list[Path], *, max_per_seed: int = 20) -> list[Variant]:
    """Find each seed's shape elsewhere in the tree."""
    wanted: dict[str, list] = {}
    for record, snippet in seeds:
        flagged = (snippet or "").strip().splitlines()
        if not flagged:
            continue
        key = shape(flagged[0])
        if not is_distinctive(key):
            log.debug("seed %s has no distinctive shape: %r", record.finding_id, key)
            continue
        wanted.setdefault(key, []).append(record)

    if not wanted:
        return []

    already = _reported(findings)
    found: list[Variant] = []
    per_seed: dict[str, int] = {}
    seen: set[tuple[str, str, int]] = set()
    scanned = 0

    for root in roots:
        for path in Path(root).rglob("*"):
            if scanned >= _MAX_FILES:
                log.warning("variant search hit the %d-file budget; results are partial", _MAX_FILES)
                return found
            if path.suffix.lower() not in _SOURCE_SUFFIXES or _SKIP_DIRS & set(path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            scanned += 1

            for n, line in enumerate(lines, 1):
                key = shape(line)
                for record in wanted.get(key, ()):
                    seed_loc = f"{record.file_path}:{record.start_line or '?'}"
                    if (path.name, n) in already:
                        continue
                    if per_seed.get(record.finding_id, 0) >= max_per_seed:
                        continue
                    if (seed_loc, str(path), n) in seen:
                        continue
                    seen.add((seed_loc, str(path), n))
                    per_seed[record.finding_id] = per_seed.get(record.finding_id, 0) + 1
                    found.append(
                        Variant(
                            seed_finding_id=record.finding_id,
                            seed_location=seed_loc,
                            file_path=str(path),
                            line=n,
                            text=line.strip()[:200],
                        )
                    )
    log.info("variant search: %d candidate(s) from %d seed shape(s) over %d file(s)", len(found), len(wanted), scanned)
    return found
