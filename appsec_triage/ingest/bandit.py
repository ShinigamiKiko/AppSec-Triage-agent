"""Bandit adapter (Python SAST).

Bandit's JSON is small but has three quirks worth handling properly:

* `code` comes with line numbers glued to the front of each line
  (`"12 from pathlib import Path\\n"`). Left as-is, every quote the model copies
  carries a number that is not in the source, and the report reads wrong. We
  strip them and keep the real line numbers separately.
* `issue_cwe` is an object (`{"id": 78, ...}`), not a string.
* `issue_confidence` is the *scanner's* own certainty, which is genuine evidence
  and distinct from the model's confidence. It is carried through as a signal.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterator

from ..models import CodeContext, Finding, Severity

_LINE_PREFIX = re.compile(r"^\s*(\d+)\s?", re.M)

_SEVERITY = {
    "HIGH": Severity.high,
    "MEDIUM": Severity.medium,
    "LOW": Severity.low,
    "UNDEFINED": Severity.unknown,
}


def _clean_code(code: str) -> str:
    """Strip Bandit's leading line numbers so quotes match the real source."""
    return _LINE_PREFIX.sub("", code or "").strip()


def looks_like_bandit(doc: Any) -> bool:
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return False
    if "generated_at" in doc and "metrics" in doc:
        return True
    first = doc["results"][0] if doc["results"] else None
    return isinstance(first, dict) and "test_id" in first and "issue_severity" in first


def parse(path: Path) -> Iterator[Finding]:
    doc = json.loads(Path(path).read_text(encoding="utf-8"))
    for i, r in enumerate(doc.get("results") or []):
        cwe_obj = r.get("issue_cwe") or {}
        cwe = f"CWE-{cwe_obj['id']}" if isinstance(cwe_obj, dict) and cwe_obj.get("id") else None

        line_range = r.get("line_range") or []
        file_path = str(r.get("filename", "<unknown>")).replace("\\", "/")

        description = r.get("issue_text") or ""
        if conf := r.get("issue_confidence"):
            description += f"\n[scanner confidence: {conf}]"
        if more := r.get("more_info"):
            description += f"\n[rule documentation: {more}]"

        yield Finding(
            finding_id=f"bandit:{r.get('test_id')}:{file_path}:{r.get('line_number')}:{i}",
            scanner="bandit",
            rule_id=f"{r.get('test_id')} {r.get('test_name')}".strip(),
            cwe=cwe,
            title=r.get("test_name"),
            description=description.strip(),
            severity=_SEVERITY.get(str(r.get("issue_severity", "")).upper(), Severity.unknown),
            code_context=CodeContext(
                file_path=file_path,
                start_line=r.get("line_number"),
                end_line=max(line_range) if line_range else r.get("line_number"),
                snippet=_clean_code(r.get("code", "")),
                language="python",
            ),
            raw=r,
        )
