"""A boolean setting, read from every assignment of it in the project's own Go code."""

from __future__ import annotations

import re
from pathlib import Path

from ..frameworks import DetectorResult, FrameworkDetector, clean_comments, project_files

_MAX_FILES = 2000
_MAX_BYTES = 600_000


class GoDetector(FrameworkDetector):
    """Go code as configuration: `Token: true`, `token := false`, `token = other`.

    One file does not speak for the project. Every assignment in first-party code is
    read — not tests, not `vendor/`, not a module cache inside the checkout — and the
    setting is "absent" only when its single assignment is `false` and no file was
    left unread.
    """

    def detect(self, roots: list[Path], tokens: list[str]) -> DetectorResult | None:
        for root in roots:
            files, complete = project_files(Path(root), (".go",), _MAX_FILES, skip=frozenset({"testdata"}))
            sources: list[tuple[str, str]] = []
            for path in files:
                if path.name.endswith("_test.go"):
                    continue
                try:
                    if path.stat().st_size > _MAX_BYTES:
                        complete = False
                        continue
                    text = clean_comments(path.read_text(encoding="utf-8", errors="replace"))
                except OSError:
                    complete = False
                    continue
                sources.append((path.relative_to(root).as_posix(), text))
            for token in tokens:
                result = self._setting(token, sources, complete)
                if result is not None:
                    return result
        return None

    @staticmethod
    def _setting(token: str, sources: list[tuple[str, str]], complete: bool) -> DetectorResult | None:
        # `:=`, `=` and a struct field's `:` assign; `==`, `!=`, `<=`, `>=` compare.
        pattern = re.compile(rf"\b{re.escape(token)}\s*(?::=|:|=(?!=))\s*(true|false|[A-Za-z_]\w*)",
                             re.IGNORECASE)
        found = [(rel, text.count("\n", 0, match.start()) + 1, match.group(0), match.group(1).lower())
                 for rel, text in sources for match in pattern.finditer(text)]
        if not found:
            return None
        rel, line, shown, value = found[0]
        if len(found) > 1:
            return DetectorResult(
                "external",
                evidence=f"{rel}: {token} assigned multiple times",
                reason=f"значение {token} может быть переприсвоено во время выполнения",
                file=rel,
            )
        if value not in ("true", "false"):
            return DetectorResult(
                "external", evidence=f"{rel}: {shown}",
                reason=f"значение {token} вычисляется в Go-коде",
                file=rel,
            )
        if value == "false" and not complete:
            # Unread files may assign it too: one `false` among them proves nothing.
            return None
        return DetectorResult(
            "holds" if value == "true" else "absent",
            evidence=f"{rel}:{line}: {shown}",
            reason=f"Go code sets {token} to {value}",
            file=rel,
        )


DETECTORS: tuple[FrameworkDetector, ...] = (GoDetector(),)
