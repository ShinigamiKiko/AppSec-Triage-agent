"""What an engine answers about a vulnerable function: where it is called, and whether input reaches it.

CodeQL and Psalm answer in the same shape, so the chain reads one kind of answer
whichever engine gave it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ...testpaths import is_test
from ..presence import Hit, PresenceResult, SymbolPresence


@dataclass(frozen=True, slots=True)
class Target:
    """One vulnerable function, named the way the application imports it."""

    package: str
    function: str
    klass: str = ""

    @property
    def label(self) -> str:
        return f"{self.klass}::{self.function}" if self.klass else self.function


@dataclass(slots=True)
class Reached:
    """One call site the query proved reachable, and where the input enters."""

    file: str
    line: int
    source_file: str = ""
    source_line: int = 0
    steps: list[str] = field(default_factory=list)
    engine: str = "CodeQL"

    @property
    def site(self) -> tuple[str, int]:
        return (self.file, self.line)

    def render(self) -> str:
        head = (f"{self.engine}: пользовательский ввод из {self.source_file}:{self.source_line} "
                f"доходит до {self.file}:{self.line}")
        if len(self.steps) > 1:
            return f"{head}; трасса {self.engine}: {' → '.join(self.steps[:12])}"
        return head


@dataclass(slots=True)
class ApiAnswer:
    """What an engine (CodeQL or Psalm) established about these functions."""

    calls: dict[str, list[Hit]] = field(default_factory=dict)
    reached: dict[str, Reached] = field(default_factory=dict)
    problem: str = ""
    engine: str = "codeql"

    @property
    def usable(self) -> bool:
        return not self.problem

    @property
    def engine_name(self) -> str:
        return "Psalm" if self.engine == "psalm" else "CodeQL"

    def presence(self, label: str) -> PresenceResult:
        hits = self.calls.get(label) or []
        how = "по типам PHP" if self.engine == "psalm" else "по API пакета"
        if not hits:
            return PresenceResult(SymbolPresence.ABSENT, label,
                                  detail=f"{self.engine_name} не нашёл вызовов {label} {how}")
        return PresenceResult(SymbolPresence.CALLED, label, hits,
                              detail=f"вызов {label} разрешён {self.engine_name} {how}, а не совпадением имени")

    def dataflow(self, label: str) -> Reached | bool | None:
        """`Reached` with CodeQL's path, False when the calls exist and none is reached, None when this answer says nothing about the function."""
        if self.problem:
            return None
        if label in self.reached:
            return self.reached[label]
        return False if self.calls.get(label) else None


def hit(root: Path, file: str, line: int) -> Hit:
    try:
        lines = (root / file).read_text(encoding="utf-8", errors="replace").splitlines()
        text = lines[line - 1].strip() if 0 < line <= len(lines) else ""
    except OSError:
        text = ""
    return Hit(file, line, text, in_tests=is_test(file))
