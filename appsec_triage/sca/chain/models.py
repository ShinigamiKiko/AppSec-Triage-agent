"""Public result model for dependency-chain analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from .. import codeql_reach
from .. import conditions as conditions_mod
from .. import exploitability as exploit_mod
from .. import govulncheck as govulncheck_mod
from .. import presence as presence_mod
from .. import reach as reach_mod
from ..bridge import BridgeResult
from ..graph import Placement
from ..resolve import VulnerableSymbol
from ..verdict import CVEDecision


@dataclass(slots=True)
class ChainResult:
    decision: CVEDecision
    symbol: VulnerableSymbol | None = None
    presence: presence_mod.PresenceResult | None = None
    reach: reach_mod.ReachResult | None = None
    problems: list[str] = field(default_factory=list)
    placement: Placement | None = None
    bridge: BridgeResult | None = None
    searched_for: list[str] = field(default_factory=list)
    condition: conditions_mod.Condition | None = None
    exploitability: exploit_mod.Exploitability | None = None
    dataflow: codeql_reach.Reached | None = None
    dataflow_status: str = ""
    reachability: govulncheck_mod.Verdict | None = None
    matched_symbol: str = ""
    audit: str = ""
    closure_kind: str = ""
    audited: bool = False
    # excluded | callgraph | codeql | text | package | condition | unknown
    route: str = ""
    codeql_calls: list[str] = field(default_factory=list)
    owner: str = ""
    # What the advisory says the flaw is, in its own words. Without it a report
    # can name the vulnerable function but not say what is wrong with it.
    flaw: str = ""
    flaw_ru: str = ""

    @property
    def needs_a_person(self) -> bool:
        return self.condition is not None and self.condition.needs_a_person

    @property
    def closes(self) -> bool:
        return self.decision.closes

    def _evidence(self) -> list[str]:
        if self.dataflow is not None:
            return [f"{self.dataflow.source_file}:{self.dataflow.source_line} (источник)",
                    f"{self.dataflow.file}:{self.dataflow.line} (вызов)"]
        if self.dataflow_status:
            return [self.dataflow_status]
        if self.reachability is not None and self.reachability.reachable:
            return list(self.reachability.trace[:6])
        return [str(hit) for hit in (self.presence.hits[:5] if self.presence else [])]

    def summary(self, dependency=None):
        from ...models import SCASummary
        condition = self.condition
        external = ""
        owner = ""
        if condition is not None:
            from ..conditions import ConditionState
            if condition.state is ConditionState.EXTERNAL:
                external = (f"{condition.statement} — искать: "
                            f"{', '.join(condition.tokens[:4]) or 'не определено'}; "
                            f"где: {condition.where or 'окружение и деплой'}")
            elif condition.state is ConditionState.INFRASTRUCTURE:
                external = condition.statement
                owner = condition.where or "владелец системы"
        owner = owner or self.owner
        return SCASummary(
            package=(dependency.package if dependency else "") or "",
            installed_version=(dependency.installed_version if dependency else "") or "",
            placement=self.placement.describe() if self.placement else "",
            upgrade=self.placement.upgrade_note() if self.placement else "",
            symbol=self.matched_symbol or (str(self.symbol) if self.symbol else ""),
            what_changed=(self.symbol.what_changed if self.symbol else ""),
            outcome=self.decision.verdict.value,
            outcome_note=self.decision.headline,
            call_sites=self._evidence(),
            trace=(self.dataflow.render() if self.dataflow is not None
                   else self.reachability.render() if self.reachability is not None
                   else (self.reach.taint_path if self.reach else "")),
            external=external,
            owner=owner,
            condition=(condition.statement if condition is not None else ""),
            condition_state=(condition.state.value if condition is not None else ""),
            condition_hits=(list(condition.hits[:4]) if condition is not None else []),
            exploitability=(self.exploitability.render() if self.exploitability else ""),
            flaw=self.flaw,
            flaw_ru=self.flaw_ru,
            audit=self.audit,
            closure_kind=self.closure_kind,
            audited=self.audited,
            route=self.route,
            codeql_calls=self.codeql_calls[:12],
            problems=self.problems[:4],
        )

    def render(self) -> str:
        lines = ["## Проверка уязвимой функции", "", self.decision.headline, ""]
        if self.symbol is not None:
            lines += [
                "Контекст advisory (это описание CVE, не verdict по проекту):",
                f"- пакет: {self.symbol.package or 'не указан'}",
                f"- источник контекста: {self.symbol.source_stage or 'не указан'}",
                f"- символ из advisory/fix: {self.symbol}",
            ]
            if self.symbol.file:
                lines.append(f"- файл в пакете: {self.symbol.file}")
            if self.symbol.what_changed:
                lines.append(f"- изменение в fix: {self.symbol.what_changed}")
            if self.symbol.evidence:
                lines.append(f"- evidence: {self.symbol.evidence}")
            if self.symbol.precondition:
                lines.append(f"- условие эксплуатации: {self.symbol.precondition}")
            if self.symbol.required_actions:
                lines.append(f"- требуемые действия: {'; '.join(self.symbol.required_actions[:8])}")
            if self.symbol.advisory_context:
                lines.append(f"- дополнительные замечания advisory: {self.symbol.advisory_context}")
            candidates = [f"{klass}::{function}" if klass else function
                          for function, klass in self.symbol.candidates if function]
            candidates = list(self.symbol.search_targets) or candidates
            if candidates:
                lines.append(f"- искать в коде проекта: {', '.join(candidates[:12])}")
            lines.append("")
        if self.exploitability is not None and (rendered := self.exploitability.render()):
            lines.append(f"- эксплуатируемость: {rendered}")
        if self.dataflow_status:
            lines.append(f"- CodeQL dataflow: {self.dataflow_status}")
        if self.placement is not None:
            lines.append(f"- положение в графе: {self.placement.describe()}")
            if note := self.placement.upgrade_note():
                lines.append(f"- что обновлять: {note}")
        if self.bridge is not None and self.bridge.detail:
            lines.append(f"- посредник: {self.bridge.detail}")
        if self.searched_for:
            lines.append(f"- искали в коде проекта: {', '.join(self.searched_for)}")
        if self.condition is not None and (rendered := self.condition.render()):
            lines.append(f"- {rendered}")
        for reason in self.decision.reasons:
            lines.append(f"- {reason}")
        if self.decision.evidence:
            lines += ["", "Места вызова:"]
            lines.extend(f"- {item}" for item in self.decision.evidence)
        if self.problems:
            lines += ["", "Не удалось выполнить:"]
            lines.extend(f"- {item}" for item in self.problems)
        return "\n".join(lines)
