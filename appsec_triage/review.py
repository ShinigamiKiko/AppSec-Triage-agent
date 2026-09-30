"""Turning an undecided finding into a short, answerable review task."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .consequence import weight as consequence_weight
from .models import TriageRecord, VerdictLabel


@dataclass(slots=True)
class Question:
    """One thing only a human can answer, with the place to answer it from."""

    text: str
    look_at: list[str] = field(default_factory=list)
    if_yes: str = ""
    if_no: str = ""

    def as_dict(self) -> dict:
        return {"question": self.text, "look_at": self.look_at, "if_yes": self.if_yes, "if_no": self.if_no}


@dataclass(slots=True)
class ReviewBrief:
    established: list[str] = field(default_factory=list)
    questions: list[Question] = field(default_factory=list)
    minutes_saved_note: str = ""

    @property
    def actionable(self) -> bool:
        return bool(self.questions)

    def as_dict(self) -> dict:
        return {
            "established": self.established,
            "questions": [q.as_dict() for q in self.questions],
        }


_ROUTE = re.compile(
    r"""(?:path|re_path|url)\s*\(\s*["']([^"']*)["']"""
    r"""|@app\.route\s*\(\s*["']([^"']*)["']"""
    r"""|Route::\w+\s*\(\s*["']([^"']*)["']"""
    r"""|@(?:Get|Post|Put|Delete|Request)Mapping\s*\(\s*["']?([^"')]*)""",
    re.IGNORECASE,
)


def _route_name(line: str) -> str | None:
    m = _ROUTE.search(line or "")
    if not m:
        return None
    return next((g for g in m.groups() if g), None)


def _is_secret_family(cwe: str | None) -> bool:
    from .context.heuristics import SECRET_FAMILY_CWES

    return bool(cwe) and cwe.upper() in SECRET_FAMILY_CWES


def _at(record: TriageRecord) -> str:
    return f"{record.file_path}" + (f":{record.start_line}" if record.start_line else "")


def build(record: TriageRecord) -> ReviewBrief:
    """What the reviewer should be told, and asked."""
    brief = ReviewBrief()
    verdict = record.verdict

    if verdict.dataflow:
        grounded = [s for s in verdict.dataflow if s.grounded]
        if grounded:
            ends = f"{grounded[0].location or '?'} → {grounded[-1].location or '?'}"
            brief.established.append(f"Путь данных прослежен, шагов: {len(grounded)}: {ends}")
    if verdict.vulnerable_symbol:
        sym = verdict.vulnerable_symbol
        brief.established.append(f"Уязвимое место: `{sym.name}`" + (f" ({sym.location})" if sym.location else ""))

    route_lines: list[str] = []
    for line in record.symbol_context:
        if line.startswith("called from:"):
            route_lines.append(line[len("called from:") :].strip())
        elif line.startswith("definition of"):
            brief.established.append("определение" + line[len("definition of"):])
    if record.reachability:
        brief.established.append(f"Достижимость: {record.reachability}")

    heavy = consequence_weight(record.cwe) >= 22

    if record.kind == "dependency" and record.verdict.verdict is not VerdictLabel.false_positive:
        brief.questions.append(
            Question(
                text=(
                    "Можно ли обновить пакет сейчас? Исправление названо в вердикте — осталось понять, "
                    "не ломает ли обновление что-то в этом проекте."
                ),
                look_at=[record.file_path, "список изменений между установленной и исправленной версиями"],
                if_yes="Обновить и закрыть.",
                if_no=(
                    "Записать, почему нельзя и что компенсирует риск до обновления — находка остаётся "
                    "открытой как принятый риск, а не как неразобранная."
                ),
            )
        )
        return brief

    for caller in route_lines[:2]:
        route = _route_name(caller)
        if route is None:
            continue
        brief.questions.append(
            Question(
                text=(
                    f"Маршрут `{route}` доходит до этого кода. Он доступен снаружи периметра "
                    "или только изнутри / за аутентификацией?"
                ),
                look_at=[caller, "правила межсетевого экрана и доступа для этого маршрута"],
                if_yes=f"Доступен снаружи → считать {'подтверждённой' if heavy else 'реальной'} находкой.",
                if_no="Только изнутри → серьёзность ниже; исправить стоит, но не срочно.",
            )
        )
        break

    if _is_secret_family(record.cwe) and record.verdict.verdict is not VerdictLabel.false_positive:
        brief.questions.append(
            Question(
                text=(
                    "Это действующий секрет, и опубликован ли файл — лежит в репозитории, "
                    "запечён в образ или выложен на сервер?"
                ),
                look_at=[
                    _at(record),
                    "`git log` по этому файлу и .gitignore",
                    "подменяется ли значение настоящим при развёртывании",
                ],
                if_yes="Действующий и опубликован → сначала сменить секрет, потом убрать его из файла.",
                if_no=(
                    "Заглушка или значение только для локального запуска → ложное срабатывание; "
                    "записать, что именно из двух: они устаревают по-разному."
                ),
            )
        )
        return brief

    if (
        not verdict.dataflow
        and record.kind == "weakness"
        and record.verdict.verdict is not VerdictLabel.false_positive
    ):
        target = verdict.vulnerable_symbol.name if verdict.vulnerable_symbol else "отмеченного значения"
        brief.questions.append(
            Question(
                text=f"Доходит ли до `{target}` хоть одно значение, которое контролирует запрос?",
                look_at=[_at(record), "вызовы функции, в которой находится это место"],
                if_yes="Контролирует атакующий → подтверждено.",
                if_no="Только внутренние или постоянные значения → ложное срабатывание; записать почему.",
            )
        )

    if record.reachability and "none of them an entry point" in record.reachability:
        brief.questions.append(
            Question(
                text=(
                    "Вызовы найдены, но ни один не регистрирует маршрут в пределах одного шага. "
                    "Этот код вызывается из контроллера выше по цепочке или это внутренняя обвязка?"
                ),
                look_at=[c for c in route_lines[:3]],
                if_yes="Достижим → находка остаётся.",
                if_no="Внутренний помощник только с доверенными вызовами → понизить приоритет.",
            )
        )

    if record.reachability and "tests or fixtures" in record.reachability:
        brief.questions.append(
            Question(
                text=(
                    "Все найденные вызовы — из тестов или фикстур. Нет ли рабочего вызова, который "
                    "индексатор пропустил: динамический вызов, внедрение зависимостей, маршрут из аннотации?"
                ),
                look_at=[record.file_path, "конфигурация внедрения зависимостей и аннотации маршрутов"],
                if_yes="Рабочий вызов есть → находка остаётся.",
                if_no="Код только для тестов → закрыть и написать об этом в задаче.",
            )
        )

    if record.challenge_note:
        brief.questions.append(
            Question(
                text=f"Второй проход возразил против вердикта: {record.challenge_note[:220]}. Он прав?",
                look_at=[_at(record)],
                if_yes="Возражение верно → изменить вердикт и написать почему.",
                if_no="Возражение неверно → вердикт остаётся; записать довод на будущее.",
            )
        )

    if verdict.blocking_question and verdict.verdict is VerdictLabel.unknown:
        already = {q.text[:40] for q in brief.questions}
        if verdict.blocking_question[:40] not in already:
            brief.questions.append(Question(text=verdict.blocking_question, look_at=[_at(record)]))

    for gap in verdict.missing_information[:2]:
        if len(brief.questions) >= 4:
            break
        brief.questions.append(Question(text=f"Не хватает: {gap}", look_at=[record.file_path]))

    if brief.established and brief.questions:
        brief.minutes_saved_note = (
            "Трасса и места вызова выше найдены автоматически — ответь на вопрос, "
            "не восстанавливая их заново."
        )
    return brief
