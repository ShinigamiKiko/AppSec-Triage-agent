"""The upgrades that clear the dependency findings: one line per package, not one per CVE.

Twig 3.14.0 carries seventeen advisories; one bump past the highest of their fixes
clears all of them. A developer acts on the package, so the plan is per package:
the version that fixes every advisory known for the installed one, how many findings
it settles, how many of them are still open, and whether the bump crosses a major.
"""

from __future__ import annotations

import html
from dataclasses import dataclass, field

from ..models import TriageRecord, VerdictLabel

_LICENSE = ("WOLFEE-LICENSE",)


def _parts(version: str) -> tuple[int, ...] | None:
    text = (version or "").strip().lower().lstrip("v")
    if not text:
        return None
    out = []
    for piece in text.split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        if not digits:
            break
        out.append(int(digits))
        if digits != piece:
            break
    return tuple(out) or None


def _major(parts: tuple[int, ...]) -> tuple[int, ...]:
    """The part a semver major bump changes: `1` of 1.4, `0.4` of 0.4.2."""
    return parts[:2] if parts and parts[0] == 0 else parts[:1]


@dataclass(slots=True)
class UpgradeStep:
    package: str
    installed: str
    target: str = ""
    advisories: list[str] = field(default_factory=list)
    open: list[str] = field(default_factory=list)
    confirmed: list[str] = field(default_factory=list)
    unfixed: list[str] = field(default_factory=list)
    """Advisories with no published fix above the installed version."""
    placement: str = ""
    upgrade: str = ""
    shipped: str = ""
    fixes: dict[str, str] = field(default_factory=dict)
    """advisory -> its lowest fix above the installed version."""

    @property
    def major(self) -> bool:
        current, target = _parts(self.installed), _parts(self.target)
        return bool(current and target and _major(target) > _major(current))

    @property
    def same_major(self) -> tuple[str, int]:
        """(version, advisories it fixes) without leaving the installed major — when the full
        fix needs a major bump: Laravel 8 gets most fixes on 8.x, one only on 12.x."""
        current = _parts(self.installed)
        if not self.major or current is None:
            return "", 0
        within = [(p, raw) for raw in self.fixes.values() if (p := _parts(raw)) and _major(p) == _major(current)]
        if not within:
            return "", 0
        best = max(within)[0]
        version = max(within)[1]
        return version, sum(1 for raw in self.fixes.values() if (p := _parts(raw)) and p <= best)

    def as_dict(self) -> dict:
        version, covered = self.same_major
        return {"package": self.package, "installed": self.installed, "target": self.target or None,
                "major": self.major, "same_major_target": version or None, "same_major_fixes": covered,
                "advisories": self.advisories, "open": self.open,
                "confirmed": self.confirmed, "without_fix": self.unfixed, "placement": self.placement,
                "how": self.upgrade, "shipped": self.shipped or None}


def plan(records: list[TriageRecord]) -> list[UpgradeStep]:
    """Packages to upgrade, the ones with confirmed or open findings first."""
    steps: dict[tuple[str, str], UpgradeStep] = {}
    for record in records:
        sca = record.sca
        if sca is None or not sca.package or (record.rule_id or "").upper().startswith(_LICENSE):
            continue
        key = (sca.package.lower(), sca.installed_version)
        step = steps.setdefault(key, UpgradeStep(sca.package, sca.installed_version))
        advisory = (record.rule_id or record.finding_id.rsplit(":", 1)[-1]).upper()
        if advisory in step.advisories:
            continue
        step.advisories.append(advisory)
        label = record.verdict.verdict
        if label is VerdictLabel.confirmed:
            step.confirmed.append(advisory)
        if label is not VerdictLabel.false_positive:
            step.open.append(advisory)
        fixed = _parts(sca.fixed_in)
        if fixed is None:
            step.unfixed.append(advisory)
        else:
            step.fixes[advisory] = sca.fixed_in
            if not step.target or fixed > (_parts(step.target) or ()):
                step.target = sca.fixed_in
        step.placement = step.placement or sca.placement
        step.upgrade = step.upgrade or sca.upgrade
        step.shipped = step.shipped or sca.shipped
    return sorted(steps.values(), key=lambda s: (-len(s.confirmed), -len(s.open), -len(s.advisories), s.package))


def summary(steps: list[UpgradeStep]) -> str:
    if not steps:
        return ""
    settled = sum(len(s.advisories) - len(s.unfixed) for s in steps if s.target)
    open_ = sum(len(s.open) for s in steps if s.target)
    return (f"план обновлений: {sum(1 for s in steps if s.target)} пакет(ов) закрывают {settled} находок "
            f"зависимостей, из них открытых {open_}")


def render_html(steps: list[UpgradeStep]) -> str:
    """The section of the report: what to bump, to what, and what it settles."""
    if not steps:
        return ""
    e = html.escape
    rows = []
    for s in steps:
        note = []
        if s.major:
            note.append("<strong>мажорное обновление</strong> — смотрите UPGRADE/changelog")
            version, covered = s.same_major
            if version:
                note.append(f"без смены мажорной версии: до {e(version)} — закроет {covered} из {len(s.fixes)}")
        if s.unfixed:
            note.append(f"без исправления: {e(', '.join(s.unfixed[:4]))}"
                        + (f" и ещё {len(s.unfixed) - 4}" if len(s.unfixed) > 4 else ""))
        if s.shipped == "build_only":
            note.append("только сборка и тесты")
        if s.upgrade:
            note.append(e(s.upgrade))
        open_cell = (f"<strong>{len(s.open)}</strong>" if s.open else "0") + (
            f" (подтверждено {len(s.confirmed)})" if s.confirmed else "")
        rows.append(
            f"<tr><td><code>{e(s.package)}</code></td><td>{e(s.installed)}</td>"
            f"<td>{e(s.target) if s.target else '—'}</td><td>{len(s.advisories)}</td><td>{open_cell}</td>"
            f"<td>{e(s.placement[:80])}</td><td>{'<br>'.join(note)}</td></tr>")
    return ("<h2 id=\"upgrade-plan\">План обновлений</h2>"
            "<p class=\"sub\">Одно обновление пакета закрывает все его бюллетени: целевая версия — "
            "наибольшая из версий с исправлением выше установленной. Открытые — подтверждённые и "
            "нерешённые находки; закрытые тоже исчезнут из отчёта после обновления.</p>"
            "<table><thead><tr><th>Пакет</th><th>Сейчас</th><th>Обновить до</th><th>Бюллетеней</th>"
            "<th>Открытых</th><th>Как пришёл</th><th>Заметки</th></tr></thead><tbody>"
            + "".join(rows) + "</tbody></table>")
