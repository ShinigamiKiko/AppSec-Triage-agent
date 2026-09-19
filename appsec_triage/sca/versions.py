"""Is the installed version inside the advisory's affected ranges at all?"""

from __future__ import annotations

import re
from dataclasses import dataclass

AFFECTED = "affected"
UNAFFECTED = "unaffected"
UNKNOWN = "unknown"

_SEMVER = re.compile(
    r"^v?(?P<main>\d+(?:\.\d+)*)(?:-(?P<pre>[0-9A-Za-z.-]+))?(?:\+(?P<build>[0-9A-Za-z.-]+))?$")
# Composer writes pre-releases without a dash (1.0.0beta2, 1.0.0-RC1, 1.0.0-p1).
_COMPOSER_PRE = re.compile(r"^(?P<main>v?\d+(?:\.\d+)*)[-.]?(?P<tag>alpha|beta|rc|a|b|p|patch|pl)\.?(?P<n>\d*)$",
                           re.IGNORECASE)


@dataclass(slots=True)
class VersionCheck:
    state: str
    detail: str

    @property
    def unaffected(self) -> bool:
        return self.state == UNAFFECTED


def _semver_key(version: str, ecosystem: str):
    text = version.strip()
    if ecosystem in ("go", "golang"):
        text = text.removesuffix("+incompatible")
        if text.startswith("go"):  # stdlib versions arrive as go1.22.3
            text = text[2:]
    if ecosystem in ("composer", "packagist", "php"):
        m = _COMPOSER_PRE.match(text)
        if m:
            tag = m.group("tag").lower()
            tag = {"a": "alpha", "b": "beta", "pl": "patch", "p": "patch"}.get(tag, tag)
            if tag == "patch":  # a patch release sorts after its base
                text = f"{m.group('main')}+patch{m.group('n') or 0}"
                main = _SEMVER.match(text)
                if not main:
                    return None
                return (_main(main.group("main")), (1,), (int(m.group("n") or 0),))
            text = f"{m.group('main')}-{tag}.{m.group('n') or 0}"
    m = _SEMVER.match(text)
    if not m:
        return None
    pre = m.group("pre")
    if not pre:
        return (_main(m.group("main")), (1,), ())
    parts = []
    for ident in pre.split("."):
        parts.append((0, int(ident), "") if ident.isdigit() else (1, 0, ident))
    return (_main(m.group("main")), (0,), tuple(parts))


def _main(text: str) -> tuple[int, ...]:
    numbers = [int(p) for p in text.split(".")]
    while len(numbers) < 3:
        numbers.append(0)
    while len(numbers) > 3 and numbers[-1] == 0:
        numbers.pop()
    return tuple(numbers)


def key(version: str, ecosystem: str):
    """A sortable key for `version`, or None when it cannot be ordered safely."""
    eco = (ecosystem or "").strip().lower()
    if not version or not version.strip():
        return None
    if eco in ("pypi", "python", "pip"):
        try:
            from packaging.version import InvalidVersion, Version
        except ImportError:
            return None
        try:
            return Version(version)
        except InvalidVersion:
            return None
    return _semver_key(version, eco)


def _entries_for(advisory, package: str) -> list[dict]:
    wanted = (package or "").strip().lower()
    entries = list(getattr(advisory, "affected", None) or [])
    matching = [e for e in entries if (e.get("package") or "").strip().lower() == wanted]
    return matching


def check(installed: str, advisory, package: str, ecosystem: str) -> VersionCheck:
    """Where `installed` stands against the advisory's own affected ranges."""
    if not installed:
        return VersionCheck(UNKNOWN, "установленная версия не известна")
    entries = _entries_for(advisory, package)
    if not entries:
        return VersionCheck(UNKNOWN, f"в advisory нет диапазонов для пакета {package}")
    if any(installed in (e.get("versions") or []) for e in entries):
        return VersionCheck(AFFECTED, f"{installed} прямо перечислена в списке затронутых версий")
    current = key(installed, ecosystem)
    if current is None:
        return VersionCheck(UNKNOWN, f"версию {installed!r} нельзя упорядочить по правилам {ecosystem}")

    orderable = 0
    for entry in entries:
        for rng in entry.get("ranges") or []:
            if (rng.get("type") or "").upper() not in ("SEMVER", "ECOSYSTEM"):
                continue
            orderable += 1
            start = None
            for event in rng.get("events") or []:
                if "introduced" in event:
                    raw = str(event["introduced"])
                    start = () if raw == "0" else key(raw, ecosystem)
                    if start is None:
                        return VersionCheck(UNKNOWN, f"граница диапазона {raw!r} не разбирается")
                    continue
                if start is None:
                    continue
                for bound, inclusive in (("fixed", False), ("last_affected", True), ("limit", False)):
                    if bound in event:
                        raw = str(event[bound])
                        end = key(raw, ecosystem)
                        if end is None:
                            return VersionCheck(UNKNOWN, f"граница диапазона {raw!r} не разбирается")
                        low_ok = start == () or current >= start
                        high_ok = current <= end if inclusive else current < end
                        if low_ok and high_ok:
                            lo = "начала" if start == () else _raw_introduced(rng, start, ecosystem)
                            op = "≤" if inclusive else "<"
                            return VersionCheck(AFFECTED, f"{installed} в диапазоне от {lo} {op} {raw}")
                        start = None
                        break
            if start is not None and (start == () or current >= start):
                return VersionCheck(AFFECTED, f"{installed} в открытом диапазоне без исправления")
    if not orderable:
        return VersionCheck(UNKNOWN, "диапазоны advisory заданы коммитами (GIT) — версию сверить нельзя")
    fixed = ", ".join(getattr(advisory, "fixed_versions", None) or []) or "—"
    return VersionCheck(UNAFFECTED, f"{installed} вне всех затронутых диапазонов (исправлено в: {fixed})")


def _raw_introduced(rng: dict, start, ecosystem: str) -> str:
    for event in rng.get("events") or []:
        raw = event.get("introduced")
        if raw is not None and key(str(raw), ecosystem) == start:
            return str(raw)
    return "?"
