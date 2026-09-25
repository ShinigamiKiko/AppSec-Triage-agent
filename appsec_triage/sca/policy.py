"""Decide whether this application's exposure is established and how urgent it is.

An affected installed version is evidence for remediation. A confirmed verdict
also needs a path to the vulnerable behavior and its required conditions.

Most outcomes are decided here without a model call:

| chain outcome / shipping                         | verdict         | priority          | person? |
|--------------------------------------------------|-----------------|-------------------|---------|
| closed on a checked fact (`closes`)              | false_positive  | none              | no      |
| build-only, advisory about the build             | confirmed       | low (CI risk)     | no      |
|   (a hostile package; a code-execution flaw only |                 |                   |         |
|   when the build takes untrusted input)          |                 |                   |         |
| build-only, no build risk                         | false_positive  | low               | no      |
| gadget: needs another flaw to fire first         | false_positive* | low               | no      |
| image-only: in the image, nothing loads it       | false_positive* | low               | no      |
| LSP resolved every reference, none in project   | false_positive  | none              | no      |
| transitive, parent source has no path            | false_positive  | low               | no      |
| transitive, parent not checked                   | unknown         | low               | yes     |
| transitive, the parent calls the function        | model decides   | medium            | if unknown |
| input reaches the vulnerable call                | confirmed       | high / critical   | crit/high: yes |
| installed symbol absent or condition external    | unknown         | medium            | yes     |
| "actual" by a call alone, no traced path         | model decides   | medium / high     | if unknown |
| called, reach not proven; name-only call;        | model decides   | medium by default | if unknown |
|   condition outside the code; undecided          |                 |                   |         |
| version range unclear                            | unknown         | —                 | yes     |

`*` — closed with a mark: the installed version is affected, and the reason
says so; it is closed because nothing here reaches the flaw, and it comes back
the moment a call or a load appears. An upgrade still removes it for good.

A confirmed finding with a published fix is a patch task. Unproven exposure stays
visible as unknown until the missing fact is checked.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .verdict import CVEVerdict

PRIORITIES = ("critical", "high", "medium", "low", "none")

# Outcomes the model is asked about; everything else is decided here.
_NEEDS_MODEL = {CVEVerdict.PRESENT_UNPROVEN, CVEVerdict.CALL_UNCONFIRMED, CVEVerdict.MENTIONED_ONLY,
                CVEVerdict.UNDECIDED, CVEVerdict.INFRASTRUCTURE}

# The package itself is hostile: it runs on every machine that installs it, input or not.
# "malicious" alone is not enough — advisories say "a malicious user could…" about ReDoS.
# Phrased the way such advisories are: "Malicious code in X", "contains malicious code",
# "the maintainer account was compromised". "Crafted malicious code" is input, not this.
# Nor is "a supply chain attack": advisories list it as one way to plant the input of an
# ordinary flaw (PHPUnit: "a supply chain attack inserting malicious files").
_SUPPLY_CHAIN = re.compile(
    r"\bmalicious (?:code|package|version|release|payload) in\b|"
    r"\b(?:contains?|contained|embedded|ships?|shipped|injected)\s+(?:\w+\s+)?malicious (?:code|payload)|"
    r"\bbackdoor(?:ed)?\b|"
    r"compromised (?:package|account|maintainer|version|release|publish)|"
    r"(?:package|account|maintainer|version|release|token)s? (?:was|were|has been|had been) compromised",
    re.IGNORECASE)
_SUPPLY_CHAIN_CWES = {"CWE-506", "CWE-912"}
# A flaw that runs code, but only on input crafted for it: a build is exposed only if
# it processes input it did not write (pull requests from forks, uploaded sources).
_CODE_EXECUTION = re.compile(
    r"arbitrary code execution|remote code execution|code injection|command injection", re.IGNORECASE)
_CODE_EXECUTION_CWES = {"CWE-94", "CWE-78", "CWE-77", "CWE-829"}
# An exploit that needs another flaw first: a prototype-pollution gadget reads a polluted
# Object.prototype, a DOM-clobbering gadget reads injected markup. A deserialization
# "gadget chain" is the opposite — the flaw itself, not a precondition — so a bare
# "gadget" counts only next to prototype pollution or DOM clobbering.
_GADGET = re.compile(r"(?:pollution|dom[- ]clobbering|script)\s+gadgets?\b", re.IGNORECASE)
_GADGET_WORD = re.compile(r"\bgadgets?\b", re.IGNORECASE)
_OTHER_FLAW = re.compile(
    r"prototype[- ]pollution|object\.prototype|__proto__|dom[- ]clobbering|загрязнени\w* прототипа",
    re.IGNORECASE)
_DESERIALIZATION = re.compile(
    r"unseriali[sz]|deseriali[sz]|gadget chain|pop chain|object injection|\breadObject\b",
    re.IGNORECASE)
_DESERIALIZATION_CWES = {"CWE-502"}
_NEEDS_POLLUTION = re.compile(
    r"(?:object\.prototype|прототип\w*)[^.]{0,80}(?:уже|already|предварительно|first)[^.]{0,60}"
    r"(?:загрязн|pollut)|(?:примитив|primitive)[^.]{0,30}(?:загрязнени\w* прототипа|prototype pollution)|"
    r"(?:другой|другая|another|separate|other)[^.]{0,40}(?:уязвимост|vulnerabilit)[^.]{0,60}(?:загрязн|pollut)",
    re.IGNORECASE)


@dataclass(slots=True)
class DependencyPolicy:
    label: str = ""                 # confirmed | false_positive | unknown | "" (the model decides)
    priority: str = "medium"
    needs_person: bool = False
    reason: str = ""
    rule: str = ""

    @property
    def needs_model(self) -> bool:
        # `unknown` is a question the checks could not settle, not an answer: the model
        # gets it with the code in front of it, and its confidence decides who looks next.
        return self.label in ("", "unknown")


def _lift(priority: str, severity: str) -> str:
    """A critical advisory is never below medium, whatever the chain found."""
    if severity == "critical" and PRIORITIES.index(priority) > PRIORITIES.index("medium"):
        return "medium"
    return priority


def _cwes(advisory) -> set[str]:
    return {c.upper() for c in (getattr(advisory, "cwe_ids", None) or [])}


def is_supply_chain(advisory) -> bool:
    """The package itself is malicious: it acts on install or load, whatever the input."""
    if advisory is None:
        return False
    return bool(_cwes(advisory) & _SUPPLY_CHAIN_CWES) or bool(
        _SUPPLY_CHAIN.search(getattr(advisory, "text", "") or ""))


def is_build_risk(advisory, *, untrusted_build_input: bool = False) -> bool:
    """An advisory that hurts the build machine itself, not the running application.

    A hostile package does, always. A code-execution flaw does only when the build
    feeds it input someone else wrote; a build over the project's own sources does not.
    """
    if advisory is None:
        return False
    if is_supply_chain(advisory):
        return True
    if not untrusted_build_input:
        return False
    return bool(_cwes(advisory) & _CODE_EXECUTION_CWES) or bool(
        _CODE_EXECUTION.search(getattr(advisory, "text", "") or ""))


def needs_other_vulnerability(advisory, condition_text: str = "") -> bool:
    """A gadget: exploitable only after some other flaw has done its part — polluted
    Object.prototype, or injected the markup a DOM-clobbering gadget reads."""
    text = (getattr(advisory, "text", "") or "") if advisory is not None else ""
    if advisory is not None and (_cwes(advisory) & _DESERIALIZATION_CWES or _DESERIALIZATION.search(text)):
        return False
    return bool(_GADGET.search(text)
                or (_GADGET_WORD.search(text) and _OTHER_FLAW.search(text))
                or _NEEDS_POLLUTION.search(condition_text or ""))


def decide(outcome: CVEVerdict | None, *, shipped: str = "unknown", severity: str = "",
           upgrade_target: str | None = None, version_known: bool = True, via: list[str] | None = None,
           build_risk: bool = False, proven: bool = False, parent_calls: bool | None = None,
           bridge_present: bool = False,
           condition_state: str = "", installed_symbol_absent: bool = False,
           needs_other_vuln: bool = False) -> DependencyPolicy:
    """The deterministic part of a dependency verdict; `label == ""` leaves it to the model."""
    severity = (severity or "").lower()
    fix = f"обновить до {upgrade_target}" if upgrade_target else "опубликованного исправления нет"
    via_text = f" через {', '.join(via[:3])}" if via else ""

    if not version_known:
        return DependencyPolicy("unknown", "medium", True,
                                "диапазон уязвимых версий не сверился с установленной — нужен человек",
                                "version_unclear")

    if (outcome is CVEVerdict.NOT_SHIPPED or shipped == "build_only") and build_risk:
        return DependencyPolicy("confirmed", "low", False,
                                f"пакет только для сборки, но advisory бьёт по самой сборке (CI) — {fix}",
                                "build_risk")

    if outcome is not None and outcome is not CVEVerdict.NOT_SHIPPED and shipped == "image_only":
        if build_risk:
            return DependencyPolicy("confirmed", "low", False,
                                    f"в образе, не загружается, но advisory бьёт по сборке/образу — {fix}",
                                    "image_only_build_risk")
        return DependencyPolicy(
            "false_positive", "low", False,
            "закрыто с пометкой: уязвимая версия лежит в рабочем образе, но работающий код её не "
            f"загружает — достижимости нет. Убрать из образа: ставить только production-зависимости; {fix}",
            "image_only")

    if outcome is CVEVerdict.NOT_CALLED:
        return DependencyPolicy(
            "false_positive", "none", False,
            "языковой сервер разрешил ссылки на уязвимую функцию: вызовов из кода проекта нет",
            "lsp_not_called")

    if needs_other_vuln:
        return DependencyPolicy(
            "false_positive", "low", False,
            "закрыто с пометкой: это гаджет — срабатывает только в паре с отдельной уязвимостью "
            "(загрязнением Object.prototype или внедрённой разметкой), сам по себе не эксплуатируется. "
            f"Если такая уязвимость найдётся в проекте, находка возвращается; {fix}",
            "needs_other_vuln")

    if installed_symbol_absent:
        return DependencyPolicy(
            "unknown", "medium", True,
            "функция из advisory отсутствует в установленной версии; вызов другого API не доказывает "
            "наличие этого механизма — нужно проверить код установленного пакета",
            "installed_symbol_absent")

    if outcome is CVEVerdict.ACTUAL and proven:
        if condition_state == "external":
            return DependencyPolicy(
                "unknown", "medium", True,
                "путь к уязвимой функции доказан, но обязательное условие вне кода не проверено",
                "external_condition")
        priority = "critical" if severity == "critical" else "high"
        return DependencyPolicy("confirmed", priority, severity in ("critical", "high"),
                                f"пользовательский ввод доходит до уязвимого вызова — {fix}", "actual")

    if (outcome is CVEVerdict.NOT_SHIPPED or shipped == "build_only") and not build_risk:
        return DependencyPolicy(
            "false_positive", "low", False,
            f"только сборка и тесты — в рабочий образ не попадает; {fix}",
            "build_only")

    if parent_calls is False and severity in ("critical", "high"):
        # A name search over the parent misses what a framework wires by itself (a
        # middleware Guzzle adds, a runtime jmespath picks): for a severe advisory it is a
        # lead for the model, not a closure.
        return DependencyPolicy(
            "unknown", _lift("medium", severity), True,
            f"проверенный родитель{via_text} не вызывает уязвимую функцию по имени, но для "
            f"{severity}-advisory это не доказательство: проверь, как родитель использует пакет "
            "(поиск внутри пакета-родителя), прежде чем закрывать",
            "bridge_no_path_severe")

    if parent_calls is False:
        return DependencyPolicy(
            "false_positive", "low", False,
            f"закрыто с пометкой: версия уязвима, но проверенный родитель{via_text} "
            f"не ведёт к уязвимой функции; для устранения уязвимой версии — {fix}",
            "bridge_no_path")

    if bridge_present and parent_calls is None:
        return DependencyPolicy(
            "unknown", "low", True,
            f"путь через родительский пакет{via_text} не удалось проверить",
            "bridge_unchecked")

    if condition_state == "external":
        return DependencyPolicy(
            "unknown", "medium", True,
            "обязательное условие эксплуатации зависит от окружения и не проверено",
            "external_condition")

    if outcome is CVEVerdict.ACTUAL:
        # "Актуальна" by a call alone — the chain's rule for flaws that need no input.
        # With no traced path and an outside condition that is a lead, not a proof.
        return DependencyPolicy("", "high" if severity in ("critical", "high") else "medium", False, "",
                                "model_called")

    if outcome is CVEVerdict.NO_DIRECT_CALL:
        if parent_calls:
            return DependencyPolicy("", _lift("medium", severity), False, "", "model_parent_calls")
        return DependencyPolicy(
            "unknown", "low", True,
            f"прямой вызов не найден{via_text}; поиск по именам "
            "не доказывает отсутствия косвенного пути к уязвимой функции",
            "call_path_unproven")

    if outcome in _NEEDS_MODEL or outcome is None:
        return DependencyPolicy("", _lift("medium", severity), False, "", "model")

    # Every other outcome closes on a checked fact (see CVEDecision.closes).
    return DependencyPolicy("false_positive", "none", False, "", "closed")


def priority_for_model_verdict(label: str, outcome: CVEVerdict | None, severity: str,
                               evidence: str = "") -> str:
    """Priority of a verdict the model gave, from what the chain established."""
    severity = (severity or "").lower()
    if label != "confirmed":
        return "none" if label == "false_positive" else "medium"
    if outcome is CVEVerdict.PRESENT_UNPROVEN and evidence == "import":
        base = "high" if severity in ("critical", "high") else "medium"
    elif outcome in (CVEVerdict.CALL_UNCONFIRMED, CVEVerdict.MENTIONED_ONLY):
        base = "medium" if severity in ("critical", "high") else "low"
    else:
        base = "medium"
    return _lift(base, severity)
