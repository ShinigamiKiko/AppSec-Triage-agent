"""Conditions the platform answers, and the many it does not.

A precondition the repository cannot settle is not automatically a question for
a person: "reachable from the internet" is answered by the ingress, "listens on
a privileged port" by the pod spec. Those are worth asking the deployment.

The risk is the opposite one, and it is what most of these tests are about: a
deployment description is prose, and prose invites a model to explain away a
condition that is really about the code. Injection is injection behind an
ingress, and a sandbox escape does not stop mattering because TLS terminates
elsewhere.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from appsec_triage.sca.conditions import (
    Condition,
    ConditionState,
    check_against_deployment,
)


class _Model:
    def __init__(self, **answer) -> None:
        self.answer = {"verdict": "unknown", "evidence": "", "why": "", **answer}
        self.prompts: list[str] = []

    def complete(self, system, user, json_schema=None):
        self.prompts.append(user)
        return SimpleNamespace(text=json.dumps(self.answer))


class _Deployment:
    usable = True

    def __init__(self, text: str) -> None:
        self._text = text

    def render(self) -> str:
        return self._text


_K8S = ("Приложение работает в Kubernetes. Внешний трафик приходит только через\n"
        "ingress-контроллер, TLS терминируется на нём.\n"
        "- tls_terminated_at_ingress: платформа отвечает за это\n"
        "- internet_exposure_via_ingress_only: платформа отвечает за это\n")


def _external(statement: str) -> Condition:
    return Condition(ConditionState.EXTERNAL, statement, ["listen", "bind"],
                     "манифесты деплоя", reason="задаётся вне репозитория")


def test_the_platform_can_settle_a_platform_condition():
    model = _Model(verdict="absent",
                   evidence="- internet_exposure_via_ingress_only: платформа отвечает за это",
                   why="наружу торчит только ingress, приложение слушает внутри кластера")

    result = check_against_deployment(
        _external("сервис доступен из интернета напрямую"), _Deployment(_K8S), model)

    assert result.state is ConditionState.ABSENT
    assert "по описанию среды" in result.reason


def test_a_condition_about_someone_elses_system_is_reassigned():
    """An LDAP server's own settings are not the application's to change.
    Leaving it in a developer queue guarantees nobody acts on it."""
    model = _Model(verdict="infrastructure",
                   evidence="Приложение работает в Kubernetes. Внешний трафик приходит только через",
                   why="это настройка LDAP-сервера, приложение её не задаёт")

    result = check_against_deployment(
        _external("LDAP-сервер разрешает незашифрованные соединения"),
        _Deployment(_K8S), model)

    assert result.state is ConditionState.INFRASTRUCTURE
    rendered = result.render()
    assert "EXTERNAL / ИНФРАСТРУКТУРА" in rendered
    assert "владелец:" in rendered


def test_an_infrastructure_finding_is_a_false_positive_for_this_service():
    from appsec_triage.sca.presence import Hit, PresenceResult, SymbolPresence
    from appsec_triage.sca.resolve import VulnerableSymbol
    from appsec_triage.sca.verdict import CVEVerdict, decide

    condition = Condition(ConditionState.INFRASTRUCTURE,
                          "LDAP-сервер разрешает незашифрованные соединения",
                          [], "команда каталога", reason="настройка сервера")
    decision = decide(
        VulnerableSymbol("GHSA-l", "symfony/ldap", function="bind"),
        PresenceResult(SymbolPresence.CALLED, "bind",
                       [Hit("src/Auth.php", 20, "$ldap->bind($dn, $pw);")]),
        None, cwe="CWE-319", condition=condition)

    assert decision.verdict is CVEVerdict.INFRASTRUCTURE
    assert decision.closes, "для этого сервиса это ложное срабатывание"
    assert decision.reassigned, "но владелец должен быть назван, а не потерян"


def test_a_client_librarys_own_tls_setting_stays_with_the_application():
    """The prompt draws this line; the test keeps it drawn."""
    from appsec_triage.sca.conditions import DEPLOYMENT_SYSTEM

    assert "client library's own TLS options" in DEPLOYMENT_SYSTEM
    assert "is not a" in DEPLOYMENT_SYSTEM or "not a\nclosure" in DEPLOYMENT_SYSTEM


def test_an_unknown_answer_leaves_it_for_a_person():
    model = _Model(verdict="unknown",
                   evidence="Приложение работает в Kubernetes. Внешний трафик приходит только через",
                   why="это условие про код, а не про платформу")

    result = check_against_deployment(
        _external("приложение десериализует недоверенные данные"), _Deployment(_K8S), model)

    assert result.state is ConditionState.EXTERNAL
    assert result.needs_a_person


def test_a_fabricated_quote_is_discarded():
    """Deployment prose is exactly where an invented justification would fit."""
    model = _Model(verdict="absent",
                   evidence="- deserialization_disabled_by_platform: да",
                   why="выдумано")

    result = check_against_deployment(
        _external("приложение десериализует недоверенные данные"), _Deployment(_K8S), model)

    assert result.state is ConditionState.EXTERNAL, (
        "ответ с несуществующей цитатой не должен ничего закрывать")


def test_a_condition_the_code_already_settled_is_not_reopened():
    """Only EXTERNAL comes here: an answer from the repository outranks prose."""
    settled = Condition(ConditionState.HOLDS, "рендерятся пользовательские шаблоны",
                        ["createTemplate"], "контроллеры", hits=["src/R.php:12"])
    model = _Model(verdict="absent", evidence=_K8S.splitlines()[0], why="что угодно")

    result = check_against_deployment(settled, _Deployment(_K8S), model)

    assert result is settled
    assert not model.prompts, "модель не должна была спрашиваться"


def test_without_a_model_nothing_changes():
    condition = _external("сервис доступен из интернета")
    assert check_against_deployment(condition, _Deployment(_K8S), None) is condition


def test_the_model_is_shown_both_the_condition_and_the_environment():
    model = _Model()
    check_against_deployment(_external("слушает привилегированный порт"),
                             _Deployment(_K8S), model)

    shown = model.prompts[0]
    assert "слушает привилегированный порт" in shown
    assert "ingress-контроллер" in shown
