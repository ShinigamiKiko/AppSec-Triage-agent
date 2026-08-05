"""Asking the model what a type resolver could not answer.

The resolver failed for a reason that is not a defect: containers, factories and
magic accessors hide the concrete class, and it answers syntactically. A
reviewer settles those by reading the file, so the model is asked to do the
same — and every answer is held to the same rule as everywhere else in this
pipeline: quote the material verbatim, or be discarded.

The tests that matter are the ones about a wrong answer getting through. A
fabricated quote, an answer with no quote, a `yes` on nothing — each would
invent a vulnerability, and each is checked here.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from appsec_triage.sca.presence import Hit, PresenceResult, SymbolPresence
from appsec_triage.sca.receiver import resolve


class _Model:
    """Answers with a fixed payload, and records what it was shown."""

    def __init__(self, **answer) -> None:
        self.answer = {"verdict": "unknown", "evidence": "", "why": "", **answer}
        self.prompts: list[str] = []

    def complete(self, system, user, json_schema=None):
        self.prompts.append(user)
        return SimpleNamespace(text=json.dumps(self.answer))


def _decorator(tmp_path):
    path = tmp_path / "src" / "Security" / "Decorator.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "<?php\n"
        "namespace App\\Security;\n"
        "use Symfony\\Component\\Security\\Guard\\AuthenticatorInterface;\n"
        "\n"
        "class Decorator implements AuthenticatorInterface\n"
        "{\n"
        "    private AuthenticatorInterface $decorated;\n"
        "\n"
        "    public function onAuthenticationFailure($request, $exception)\n"
        "    {\n"
        "        return $this->decorated->onAuthenticationFailure($request, $exception);\n"
        "    }\n"
        "}\n",
        encoding="utf-8")
    return PresenceResult(
        SymbolPresence.CALL_UNCONFIRMED,
        "DefaultAuthenticationFailureHandler::onAuthenticationFailure",
        [Hit("src/Security/Decorator.php", 11,
             "return $this->decorated->onAuthenticationFailure($request, $exception);",
             False, 30)],
        detail="класс объекта не подтверждён")


def test_the_question_is_asked_in_every_language_not_just_php(tmp_path):
    """Matching only `$this->` meant the model was never asked outside PHP."""
    from appsec_triage.sca.receiver import _receiver_expression

    assert _receiver_expression("$this->decorated->onAuthenticationFailure($r);") == \
        "$this->decorated"
    assert _receiver_expression("return this.client.request(config);") == "this.client"
    assert _receiver_expression("return self.session.request(url)") == "self.session"
    assert _receiver_expression("return c.client.Do(req)") == "c.client"
    assert _receiver_expression("doSomething(value)") == ""


def test_a_typescript_call_reaches_the_model(tmp_path):
    path = tmp_path / "src" / "client.ts"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "import { Agent } from 'proxy-agent';\n"
        "\n"
        "export class Fetcher {\n"
        "  private client: Agent;\n"
        "  fetch(url: string) {\n"
        "    return this.client.request(url);\n"
        "  }\n"
        "}\n",
        encoding="utf-8")

    result = PresenceResult(
        SymbolPresence.CALL_UNCONFIRMED, "Agent::request",
        [Hit("src/client.ts", 6, "return this.client.request(url);", False, 21)])
    model = _Model(verdict="yes", evidence="  private client: Agent;",
                   why="поле объявлено типом Agent")

    resolution = resolve(result, None, tmp_path, "Agent", "proxy-agent", client=model)

    assert model.prompts, "модель не была спрошена для TypeScript"
    assert "private client: Agent;" in model.prompts[0], "объявление поля не показано"
    assert resolution.presence.presence is SymbolPresence.CALLED


def test_a_grounded_yes_settles_the_call(tmp_path):
    result = _decorator(tmp_path)
    model = _Model(verdict="yes",
                   evidence="    private AuthenticatorInterface $decorated;",
                   why="свойство объявлено интерфейсом, который контейнер связывает с этим классом")

    resolution = resolve(result, None, tmp_path,
                         "DefaultAuthenticationFailureHandler", "symfony/security-http",
                         client=model)

    assert resolution.presence.presence is SymbolPresence.CALLED
    assert "модель разобрала вызов" in resolution.presence.detail


def test_a_grounded_no_drops_it(tmp_path):
    result = _decorator(tmp_path)
    model = _Model(verdict="no",
                   evidence="    private AuthenticatorInterface $decorated;",
                   why="это другой обработчик")

    resolution = resolve(result, None, tmp_path, "SomeOtherHandler", "x/y", client=model)

    assert resolution.presence.presence is SymbolPresence.ABSENT
    assert "вызов идёт не в SomeOtherHandler" in resolution.presence.detail


def test_a_fabricated_quote_is_discarded(tmp_path):
    """The control that catches invented answers everywhere else in the pipeline."""
    result = _decorator(tmp_path)
    model = _Model(verdict="yes",
                   evidence="private DefaultAuthenticationFailureHandler $decorated;",
                   why="выдумано")

    resolution = resolve(result, None, tmp_path,
                         "DefaultAuthenticationFailureHandler", "symfony/security-http",
                         client=model)

    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED, (
        "ответ с несуществующей цитатой не должен ничего решать")


def test_an_answer_without_a_quote_is_discarded(tmp_path):
    result = _decorator(tmp_path)
    model = _Model(verdict="yes", evidence="", why="уверен")
    resolution = resolve(result, None, tmp_path, "X", "p", client=model)
    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED


def test_unknown_leaves_the_question_open(tmp_path):
    result = _decorator(tmp_path)
    model = _Model(verdict="unknown",
                   evidence="    private AuthenticatorInterface $decorated;",
                   why="объект приходит из контейнера, конфигурации не показано")
    resolution = resolve(result, None, tmp_path, "X", "p", client=model)
    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED


def test_the_model_is_shown_the_declaration_and_the_imports(tmp_path):
    """It cannot answer from a single line, and must not be asked to."""
    result = _decorator(tmp_path)
    model = _Model()
    resolve(result, None, tmp_path, "X", "p", client=model)

    shown = model.prompts[0]
    assert "private AuthenticatorInterface $decorated;" in shown
    assert "use Symfony\\Component\\Security\\Guard\\AuthenticatorInterface;" in shown
    assert "src/Security/Decorator.php:11" in shown


def test_a_broken_model_costs_nothing(tmp_path):
    class _Broken:
        def complete(self, system, user, json_schema=None):
            raise RuntimeError("provider timed out")

    result = _decorator(tmp_path)
    resolution = resolve(result, None, tmp_path, "X", "p", client=_Broken())
    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED


def test_no_client_means_the_step_is_skipped(tmp_path):
    result = _decorator(tmp_path)
    resolution = resolve(result, None, tmp_path, "X", "p")
    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED
    assert "не подключён" in resolution.detail
