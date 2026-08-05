"""Resolving the receiver of a call the text cannot type.

Two calls that look identical to a regex: one on an interface that really does
land on the vulnerable class, one on a container that shares a method name with
it. The language server separates them, and where it cannot — nothing indexed,
no server — the question has to stay open with the reason attached, never
collapse to "not vulnerable".
"""

from __future__ import annotations

from pathlib import Path

from appsec_triage.sca.presence import Hit, PresenceResult, SymbolPresence
from appsec_triage.sca.receiver import resolve


class _Client:
    def __init__(self, locations) -> None:
        self._locations = locations
        self.asked = []

    def open_document(self, path, language):
        return True

    def definition(self, path, line, character):
        self.asked.append((str(path), line, character))
        return self._locations


class _LSP:
    def __init__(self, client) -> None:
        self._client_obj = client
        self.cfg = type("cfg", (), {"language_for": staticmethod(lambda p: "php")})()

    def _client(self, language):
        return self._client_obj

    def _path_map_for(self, language):
        return {}


def _unconfirmed(file="src/Security/Decorator.php"):
    return PresenceResult(
        SymbolPresence.CALL_UNCONFIRMED, "DefaultAuthenticationFailureHandler::onAuthenticationFailure",
        [Hit(file, 68, "$this->decorated->onAuthenticationFailure($r, $e);", False, 24)],
        detail="класс объекта не подтверждён")


def test_the_server_confirming_the_class_makes_it_a_call(tmp_path):
    client = _Client([{"uri": "file:///vendor/symfony/security-http/"
                              "Authentication/DefaultAuthenticationFailureHandler.php"}])
    resolution = resolve(_unconfirmed(), _LSP(client), tmp_path,
                         "DefaultAuthenticationFailureHandler", "symfony/security-http")

    assert resolution.presence.presence is SymbolPresence.CALLED
    assert "языковой сервер подтвердил" in resolution.presence.detail


def test_a_definition_in_another_class_weakens_but_does_not_close(tmp_path):
    """The server answered 2 of 5 positions on a project with its dependencies
    installed, and one answer pointed at the wrong file. That is enough to
    raise confidence, not enough to close a finding."""
    client = _Client([{"uri": "file:///vendor/symfony/dependency-injection/Container.php"}])
    result = PresenceResult(
        SymbolPresence.CALL_UNCONFIRMED, "ParameterizedHeader::getParameter",
        [Hit("src/Compiler.php", 17, "$container->getParameter('roles');", False, 16)])

    resolution = resolve(result, _LSP(client), tmp_path,
                         "ParameterizedHeader", "symfony/mime")

    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED
    assert "не доказательство" in resolution.presence.detail
    assert "Container.php" in resolution.presence.detail


def test_a_definition_pointing_at_the_call_site_resolved_nothing(tmp_path):
    """Measured on symfony/demo: asked about `setDescription`, phpactor answered
    with the calling file rather than the declaration in symfony/console."""
    (tmp_path / "src").mkdir()
    call_site = tmp_path / "src" / "AddUserCommand.php"
    call_site.write_text("<?php\n", encoding="utf-8")

    client = _Client([{"uri": f"file://{call_site}"}])
    result = PresenceResult(
        SymbolPresence.CALL_UNCONFIRMED, "Command::setDescription",
        [Hit("src/AddUserCommand.php", 81, "->setDescription('x')", False, 2)])

    resolution = resolve(result, _LSP(client), tmp_path, "Command", "symfony/console")

    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED
    assert "AddUserCommand" not in resolution.presence.detail, (
        "определение на месте вызова не должно приписывать вызов этому классу")


def test_the_position_asked_is_the_method_name_not_the_line_start(tmp_path):
    client = _Client([])
    resolve(_unconfirmed(), _LSP(client), tmp_path, "X", "p")
    assert client.asked, "сервер не был спрошен"
    _, line, character = client.asked[0]
    assert line == 67, "LSP считает строки с нуля"
    assert character == 24


def test_no_definition_reports_what_happened_not_a_guessed_cause(tmp_path):
    """The first version claimed "dependencies are not installed" — and said it
    on a project whose dependencies were installed. The message states the
    observation; the cause is not ours to assert."""
    resolution = resolve(_unconfirmed(), _LSP(_Client([])), tmp_path,
                         "DefaultAuthenticationFailureHandler", "symfony/security-http")

    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED
    assert "не вернул ни одного определения" in resolution.detail
    assert "symfony/security-http" in resolution.detail
    assert "не установлен" not in resolution.detail


def test_no_language_server_is_not_a_verdict(tmp_path):
    resolution = resolve(_unconfirmed(), None, tmp_path, "X", "p")
    assert resolution.presence.presence is SymbolPresence.CALL_UNCONFIRMED
    assert "не подключён" in resolution.detail


def test_a_settled_result_is_left_alone(tmp_path):
    called = PresenceResult(SymbolPresence.CALLED, "A::b",
                            [Hit("src/A.php", 1, "$a->b();")])
    assert resolve(called, None, tmp_path, "A", "p").presence is called
