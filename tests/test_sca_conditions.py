"""Preconditions: decided against the repository, or handed over on purpose.

The important case is the third one. A condition whose answer lives outside the
source tree must not quietly become `unknown` — that reads as "the tool tried
and could not tell", and a reviewer treats it as noise. It has to say that it is
external, and say enough that a person can settle it without reading the
advisory themselves.
"""

from __future__ import annotations

from appsec_triage.sca.conditions import ConditionState, check


def _write(tmp_path, name, body):
    path = tmp_path / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return tmp_path


def test_a_condition_the_code_meets_is_reported_as_met(tmp_path):
    _write(tmp_path, "src/Render.php",
           "<?php\n$twig->createTemplate($userSupplied);\n")
    condition = check([tmp_path], "приложение рендерит пользовательские шаблоны",
                      ["createTemplate", "->render("], "контроллеры")
    assert condition.state is ConditionState.HOLDS
    assert "src/Render.php:2" in condition.hits[0]


def test_a_condition_the_code_contradicts_is_reported_as_absent(tmp_path):
    _write(tmp_path, "src/App.php", "<?php\necho 'hello';\n")
    condition = check([tmp_path], "приложение рендерит пользовательские шаблоны",
                      ["createTemplate"], "контроллеры")
    assert condition.state is ConditionState.ABSENT
    assert "не выполняется" in condition.render()


def test_configuration_files_are_searched_too(tmp_path):
    """Most of these conditions live in config, not in code."""
    _write(tmp_path, "config/packages/twig.yaml", "twig:\n    sandbox: true\n")
    condition = check([tmp_path], "песочница включена", ["sandbox"], "config/packages")
    assert condition.state is ConditionState.HOLDS


def test_an_undecidable_condition_says_external_with_instructions(tmp_path):
    _write(tmp_path, "src/App.php", "<?php\n")
    condition = check(
        [tmp_path],
        "загрузка внешних XML-сущностей включена в окружении",
        ["libxml_disable_entity_loader", "LIBXML_NOENT"],
        "php.ini и переменные окружения деплоя",
        decidable=False,
    )
    assert condition.state is ConditionState.EXTERNAL
    assert condition.needs_a_person is True

    rendered = condition.render()
    # Phrased as a note rather than a blocker: the earlier "проверить
    # обязательно" pushed the verdict to `unknown` and turned five decided
    # findings per project into work for a person.
    assert "условие не проверено" in rendered
    assert "на вердикт по версии не влияет" in rendered
    assert "что должно быть верно:" in rendered
    assert "libxml_disable_entity_loader" in rendered, "не сказано, что именно искать"
    assert "php.ini" in rendered, "не сказано, где смотреть"
    assert "почему нельзя решить здесь:" in rendered


def test_a_condition_with_nothing_searchable_is_external_not_absent(tmp_path):
    """No tokens means the search would find nothing — which is not evidence."""
    _write(tmp_path, "src/App.php", "<?php\n")
    condition = check([tmp_path], "приложение обрабатывает недоверенный ввод", [], "")
    assert condition.state is ConditionState.EXTERNAL
    assert "ни одного конкретного символа" in condition.reason


def test_no_source_roots_is_external_not_absent(tmp_path):
    condition = check([], "песочница включена", ["sandbox"], "config")
    assert condition.state is ConditionState.EXTERNAL
    assert "искать негде" in condition.reason


def test_a_flaw_with_no_precondition_stays_silent(tmp_path):
    condition = check([tmp_path], "", ["anything"], "")
    assert condition.state is ConditionState.NONE
    assert condition.render() == ""
