"""Does untrusted input reach the call, when no tool can say.

CodeQL has no PHP; the language server has no call graph. On the projects this
runs against, the pair that was supposed to answer this cannot run at all, and
the finding sat in "unknown" forever. Reading the file is what a reviewer does
instead, so the model is asked — under the same rule as every other answer here:
quote the material verbatim or be discarded.

The tests that matter are the ones about a wrong `no`: that is the answer that
hides a real vulnerability, and it is the reason `unknown` has to stay
available and be used.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from appsec_triage.sca.presence import Hit
from appsec_triage.sca.reach import Reachability, assess


class _Model:
    def __init__(self, **answer) -> None:
        self.answer = {"verdict": "unknown", "evidence": "", "why": "", **answer}
        self.prompts: list[str] = []

    def complete(self, system, user, json_schema=None):
        self.prompts.append(user)
        return SimpleNamespace(text=json.dumps(self.answer))


def _controller(tmp_path):
    path = tmp_path / "src" / "Controller" / "ExportController.php"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "<?php\n"
        "namespace App\\Controller;\n"
        "use Symfony\\Component\\HttpFoundation\\Request;\n"
        "\n"
        "class ExportController\n"
        "{\n"
        "    public function export(Request $request)\n"
        "    {\n"
        "        $name = $request->query->get('name');\n"
        "        return $this->writer->generateRow($name);\n"
        "    }\n"
        "}\n",
        encoding="utf-8")
    return [Hit("src/Controller/ExportController.php", 10,
                "return $this->writer->generateRow($name);", False, 30)]


def test_a_grounded_yes_makes_it_reachable(tmp_path):
    model = _Model(verdict="yes",
                   evidence="        $name = $request->query->get('name');",
                   why="значение приходит из query-параметра запроса")

    result = assess(_controller(tmp_path), tmp_path, lsp=None, routes=None, client=model)

    assert result.verdict is not Reachability.NO_INPUT_PATH
    assert "по чтению кода" in result.taint_path


def test_a_grounded_no_closes_the_input_path(tmp_path):
    model = _Model(verdict="no",
                   evidence="        $name = $request->query->get('name');",
                   why="в вызов уходит константа, а не это значение")

    result = assess(_controller(tmp_path), tmp_path, lsp=None, routes=None, client=model)

    assert result.verdict is Reachability.NO_INPUT_PATH
    assert "не доходит" in result.detail


def test_unknown_never_becomes_no(tmp_path):
    """The failure that hides a vulnerability: "could not tell" read as "safe"."""
    model = _Model(verdict="unknown",
                   evidence="        $name = $request->query->get('name');",
                   why="не видно, кто вызывает этот метод")

    result = assess(_controller(tmp_path), tmp_path, lsp=None, routes=None, client=model)

    assert result.verdict is Reachability.UNKNOWN


def test_a_fabricated_quote_is_discarded(tmp_path):
    model = _Model(verdict="no", evidence="$name = 'constant';", why="выдумано")
    result = assess(_controller(tmp_path), tmp_path, lsp=None, routes=None, client=model)
    assert result.verdict is Reachability.UNKNOWN, (
        "ответ с несуществующей цитатой не должен закрывать путь")


def test_the_model_sees_the_lines_around_the_call(tmp_path):
    model = _Model()
    assess(_controller(tmp_path), tmp_path, lsp=None, routes=None, client=model)

    shown = model.prompts[0]
    assert "$request->query->get('name')" in shown
    assert "use Symfony\\Component\\HttpFoundation\\Request;" in shown


def test_without_a_model_nothing_changes(tmp_path):
    result = assess(_controller(tmp_path), tmp_path, lsp=None, routes=None)
    assert result.verdict is Reachability.UNKNOWN
