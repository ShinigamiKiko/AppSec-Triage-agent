import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.sca import codeql_agent
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.codeql_api import ApiAnswer
from appsec_triage.sca.codeql_reach import Reached
from appsec_triage.sca.presence import Hit, SymbolPresence
from appsec_triage.sca.resolve import VulnerableSymbol
from appsec_triage.sca.verdict import CVEVerdict

ADVISORY = Advisory(advisory_id="GHSA-x", package="js-yaml", ecosystem="npm", summary="Code injection in load",
                    cwe_ids=["CWE-94"])
PATH = Reached("src/parser.js", 5, "src/server.js", 8, steps=["src/server.js:8 req.body", "src/parser.js:5 text"])


def _client(*replies):
    queue = iter(json.dumps(reply) for reply in replies)
    return SimpleNamespace(complete=Mock(side_effect=lambda *a, **k: SimpleNamespace(text=next(queue))))


def _answer_with_path():
    return ApiAnswer(calls={"load": [Hit("src/parser.js", 5, "return yaml.load(text);")]}, reached={"load": PATH})


class InvestigateTests(unittest.TestCase):
    def test_model_names_a_function_and_codeql_finds_call_and_path(self):
        client = _client({"functions": [{"name": "load", "class": "", "vulnerable": True}], "sites": [], "why": "public API"},
                         {"functions": [], "sites": [], "why": "settled"})
        ask_functions = Mock(return_value=_answer_with_path())
        ask_sites = Mock()
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=ask_functions, ask_sites=ask_sites)
        ask_functions.assert_called_once_with([("load", "")])
        ask_sites.assert_not_called()
        self.assertEqual(result.label, "load")
        self.assertIs(result.found.presence, SymbolPresence.CALLED)
        self.assertIs(result.reached, PATH)
        self.assertEqual(result.requests, 1)
        # The second round saw CodeQL's answer, trace included.
        second_material = client.complete.call_args_list[1].args[1]
        self.assertIn("трасса CodeQL", second_material)

    def test_repeating_a_question_ends_the_investigation(self):
        reply = {"functions": [{"name": "load"}], "sites": [], "why": ""}
        client = _client(reply, reply, reply)
        ask_functions = Mock(return_value=ApiAnswer())
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=ask_functions, ask_sites=Mock())
        ask_functions.assert_called_once()
        self.assertEqual(client.complete.call_count, 2)
        self.assertIsNone(result.found)

    def test_a_site_alone_does_not_prove_the_flaw(self):
        client = _client({"functions": [], "sites": [{"file": "src/parser.js", "line": 5}], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=Mock(), ask_sites=Mock(return_value=PATH))
        self.assertIsNone(result.reached)
        self.assertIsNone(result.found)

    def test_a_site_at_a_vulnerable_call_establishes_the_path(self):
        client = _client({"functions": [{"name": "load", "class": "", "vulnerable": True}], "sites": [], "why": ""},
                         {"functions": [], "sites": [{"file": "src/parser.js", "line": 5}], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        called = ApiAnswer(calls={"load": [Hit("src/parser.js", 5, "return yaml.load(text);")]})
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=Mock(return_value=called), ask_sites=Mock(return_value=PATH))
        self.assertIs(result.reached, PATH)
        self.assertEqual(result.label, "load")

    def test_path_into_a_safe_alternative_is_not_evidence(self):
        """Measured: the model asked load and safeLoad; only safeLoad was reached, and it was taken as the flaw."""
        client = _client({"functions": [{"name": "load", "class": "", "vulnerable": True},
                                        {"name": "safeLoad", "class": "", "vulnerable": False}],
                          "sites": [], "why": "load is affected, safeLoad is the safe schema"},
                         {"functions": [], "sites": [], "why": "settled"})
        safe_path = Reached("src/server.js", 8, "src/server.js", 8)
        answer = ApiAnswer(calls={"safeLoad": [Hit("src/server.js", 8, "yaml.safeLoad(req.body)")]},
                           reached={"safeLoad": safe_path})
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=Mock(return_value=answer), ask_sites=Mock())
        self.assertIsNone(result.found)
        self.assertIsNone(result.reached)
        self.assertIn("safeLoad (context", client.complete.call_args_list[1].args[1])

    def test_advisory_saying_unaffected_overrules_the_model(self):
        """Measured: with the prompt rule in place the model still marked safeLoad vulnerable."""
        advisory = Advisory(
            advisory_id="GHSA-8j8c-7jfh-h6hx", package="js-yaml", ecosystem="npm", summary="Code Injection in js-yaml",
            details=("Objects that have `toString` as key are used as explicit mapping keys allow attackers to "
                     "execute the supplied code through the `load()` function. The `safeLoad()` function is unaffected."))
        self.assertIn("safeLoad()", codeql_agent.declared_unaffected(advisory, "safeLoad"))
        self.assertEqual(codeql_agent.declared_unaffected(advisory, "load"), "")

        client = _client({"functions": [{"name": "load", "class": "", "vulnerable": True},
                                        {"name": "safeLoad", "class": "", "vulnerable": True}],
                          "sites": [], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        safe_path = Reached("src/server.js", 8, "src/server.js", 8)
        answer = ApiAnswer(calls={"safeLoad": [Hit("src/server.js", 8, "yaml.safeLoad(req.body)")]},
                           reached={"safeLoad": safe_path})
        result = codeql_agent.investigate(client, advisory, None, "js-yaml",
                                          ask_functions=Mock(return_value=answer), ask_sites=Mock())
        self.assertIsNone(result.found)
        self.assertIsNone(result.reached)
        self.assertIn("safeLoad is marked context", client.complete.call_args_list[1].args[1])

    def test_callers_condition_and_mixed_clauses_do_not_overrule_the_vulnerable_function(self):
        advisory = Advisory(
            advisory_id="GHSA-x", package="js-yaml", ecosystem="npm",
            details=("Applications that do not pass untrusted input to `load()` are not affected. "
                     "`load()` is vulnerable while `safeLoad()` is unaffected."))
        self.assertEqual(codeql_agent.declared_unaffected(advisory, "load"), "")
        self.assertIn("safeLoad()", codeql_agent.declared_unaffected(advisory, "safeLoad"))

    def test_leading_backslash_class_matches_the_engine_answer(self):
        label = "Symfony\\Component\\Yaml\\Yaml::parse"
        client = _client({"functions": [{"name": "parse", "class": "\\Symfony\\Component\\Yaml\\Yaml",
                                         "vulnerable": True}], "sites": [], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        ask_functions = Mock(return_value=ApiAnswer(calls={label: [Hit("src/A.php", 3, "Yaml::parse($x)")]}))
        result = codeql_agent.investigate(client, ADVISORY, None, "symfony/yaml", ask_functions=ask_functions,
                                          ask_sites=Mock(), engine="Psalm")
        ask_functions.assert_called_once_with([("parse", "Symfony\\Component\\Yaml\\Yaml")])
        self.assertEqual(result.label, label)
        self.assertIsNotNone(result.found)

    def test_unmarked_function_is_context(self):
        client = _client({"functions": [{"name": "load", "class": ""}], "sites": [], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=Mock(return_value=_answer_with_path()), ask_sites=Mock())
        self.assertIsNone(result.found)

    def test_namespaced_php_class_is_asked(self):
        client = _client({"functions": [{"name": "parse", "class": "Symfony\\Component\\Yaml\\Yaml"}],
                          "sites": [], "why": ""},
                         {"functions": [], "sites": [], "why": ""})
        ask_functions = Mock(return_value=ApiAnswer())
        codeql_agent.investigate(client, ADVISORY, None, "symfony/yaml", ask_functions=ask_functions,
                                 ask_sites=Mock(), engine="Psalm")
        ask_functions.assert_called_once_with([("parse", "Symfony\\Component\\Yaml\\Yaml")])
        self.assertIn("fully qualified class name", client.complete.call_args_list[0].args[1])

    def test_unsafe_names_and_paths_are_not_asked(self):
        client = _client({"functions": [{"name": "load()x"}, {"name": "ok", "class": "a-b"}],
                          "sites": [{"file": "../etc/passwd", "line": 1}, {"file": "/abs.js", "line": 2},
                                    {"file": "src/a.js", "line": 0}], "why": ""})
        ask_functions, ask_sites = Mock(), Mock()
        result = codeql_agent.investigate(client, ADVISORY, None, "js-yaml",
                                          ask_functions=ask_functions, ask_sites=ask_sites)
        ask_functions.assert_not_called()
        ask_sites.assert_not_called()
        self.assertEqual(result.requests, 0)

    def test_without_a_model_nothing_is_asked(self):
        ask_functions = Mock()
        result = codeql_agent.investigate(None, ADVISORY, None, "js-yaml", ask_functions=ask_functions, ask_sites=Mock())
        ask_functions.assert_not_called()
        self.assertIn("модель не подключена", result.detail)


class ChainLetsTheModelAskCodeQLTests(unittest.TestCase):
    def test_model_question_reaches_the_database_and_decides_with_its_path(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "server.js").write_text("const yaml = require('js-yaml');\n", encoding="utf-8")
            client = _client({"functions": [{"name": "load", "class": "", "vulnerable": True}], "sites": [], "why": "public API"},
                             {"functions": [], "sites": [], "why": "settled"})
            chain = DependencyChain(client, [root], codeql_databases={"javascript": root})
            chain._resolver.resolve = Mock(return_value=VulnerableSymbol(
                "GHSA-x", package="js-yaml", function="storeMappingPair", grounded_in_fix=True))
            chain._resolver._last_resort = Mock(return_value=None)
            chain._placement = Mock(return_value=SimpleNamespace(
                direct=True, known=True, introductions=[],
                describe=lambda: "прямая зависимость проекта", upgrade_note=lambda: ""))
            chain._exploit.assess = Mock(return_value=Mock(problems=[], render=Mock(return_value="")))
            finding = Finding(
                finding_id="f-1", scanner="wolfee", rule_id="GHSA-x", cwe="CWE-94",
                code_context=CodeContext(file_path="package.json"),
                dependency=DependencyInfo(package="js-yaml", ecosystem="npm", installed_version="3.13.0"))
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=ADVISORY), \
                    patch("appsec_triage.sca.chain.support.codeql_api.run",
                          return_value=_answer_with_path()) as database:
                result = chain.run(finding)

        database.assert_called_once()
        self.assertTrue(result.codeql_calls[0].startswith("модель (запрос к CodeQL) → CodeQL API пакета js-yaml (load)"))
        self.assertIn("трасса CodeQL", result.codeql_calls[0])
        self.assertEqual(result.route, "codeql")
        self.assertEqual(result.matched_symbol, "load")
        self.assertIs(result.decision.verdict, CVEVerdict.ACTUAL)
        self.assertIn("load (запрошено моделью через CodeQL)", result.searched_for)
        self.assertEqual(result.summary().codeql_calls, result.codeql_calls)


if __name__ == "__main__":
    unittest.main()
