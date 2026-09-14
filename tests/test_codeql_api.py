import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.sca import codeql_api
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.codeql_reach import Reached
from appsec_triage.sca.presence import Hit, SymbolPresence
from appsec_triage.sca.resolve import VulnerableSymbol
from appsec_triage.sca.verdict import CVEVerdict


def _loc(uri, line, text=""):
    location = {"physicalLocation": {"artifactLocation": {"uri": uri}, "region": {"startLine": line}}}
    if text:
        location["message"] = {"text": text}
    return location


class ParsePathsTests(unittest.TestCase):
    def test_multi_step_path_keeps_codeql_steps_source_first(self):
        document = {"runs": [{"results": [{
            "message": {"text": "reaches load"},
            "locations": [_loc("src/parser.js", 5)],
            "codeFlows": [{"threadFlows": [{"locations": [
                {"location": _loc("src/server.js", 8, "req.body")},
                {"location": _loc("src/parser.js", 3, "source")},
                {"location": _loc("src/parser.js", 5, "normalized")},
            ]}]}],
        }]}]}
        reached = codeql_api.parse_paths(document)["load"]
        self.assertEqual((reached.source_file, reached.source_line), ("src/server.js", 8))
        self.assertEqual((reached.file, reached.line), ("src/parser.js", 5))
        self.assertEqual(reached.steps, ["src/server.js:8 req.body", "src/parser.js:3 source",
                                         "src/parser.js:5 normalized"])
        self.assertIn("трасса CodeQL: src/server.js:8 req.body →", reached.render())

    def test_zero_length_path_has_no_code_flows_and_is_still_reached(self):
        document = {"runs": [{"results": [{
            "message": {"text": "reaches load"}, "locations": [_loc("src/server.js", 8)]}]}]}
        reached = codeql_api.parse_paths(document)["load"]
        self.assertEqual((reached.source_file, reached.source_line), ("src/server.js", 8))
        self.assertEqual(reached.steps, [])


class QueryShapeTests(unittest.TestCase):
    def test_every_import_shape_is_searched(self):
        text = codeql_api.call_predicate([codeql_api.Target("lodash", "template")])
        self.assertIn('API::moduleImport("lodash").getMember("template").getACall()', text)
        self.assertIn('API::moduleImport("lodash/template").getACall()', text)
        self.assertNotIn("getInstance", text)

    def test_class_methods_go_through_the_class_only(self):
        text = codeql_api.call_predicate([codeql_api.Target("pkg", "run", "Client")])
        self.assertIn('getMember("Client").getInstance().getMember("run")', text)
        self.assertIn('getMember("Client").getMember("run")', text)
        self.assertIn('label = "Client::run"', text)
        # A module-level `pkg.run` is a different function and must not match.
        self.assertNotIn('API::moduleImport("pkg").getMember("run")', text)
        self.assertNotIn('"pkg/run"', text)

    def test_names_are_escaped(self):
        text = codeql_api.call_predicate([codeql_api.Target('evil"pkg', "f")])
        self.assertIn('"evil\\"pkg"', text)


class ApiAnswerTests(unittest.TestCase):
    hit = Hit("src/server.js", 8, "yaml.load(req.body)")

    def test_call_without_path_is_a_negative(self):
        answer = codeql_api.ApiAnswer(calls={"load": [self.hit]})
        self.assertIs(answer.presence("load").presence, SymbolPresence.CALLED)
        self.assertIs(answer.dataflow("load"), False)

    def test_no_call_says_nothing_about_flow(self):
        answer = codeql_api.ApiAnswer()
        self.assertIs(answer.presence("load").presence, SymbolPresence.ABSENT)
        self.assertIsNone(answer.dataflow("load"))

    def test_failed_query_answers_nothing(self):
        answer = codeql_api.ApiAnswer(calls={"load": [self.hit]}, problem="timeout")
        self.assertFalse(answer.usable)
        self.assertIsNone(answer.dataflow("load"))


class ChainUsesCodeQLTests(unittest.TestCase):
    """The chain takes the call and the trace from CodeQL, not from reading the file."""

    def _run(self, source, answer):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "server.js").write_text(source, encoding="utf-8")
            chain = DependencyChain(None, [root])
            chain._resolver.resolve = Mock(return_value=VulnerableSymbol(
                "GHSA-x", package="js-yaml", function="load", grounded_in_fix=True))
            chain._resolver._last_resort = Mock(return_value=None)
            chain._placement = Mock(return_value=SimpleNamespace(
                direct=True, known=True, introductions=[],
                describe=lambda: "прямая зависимость проекта", upgrade_note=lambda: ""))
            chain._exploit.assess = Mock(return_value=Mock(problems=[], render=Mock(return_value="")))
            chain._codeql_api_for = Mock(return_value=answer)
            finding = Finding(
                finding_id="f-1", scanner="wolfee", rule_id="GHSA-x", cwe="CWE-94",
                code_context=CodeContext(file_path="package.json"),
                dependency=DependencyInfo(package="js-yaml", ecosystem="npm", installed_version="3.13.0"))
            advisory = Advisory(advisory_id="GHSA-x", package="js-yaml", ecosystem="npm", cwe_ids=["CWE-94"])
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=advisory), \
                    patch("appsec_triage.sca.chain.orchestration.reach_mod.assess") as model_reading:
                return chain.run(finding), model_reading

    def test_codeql_path_decides_and_the_model_writes_no_trace(self):
        path = Reached("src/parser.js", 5, "src/server.js", 8,
                       steps=["src/server.js:8 req.body", "src/parser.js:5 normalized"])
        answer = codeql_api.ApiAnswer(calls={"load": [Hit("src/parser.js", 5, "yaml.load(normalized)")]},
                                      reached={"load": path})
        result, model_reading = self._run("const yaml = require('js-yaml');\n", answer)
        self.assertIs(result.decision.verdict, CVEVerdict.ACTUAL)
        self.assertIs(result.dataflow, path)
        self.assertIn("трасса CodeQL", result.summary().trace)
        self.assertEqual(result.route, "codeql")
        model_reading.assert_not_called()

    def test_codeql_silence_on_the_call_still_runs_the_text_search(self):
        source = "const yaml = require('js-yaml');\nyaml.load(document);\n"
        result, _ = self._run(source, codeql_api.ApiAnswer())
        self.assertEqual(result.matched_symbol, "load")
        self.assertTrue(result.presence.found)
        self.assertEqual(result.route, "text")


if __name__ == "__main__":
    unittest.main()
