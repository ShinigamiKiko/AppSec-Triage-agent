import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.sca import psalm_api
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.codeql_api import ApiAnswer, Target
from appsec_triage.sca.codeql_reach import Reached
from appsec_triage.sca.presence import Hit
from appsec_triage.sca.resolve import VulnerableSymbol
from appsec_triage.sca.verdict import CVEVerdict

YAML = psalm_api.Signature("Symfony\\Component\\Yaml\\Yaml::parse", "parse", "Symfony\\Component\\Yaml\\Yaml",
                           "class", True, [{"name": "input"}, {"name": "flags", "optional": True}])
PARSER = psalm_api.Signature("Symfony\\Component\\Yaml\\Parser::parse", "parse", "Symfony\\Component\\Yaml\\Parser",
                             "class", False, [{"name": "value"}, {"name": "flags", "optional": True}])


class StubTests(unittest.TestCase):
    def test_static_and_instance_methods_become_eval_sinks(self):
        text = psalm_api.stub([YAML, PARSER])
        self.assertIn("namespace Symfony\\Component\\Yaml {", text)
        self.assertIn("class Yaml {", text)
        self.assertIn("public static function parse($input, $flags = null) {}", text)
        self.assertIn("public function parse($value, $flags = null) {}", text)
        self.assertIn("@psalm-taint-sink eval $input", text)
        self.assertIn("@psalm-taint-sink eval $value", text)

    def test_variadic_interface_and_function(self):
        text = psalm_api.stub([
            psalm_api.Signature("Vendor\\Api::call", "call", "Vendor\\Api", "interface", False,
                                [{"name": "args", "variadic": True}]),
            psalm_api.Signature("render", "render", "Vendor\\render", "function", False, [{"name": "template"}]),
        ])
        self.assertIn("interface Api {", text)
        self.assertIn("public function call(...$args);", text)
        self.assertIn("function render($template) {}", text)

    def test_unsafe_names_are_not_asked(self):
        valid = psalm_api.targets_valid([Target("p", "parse", "Symfony\\Component\\Yaml\\Yaml"),
                                         Target("p", "parse()", ""), Target("p", "run", "Bad-Class")])
        self.assertEqual([t.function for t in valid], ["parse"])


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name, "project").resolve()
        (self.project / "src").mkdir(parents=True)
        (self.project / "src" / "Import.php").write_text(
            "<?php\n\nfinal class Import {\n  function run($d) { return Yaml::parse($d); }\n"
            "  function page($n) { echo $n; }\n}\n", encoding="utf-8")
        self.work = Path(self.tmp.name, "work").resolve()
        self.work.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def _uri(self, rel):
        import os
        return os.path.relpath(self.project / rel, self.work)

    def test_references_strip_ansi_and_resolve_relative_paths(self):
        output = (f"{self._uri('src/Import.php')}:4\n        return Yaml::\x1b[97;42mparse\x1b[0m($d);\n"
                  f"{self._uri('src/Import.php')}:4\n------\nNo errors found!\n/elsewhere/Outside.php:3\n")
        self.assertEqual(psalm_api.parse_references(output, self.work, self.project), [("src/Import.php", 4)])

    def test_taint_keeps_only_eval_sinks_on_a_line_calling_the_method(self):
        def result(rule_id, line, steps):
            return {"ruleId": rule_id, "message": {"text": "tainted"},
                    "locations": [{"physicalLocation": {"artifactLocation": {"uri": self._uri("src/Import.php")},
                                                        "region": {"startLine": line}}}],
                    "codeFlows": [{"threadFlows": [{"locations": [
                        {"location": {"physicalLocation": {"artifactLocation": {"uri": self._uri("src/Import.php")},
                                                           "region": {"startLine": s}}}} for s in steps]}]}]}
        document = {"runs": [{
            "tool": {"driver": {"rules": [{"id": "252", "name": "TaintedEval"}, {"id": "245", "name": "TaintedHtml"}]}},
            "results": [result("245", 5, [5]), result("252", 4, [2, 4, 4])],
        }]}
        found = psalm_api.parse_taint(document, self.work, self.project, [YAML],
                                      {YAML.label: [("src/Import.php", 4)]})
        self.assertEqual(list(found), [YAML.label])
        reached = found[YAML.label]
        self.assertEqual((reached.file, reached.line, reached.source_line), ("src/Import.php", 4, 2))
        self.assertEqual(reached.steps, ["src/Import.php:2", "src/Import.php:4"])
        self.assertTrue(reached.render().startswith("Psalm: пользовательский ввод"))

    def test_eval_sink_on_a_line_without_the_method_is_not_ours(self):
        document = {"runs": [{"tool": {"driver": {"rules": [{"id": "252", "name": "TaintedEval"}]}}, "results": [{
            "ruleId": "252", "message": {"text": "x"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": self._uri("src/Import.php")},
                                                "region": {"startLine": 5}}}]}]}]}
        self.assertEqual(psalm_api.parse_taint(document, self.work, self.project, [YAML], {}), {})

    def test_without_vendor_psalm_is_not_run(self):
        answer = psalm_api.run(self.project, [Target("symfony/yaml", "parse", "Symfony\\Component\\Yaml\\Yaml")])
        self.assertIn("vendor/autoload.php", answer.problem)
        self.assertEqual(answer.engine, "psalm")


class ClassBindingTests(unittest.TestCase):
    """A class is bound by its name or a namespace path, never by a shared suffix."""

    def test_suffix_of_another_class_does_not_bind(self):
        from appsec_triage.sca.presence import _class_is_bound
        self.assertFalse(_class_is_bound("Parser", "<?php\nuse App\\DateParser;\n$d = DateParser::parse($x);\n"))
        self.assertFalse(_class_is_bound("Parser", "<?php\n$d = new DateParser();\n"))
        self.assertFalse(_class_is_bound("Parser", "<?php\nfunction f(): DateParser {}\n"))

    def test_real_bindings_still_bind(self):
        from appsec_triage.sca.presence import _class_is_bound
        self.assertTrue(_class_is_bound("Parser", "<?php\nuse Symfony\\Component\\Yaml\\Parser;\n"))
        self.assertTrue(_class_is_bound("Parser", "<?php\n$p = new \\Symfony\\Component\\Yaml\\Parser();\n"))
        self.assertTrue(_class_is_bound("Parser", "<?php\n$p = new Parser();\n"))
        self.assertTrue(_class_is_bound("Yaml", "<?php\n$d = \\Symfony\\Component\\Yaml\\Yaml::parse($x);\n"))
        self.assertTrue(_class_is_bound("Yaml", "<?php\n$d = Yaml::parse($x);\n"))
        self.assertTrue(_class_is_bound("Parser", "<?php\nprivate Parser $parser;\n"))
        self.assertTrue(_class_is_bound("Parser", "<?php\nfunction f(): \\Symfony\\Component\\Yaml\\Parser {}\n"))


class MultiLineSinkTests(unittest.TestCase):
    """Psalm puts the sink on the argument line, below the line the call starts on."""

    def test_sink_on_an_argument_line_belongs_to_the_call_above(self):
        import os
        with tempfile.TemporaryDirectory() as tmp:
            project, work = Path(tmp, "project").resolve(), Path(tmp, "work").resolve()
            (project / "src").mkdir(parents=True)
            work.mkdir()
            (project / "src" / "Import.php").write_text(
                "<?php\nfinal class Import {\n  function run($d) {\n    return Yaml::parse(\n"
                "        $d,\n        0\n    );\n  }\n  function other($x) { return strlen(\n      $x); }\n}\n",
                encoding="utf-8")
            uri = os.path.relpath(project / "src" / "Import.php", work)

            def result(line):
                return {"ruleId": "252", "message": {"text": "tainted"},
                        "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri},
                                                            "region": {"startLine": line}}}]}
            document = {"runs": [{"tool": {"driver": {"rules": [{"id": "252", "name": "TaintedEval"}]}},
                                  "results": [result(10), result(5)]}]}
            found = psalm_api.parse_taint(document, work, project, [YAML], {YAML.label: [("src/Import.php", 4)]})
        self.assertEqual(list(found), [YAML.label])
        self.assertEqual((found[YAML.label].file, found[YAML.label].line), ("src/Import.php", 4))

    def test_call_end_skips_parentheses_inside_strings(self):
        lines = ["$x = Yaml::parse(\")\",", "    $input", ");", "$y = 1;"]
        self.assertEqual(psalm_api._call_end(lines, 1, "parse"), 3)
        self.assertEqual(psalm_api._call_end(lines, 4, "parse"), 4)


class StaticCallOnAnotherClassTests(unittest.TestCase):
    def _find(self, source, klass="Parser"):
        from appsec_triage.sca.presence import find_symbol
        with tempfile.TemporaryDirectory() as root:
            Path(root, "index.php").write_text(source, encoding="utf-8")
            return find_symbol(root, function="parse", klass=klass, ecosystem="composer", package="symfony/yaml")

    def test_named_other_class_is_not_a_candidate(self):
        result = self._find("<?php\nuse App\\DateParser;\n$d = DateParser::parse($_GET['d']);\n")
        self.assertFalse(result.found)

    def test_aliased_import_of_the_class_is_a_call(self):
        from appsec_triage.sca.presence import SymbolPresence
        result = self._find("<?php\nuse Symfony\\Component\\Yaml\\Yaml as SfYaml;\n$d = SfYaml::parse($_POST['x']);\n",
                            klass="Yaml")
        self.assertIs(result.presence, SymbolPresence.CALLED)

    def test_other_class_does_not_hide_a_second_call_on_the_line(self):
        result = self._find("<?php\nuse Symfony\\Component\\Yaml\\Parser;\n"
                            "$a = DateParser::parse($d) ?: $this->parser->parse($t);\n")
        self.assertTrue(result.found)

    def test_unknown_receiver_stays_a_candidate(self):
        from appsec_triage.sca.presence import SymbolPresence
        result = self._find("<?php\n$rows = $this->parser->parse($text);\n")
        self.assertIs(result.presence, SymbolPresence.CALL_UNCONFIRMED)

    def test_the_named_class_itself_is_a_call(self):
        from appsec_triage.sca.presence import SymbolPresence
        result = self._find("<?php\nuse Symfony\\Component\\Yaml\\Yaml;\n$d = Yaml::parse($x);\n", klass="Yaml")
        self.assertIs(result.presence, SymbolPresence.CALLED)
        result = self._find("<?php\n$d = \\Symfony\\Component\\Yaml\\Yaml::parse($x);\n", klass="Yaml")
        self.assertIs(result.presence, SymbolPresence.CALLED)


class QualifyTests(unittest.TestCase):
    def _vendor(self, root):
        package = Path(root, "vendor", "symfony", "yaml")
        (package / "Tests").mkdir(parents=True)
        # Psalm is used only for projects with an installed vendor tree.
        Path(root, "vendor", "autoload.php").write_text("<?php\n", encoding="utf-8")
        (package / "Yaml.php").write_text(
            "<?php\nnamespace Symfony\\Component\\Yaml;\n\nclass Yaml\n{\n"
            "    public static function parse(string $input) {}\n    public static function dump($v) {}\n}\n",
            encoding="utf-8")
        (package / "Parser.php").write_text(
            "<?php\nnamespace Symfony\\Component\\Yaml;\n\nfinal class Parser\n{\n"
            "    public function parse(string $value) {}\n    private function parseBlock(int $o) {}\n}\n",
            encoding="utf-8")
        (package / "Tests" / "ParserTest.php").write_text(
            "<?php\nnamespace Symfony\\Component\\Yaml\\Tests;\n\nclass ParserTest\n{\n"
            "    public function parse() {}\n}\n", encoding="utf-8")

    def test_bare_names_get_the_declaring_classes_and_tests_are_skipped(self):
        with tempfile.TemporaryDirectory() as root:
            self._vendor(root)
            found = psalm_api.qualify(root, "symfony/yaml", ["parse", "parseBlock", "missing"])
        self.assertEqual(sorted(found["parse"]), ["Symfony\\Component\\Yaml\\Parser", "Symfony\\Component\\Yaml\\Yaml"])
        self.assertEqual(found["parseBlock"], ["Symfony\\Component\\Yaml\\Parser"])
        self.assertEqual(found["missing"], [])

    def test_chain_expands_pairs_and_keeps_what_it_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as root:
            self._vendor(root)
            chain = DependencyChain(None, [root], psalm_binary="/usr/bin/psalm")
            pairs = chain._qualify_php_pairs("symfony/yaml", [("parse", ""), ("parse", "Yaml"), ("nowhere", "")])
        self.assertIn(("parse", "Symfony\\Component\\Yaml\\Parser"), pairs)
        self.assertIn(("parse", "Symfony\\Component\\Yaml\\Yaml"), pairs)
        self.assertIn(("nowhere", ""), pairs)
        self.assertNotIn(("parse", ""), pairs)
        self.assertNotIn(("parse", "Yaml"), pairs)

    def test_own_class_with_the_same_method_name_is_not_a_call(self):
        """The seeded false alarm: a bare `parse` matched App\\DateParser::parse."""
        with tempfile.TemporaryDirectory() as root:
            self._vendor(root)
            Path(root, "public").mkdir()
            Path(root, "public", "index.php").write_text(
                "<?php\nuse App\\DateParser;\nuse App\\Exporter;\n$when = DateParser::parse($_GET['date']);\n",
                encoding="utf-8")
            chain = DependencyChain(None, [root], psalm_binary="/usr/bin/psalm")
            chain._resolver.resolve = Mock(return_value=VulnerableSymbol(
                "GHSA-c2p3-7m5p-cv8x", package="symfony/yaml", function="parse", grounded_in_fix=True))
            chain._resolver._last_resort = Mock(return_value=None)
            chain._placement = Mock(return_value=SimpleNamespace(
                direct=True, known=True, introductions=[],
                describe=lambda: "прямая зависимость проекта", upgrade_note=lambda: ""))
            chain._exploit.assess = Mock(return_value=Mock(problems=[], render=Mock(return_value="")))
            finding = Finding(
                finding_id="php-own", scanner="wolfee", rule_id="GHSA-c2p3-7m5p-cv8x", cwe="CWE-776",
                code_context=CodeContext(file_path="composer.lock"),
                dependency=DependencyInfo(package="symfony/yaml", ecosystem="composer", installed_version="7.3.0"))
            advisory = Advisory(advisory_id="GHSA-c2p3-7m5p-cv8x", package="symfony/yaml", ecosystem="Packagist",
                                summary="Yaml::parse on untrusted input", cwe_ids=["CWE-776"])
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=advisory), \
                    patch("appsec_triage.sca.chain.support.psalm_api.run",
                          return_value=ApiAnswer(engine="psalm")) as psalm:
                result = chain.run(finding)
        asked = [t.label for call in psalm.call_args_list for t in call.args[1]]
        self.assertIn("Symfony\\Component\\Yaml\\Yaml::parse", asked)
        self.assertEqual(result.matched_symbol, "")
        self.assertNotEqual(result.decision.verdict, CVEVerdict.CALL_UNCONFIRMED)


class ChainUsesPsalmForPhpTests(unittest.TestCase):
    def test_composer_dependency_is_answered_by_psalm_through_the_model(self):
        import json

        label = "Symfony\\Component\\Yaml\\Yaml::parse"
        path = Reached("src/ImportController.php", 11, "public/index.php", 8,
                       steps=["public/index.php:8", "src/ImportController.php:11"], engine="Psalm")
        answer = ApiAnswer(calls={label: [Hit("src/ImportController.php", 11, "Yaml::parse($document)")]},
                           reached={label: path}, engine="psalm")
        replies = iter([{"functions": [{"name": "parse", "class": "Symfony\\Component\\Yaml\\Yaml",
                                        "vulnerable": True}], "sites": [],
                         "why": "entry point"}, {"functions": [], "sites": [], "why": "done"}])
        client = SimpleNamespace(complete=Mock(side_effect=lambda *a, **k: SimpleNamespace(text=json.dumps(next(replies)))))
        with tempfile.TemporaryDirectory() as root:
            Path(root, "vendor").mkdir()
            Path(root, "vendor", "autoload.php").write_text("<?php\n", encoding="utf-8")
            Path(root, "src").mkdir()
            Path(root, "src", "ImportController.php").write_text(
                "<?php\nuse Symfony\\Component\\Yaml\\Yaml;\n", encoding="utf-8")
            chain = DependencyChain(client, [root], psalm_binary="/usr/bin/psalm")
            chain._resolver.resolve = Mock(return_value=VulnerableSymbol(
                "GHSA-c2p3-7m5p-cv8x", package="symfony/yaml", function="parseBlock", grounded_in_fix=True))
            chain._resolver._last_resort = Mock(return_value=None)
            chain._placement = Mock(return_value=SimpleNamespace(
                direct=True, known=True, introductions=[],
                describe=lambda: "прямая зависимость проекта", upgrade_note=lambda: ""))
            chain._exploit.assess = Mock(return_value=Mock(problems=[], render=Mock(return_value="")))
            finding = Finding(
                finding_id="php-1", scanner="wolfee", rule_id="GHSA-c2p3-7m5p-cv8x", cwe="CWE-776",
                code_context=CodeContext(file_path="composer.lock"),
                dependency=DependencyInfo(package="symfony/yaml", ecosystem="composer", installed_version="7.3.0"))
            advisory = Advisory(advisory_id="GHSA-c2p3-7m5p-cv8x", package="symfony/yaml", ecosystem="Packagist",
                                summary="Yaml::parse on untrusted input", cwe_ids=["CWE-776"])
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=advisory), \
                    patch("appsec_triage.sca.chain.support.psalm_api.run", return_value=answer) as psalm:
                result = chain.run(finding)

        psalm.assert_called_once()
        self.assertEqual(psalm.call_args.kwargs["binary"], "/usr/bin/psalm")
        self.assertTrue(result.codeql_calls[0].startswith("модель (запрос к Psalm) → Psalm (типы и taint) пакета symfony/yaml"))
        self.assertEqual(result.route, "psalm")
        self.assertEqual(result.matched_symbol, label)
        self.assertIs(result.decision.verdict, CVEVerdict.ACTUAL)
        self.assertIn("трасса Psalm", result.summary().trace)


if __name__ == "__main__":
    unittest.main()
