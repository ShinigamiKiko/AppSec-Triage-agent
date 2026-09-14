import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from appsec_triage import testpaths
from appsec_triage.sca import codeql_api
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.codeql_api import ImportAnswer
from appsec_triage.sca.presence import Hit, package_usage
from appsec_triage.sca.verdict import CVEVerdict, decide

SECTION = """# Project Context

## Stack

- `ignored/` — not in the test section

## Test And Non-Production Paths

Prose the model reads.

- `test/`
- `__tests__/`
- `*_test.go`
- `*.test.*`

## Triage Rules

- `rules/` is not a test path either
"""


class ParseTests(unittest.TestCase):
    def setUp(self):
        self.paths = testpaths.parse(SECTION)

    def test_only_the_named_section_is_read(self):
        self.assertEqual(self.paths.directories, ("test", "__tests__"))
        self.assertEqual(self.paths.files, ("*_test.go", "*.test.*"))

    def test_directories_match_whole_segments(self):
        self.assertTrue(self.paths.is_test("test/greeting.js"))
        self.assertTrue(self.paths.is_test("pkg/__tests__/a.js"))
        self.assertTrue(self.paths.is_test("src\\Test\\a.js"))
        self.assertFalse(self.paths.is_test("src/latest/a.js"))
        self.assertFalse(self.paths.is_test("src/contest.js"))
        self.assertFalse(self.paths.is_test("test"))

    def test_file_globs_match_the_base_name(self):
        self.assertTrue(self.paths.is_test("internal/api/handler_test.go"))
        self.assertTrue(self.paths.is_test("src/render.test.js"))
        self.assertFalse(self.paths.is_test("src/render.js"))

    def test_the_repository_file_lists_what_the_code_used_to(self):
        paths = testpaths.load()
        for path in ("test/a.js", "tests/a.py", "spec/a.rb", "__tests__/a.js", "testdata/x.json",
                     "handler_test.go", "test_models.py", "render.test.js", "render.spec.ts"):
            with self.subTest(path=path):
                self.assertTrue(paths.is_test(path))
        self.assertFalse(paths.is_test("src/server.js"))


class TextUsageTests(unittest.TestCase):
    def _usage(self, files):
        with tempfile.TemporaryDirectory() as root:
            for name, text in files.items():
                Path(root, name).parent.mkdir(parents=True, exist_ok=True)
                Path(root, name).write_text(text, encoding="utf-8")
            return package_usage(root, "npm", "lodash")

    def test_production_use_counts(self):
        used, _, test_only = self._usage({"src/a.js": "const _ = require('lodash');\n",
                                          "test/a.test.js": "require('lodash')\n"})
        self.assertTrue(used)
        self.assertFalse(test_only)

    def test_use_only_in_tests_is_reported_as_such(self):
        used, detail, test_only = self._usage({"src/a.js": "module.exports = 1;\n",
                                               "test/a.test.js": "const _ = require('lodash');\n"})
        self.assertIs(used, False)
        self.assertTrue(test_only)
        self.assertIn("test/a.test.js", detail)

    def test_no_use_anywhere(self):
        used, _, test_only = self._usage({"src/a.js": "module.exports = 1;\n"})
        self.assertIs(used, False)
        self.assertFalse(test_only)


class DecideTests(unittest.TestCase):
    def test_direct_dependency_imported_only_in_tests_closes(self):
        decision = decide(None, None, None, used=False, used_detail="test/a.test.js:1", test_only=True, direct=True)
        self.assertIs(decision.verdict, CVEVerdict.ONLY_TEST_IMPORT)
        self.assertTrue(decision.closes)

    def test_test_only_import_outranks_codeql_no_path(self):
        decision = decide(None, None, None, dataflow=False, input_driven=True,
                          used=False, test_only=True, direct=True)
        self.assertIs(decision.verdict, CVEVerdict.ONLY_TEST_IMPORT)

    def test_a_codeql_path_still_outranks_test_only(self):
        reached = SimpleNamespace(render=lambda: "path", source_file="test/a.js", source_line=1,
                                  file="test/a.js", line=2)
        decision = decide(None, None, None, dataflow=reached, used=False, test_only=True, direct=True)
        self.assertIs(decision.verdict, CVEVerdict.ACTUAL)

    def test_transitive_dependency_stays_open(self):
        decision = decide(None, None, None, used=False, test_only=True, direct=False)
        self.assertIs(decision.verdict, CVEVerdict.NO_DIRECT_CALL)
        self.assertFalse(decision.closes)


class ImportsQueryTests(unittest.TestCase):
    def test_package_and_subpaths_but_not_lookalikes(self):
        text = codeql_api.imports_query("lodash")
        self.assertIn('path = "lodash"', text)
        self.assertIn('path.prefix(7) = "lodash/"', text)

    def test_hits_are_split_with_the_shared_list(self):
        answer = ImportAnswer(sites=[Hit("src/a.js", 1, "", in_tests=False), Hit("test/b.js", 2, "", in_tests=True)])
        self.assertEqual([h.file for h in answer.production], ["src/a.js"])
        self.assertEqual([h.file for h in answer.tests], ["test/b.js"])


class ChainUsageTests(unittest.TestCase):
    def _usage(self, files, answer):
        with tempfile.TemporaryDirectory() as root:
            for name, text in files.items():
                Path(root, name).parent.mkdir(parents=True, exist_ok=True)
                Path(root, name).write_text(text, encoding="utf-8")
            chain = DependencyChain(None, [root], codeql_databases={"javascript": root})
            record: list[str] = []
            with patch("appsec_triage.sca.chain.support.codeql_api.run_imports", return_value=answer):
                result = chain._package_usage(SimpleNamespace(ecosystem="npm"), "lodash", record=record)
        return result, record

    def test_codeql_test_only_imports_close_as_test_only(self):
        answer = ImportAnswer(sites=[Hit("test/a.test.js", 1, "require('lodash')", in_tests=True)])
        (used, detail, test_only), record = self._usage(
            {"src/a.js": "module.exports = 1;\n", "test/a.test.js": "require('lodash')\n"}, answer)
        self.assertIs(used, False)
        self.assertTrue(test_only)
        self.assertIn("только в тестовом коде", detail)
        self.assertTrue(record[0].startswith("цепочка → CodeQL импорты пакета lodash"))

    def test_text_use_in_production_keeps_it_used_when_codeql_sees_no_import(self):
        (used, _, test_only), _ = self._usage(
            {"src/a.js": "const name = 'lodash'; const _ = require(name);\n"}, ImportAnswer())
        self.assertTrue(used)
        self.assertFalse(test_only)

    def test_codeql_production_import_wins(self):
        answer = ImportAnswer(sites=[Hit("src/a.js", 1, "require('lodash')", in_tests=False)])
        (used, detail, _), _ = self._usage({"src/a.js": "require('lodash')\n"}, answer)
        self.assertTrue(used)
        self.assertIn("рабочем коде", detail)


if __name__ == "__main__":
    unittest.main()
