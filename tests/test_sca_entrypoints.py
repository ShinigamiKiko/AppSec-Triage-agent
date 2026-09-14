import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.resolve import VulnerableSymbol

_HANDLER = "const yaml = require('js-yaml');\napp.post('/import', (req, res) => res.json(yaml.load(req.body)));\n"


class PublicEntryPointSearchTests(unittest.TestCase):
    """A private helper named by the fix is searched through the API above it."""

    @staticmethod
    def _entry(*names):
        return VulnerableSymbol("GHSA-x", package="js-yaml", function=names[0],
                                candidates=tuple((n, "") for n in names), named_by_model=True)

    def _run(self, source, *, symbol="storeMappingPair", entry=None, direct=True):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "server.js").write_text(source, encoding="utf-8")
            chain = DependencyChain(None, [root])
            chain._resolver.resolve = Mock(return_value=VulnerableSymbol(
                "GHSA-x", package="js-yaml", function=symbol, grounded_in_fix=True))
            chain._resolver._last_resort = Mock(return_value=entry)
            chain._placement = Mock(return_value=SimpleNamespace(direct=direct, known=True, introductions=[]))
            chain._exploit.assess = Mock(return_value=Mock(problems=[]))
            finding = Finding(
                finding_id="f-1", scanner="wolfee", rule_id="GHSA-x",
                code_context=CodeContext(file_path="package.json"),
                dependency=DependencyInfo(package="js-yaml", ecosystem="npm", installed_version="3.13.0"))
            advisory = Advisory(advisory_id="GHSA-x", package="js-yaml", ecosystem="npm", cwe_ids=["CWE-94"])
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=advisory):
                return chain.run(finding), chain._resolver._last_resort

    def test_helper_miss_on_direct_dependency_finds_the_public_call(self):
        result, asked = self._run(_HANDLER, entry=self._entry("load", "loadAll"))
        asked.assert_called_once()
        self.assertEqual(result.matched_symbol, "load")
        self.assertTrue(result.presence.found)
        self.assertIn("load (публичный вход, назван моделью)", result.searched_for)

    def test_symbol_found_directly_does_not_ask(self):
        result, asked = self._run(_HANDLER, symbol="load", entry=self._entry("load"))
        asked.assert_not_called()
        self.assertEqual(result.matched_symbol, "load")

    def test_transitive_dependency_does_not_ask(self):
        _, asked = self._run(_HANDLER, entry=self._entry("load"), direct=False)
        asked.assert_not_called()

    def test_entry_point_miss_closes_nothing(self):
        source = "const yaml = require('js-yaml');\nmodule.exports = yaml;\n"
        result, asked = self._run(source, entry=self._entry("loadAll"))
        asked.assert_called_once()
        self.assertEqual(result.matched_symbol, "")
        self.assertFalse(result.closes)


if __name__ == "__main__":
    unittest.main()
