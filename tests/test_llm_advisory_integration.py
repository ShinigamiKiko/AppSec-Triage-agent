import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from appsec_triage.llm.base import LLMError
from appsec_triage.models import CodeContext, DependencyInfo, Finding, TraceStep
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.codeql_reach import Reached
from appsec_triage.sca.llm_advisory import lookup
from appsec_triage.sca.resolve import VulnerableSymbol


class LLMAdvisoryIntegrationTests(unittest.TestCase):
    """Verify when the last-resort advisory lookup is invoked by the chain."""

    def _finding(self, reachability="reachable", call_site="main.go:42"):
        return Finding(
            finding_id="test-1",
            scanner="wolfee",
            rule_id="CVE-2099-0001",
            code_context=CodeContext(file_path="main.go", start_line=42),
            dependency=DependencyInfo(
                package="example/pkg", ecosystem="go", installed_version="v1.0.0",
                reachability=reachability, call_site=call_site,
            ),
        )

    @staticmethod
    def _bare_advisory():
        return Advisory(advisory_id="CVE-2099-0001", package="example/pkg")

    def _run(self, client, finding=None):
        chain = DependencyChain(client, [])
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        chain._exploit.assess = Mock(return_value=Mock(problems=[]))
        with patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()):
            return chain.run(finding or self._finding())

    def test_reachable_trace_enriches_bare_advisory(self):
        client = Mock()
        context = (
            "[LLM-provided advisory context; verify against external sources]\n"
            "Summary: parser accepts malformed input\n"
            "Vulnerable symbols: Parse\n"
            "Attack conditions: attacker controls input\n"
            "Impact: denial of service"
        )
        with patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value=context) as lookup_mock:
            result = self._run(client)

        passed_context = lookup_mock.call_args.kwargs["dataflow_context"]
        self.assertIn("Wolfee reachability", passed_context)
        self.assertIn("main.go:42", passed_context)
        self.assertIsNotNone(result)

    def test_scanner_trace_is_forwarded_to_fallback(self):
        client = Mock()
        finding = self._finding()
        finding.trace = [
            TraceStep(file_path="cmd/server.go", line=12, message="handle(req)"),
            TraceStep(file_path="main.go", line=42, message="vulnerable(req)"),
        ]
        with patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value="") as lookup_mock:
            self._run(client, finding)
        passed_context = lookup_mock.call_args.kwargs["dataflow_context"]
        self.assertIn("Wolfee/govulncheck call trace", passed_context)
        self.assertIn("cmd/server.go:12 — handle(req)", passed_context)
        self.assertIn("main.go:42 — vulnerable(req)", passed_context)

    def test_fallback_verdict_keeps_innermost_trace_order(self):
        finding = self._finding(call_site=None)
        finding.trace = [
            TraceStep(file_path=f"frame-{i}.go", line=i, message=f"frame_{i}")
            for i in range(1, 8)
        ]
        result = self._run(Mock(), finding)

        self.assertIsNotNone(result.reachability)
        self.assertEqual(result.reachability.trace[0], "frame_7")
        self.assertEqual(result.reachability.trace[-1], "frame_1")
        self.assertEqual(result.reachability.sites[0], ("frame-1.go", 1))
        self.assertIn("frame_7", result.reachability.render())

    def test_codeql_context_is_forwarded_to_fallback(self):
        client = Mock()
        context = "[LLM-provided advisory context; verify against external sources]"
        chain = DependencyChain(client, [Path("/tmp")], codeql_databases={"go": "/tmp/codeql"})
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        chain._exploit.assess = Mock(return_value=Mock(problems=[]))
        reached = Reached("main.go", 42, "request.go", 10)
        with patch.object(chain, "_dataflow_for", return_value=reached), \
             patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value=context) as lookup_mock:
            chain.run(self._finding())
        passed_context = lookup_mock.call_args.kwargs["dataflow_context"]
        self.assertIsInstance(passed_context, str)
        self.assertIn("request.go:10", passed_context)
        self.assertIn("main.go:42", passed_context)

    def test_codeql_context_is_forwarded_to_exploitability_model(self):
        client = Mock()
        chain = DependencyChain(client, [Path("/tmp")], codeql_databases={"go": "/tmp/codeql"})
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        exploit_assess = Mock(return_value=Mock(problems=[]))
        reached = Reached("main.go", 42, "request.go", 10)
        with patch.object(chain, "_dataflow_for", return_value=reached), \
             patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value=""), \
             patch("appsec_triage.sca.chain.exploitable_mod.assess", exploit_assess):
            chain.run(self._finding())
        passed_context = exploit_assess.call_args.kwargs["dataflow_context"]
        self.assertIn("request.go:10", passed_context)
        self.assertIn("main.go:42", passed_context)

    def test_exploitability_model_can_request_codeql_trace(self):
        client = Mock()
        chain = DependencyChain(client, [Path("/tmp")], codeql_databases={"go": "/tmp/codeql"})
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        exploit_assess = Mock(return_value=Mock(problems=[]))
        reached = Reached("main.go", 42, "request.go", 10)
        with patch.object(chain, "_dataflow_for", return_value=reached) as query, \
             patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value=""), \
             patch("appsec_triage.sca.chain.exploitable_mod.assess", exploit_assess):
            chain.run(self._finding())
            callback = exploit_assess.call_args.kwargs["dataflow_query"]
            self.assertIn("request.go:10", callback([("main.go", 42)]))
            self.assertEqual(query.call_count, 2)

    def test_codeql_error_is_not_sent_as_evidence(self):
        client = Mock()
        chain = DependencyChain(client, [], codeql_databases={"go": "/tmp/codeql"})
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        chain._exploit.assess = Mock(return_value=Mock(problems=[]))
        with patch.object(chain, "_dataflow_for", return_value="CodeQL query failed"), \
             patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value="") as lookup_mock:
            chain.run(self._finding())
        self.assertIn("Wolfee reachability", lookup_mock.call_args.kwargs["dataflow_context"])
        self.assertNotIn("CodeQL query failed", lookup_mock.call_args.kwargs["dataflow_context"])

    def test_codeql_unreachable_result_is_not_rendered(self):
        client = Mock()
        chain = DependencyChain(client, [], codeql_databases={"go": "/tmp/codeql"})
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        chain._exploit.assess = Mock(return_value=Mock(problems=[]))
        with patch.object(chain, "_dataflow_for", return_value=False), \
             patch("appsec_triage.sca.chain.adv.collect", return_value=self._bare_advisory()), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup", return_value="") as lookup_mock:
            chain.run(self._finding())
        self.assertIn("Wolfee reachability", lookup_mock.call_args.kwargs["dataflow_context"])

    def test_fallback_skipped_when_advisory_has_details(self):
        client = Mock()
        advisory = Advisory(
            advisory_id="CVE-2099-0001", package="example/pkg",
            details="The parser mishandles attacker-controlled input.",
        )
        chain = DependencyChain(client, [])
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        with patch("appsec_triage.sca.chain.adv.collect", return_value=advisory), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup") as lookup_mock:
            chain.run(self._finding())
        lookup_mock.assert_not_called()

    def test_fallback_skipped_when_symbols_are_present(self):
        client = Mock()
        advisory = Advisory(
            advisory_id="CVE-2099-0001", package="example/pkg", symbols=["Parse"]
        )
        chain = DependencyChain(client, [])
        chain._resolver.resolve = Mock(return_value=VulnerableSymbol("CVE-2099-0001"))
        with patch("appsec_triage.sca.chain.adv.collect", return_value=advisory), \
             patch("appsec_triage.sca.chain.llm_advisory.lookup") as lookup_mock:
            chain.run(self._finding())
        lookup_mock.assert_not_called()

    def test_fallback_skipped_without_reachable_trace(self):
        client = Mock()
        with patch("appsec_triage.sca.chain.llm_advisory.lookup") as lookup_mock:
            result = self._run(client, self._finding("unreachable", None))
        lookup_mock.assert_not_called()
        self.assertIsNotNone(result)

    def test_fallback_failure_does_not_break_pipeline(self):
        client = Mock()
        client.complete.side_effect = LLMError("timeout")
        result = self._run(client)
        self.assertIsNotNone(result)
        self.assertTrue(any("LLM fallback" in problem for problem in result.problems))

    def test_invalid_or_empty_llm_payload_is_ignored(self):
        client = Mock()
        for payload in ("not json", ""):
            with self.subTest(payload=payload), patch(
                "appsec_triage.sca.llm_advisory._cache_path",
                return_value=Path("/definitely/missing/cache.json"),
            ):
                client.complete.return_value = type("Response", (), {"text": payload})()
                self.assertEqual(lookup(client, "CVE-2099-0001", "pkg", "1.0"), "")


if __name__ == "__main__":
    unittest.main()
