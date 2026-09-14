import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, call, patch

from appsec_triage.config import HeuristicsConfig, PipelineConfig, ProviderConfig
from appsec_triage.context import builder
from appsec_triage.context.source import SourceResolver
from appsec_triage.deployment import load as load_deployment
from appsec_triage.llm.base import LLMClient, LLMError, LLMResponse
from appsec_triage.models import CodeContext, DependencyInfo, Finding, TraceStep, VerdictLabel
from appsec_triage.pipeline import TriagePipeline
from appsec_triage.validate.schema import VERDICT_SCHEMA, parse_verdict


class PipelineContextTests(unittest.TestCase):
    def test_deployment_context_is_in_every_system_prompt(self):
        context = load_deployment(Path("configs/deployment.yaml"))
        rendered = context.render()
        self.assertIn("Linux container", rendered)
        self.assertIn("Windows-only", rendered)
        self.assertIn("Incoming TLS and outgoing", rendered)
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pipeline-context-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "application"
        self.root.mkdir()
        self.write("src/Handler.php", "<?php\n$target = $_GET['target'];\nrunCommand($target);\n")
        self.write("config/packages/security.yaml", "security:\n  access_control: []\n")
        # Ordinary PHP, not an API resource or a traced location: only retrieval reveals it.
        self.write(
            "src/Command.php",
            "<?php\nfunction runCommand($target) {\n"
            "    $mode = 'cmd.raw[on]';\n    return shell_exec($target);\n}\n",
        )
        self.cfg = PipelineConfig(
            max_workers=1,
            heuristics=HeuristicsConfig(enabled=False, autoclose_on_hard_fp=False),
            code_context_lines=0,
            secrets_without_model=False,
            resolve_vulnerable_symbols=False,
        )
        self.cfg.lsp.enabled = False
        self.cfg.lsp.required_languages = []
        self.cfg.verification.enabled = False
        self.cfg.scope.enabled = False
        self.cfg.post_validation.enabled = False
        self.provider = ProviderConfig(
            name="mock", kind="ollama", model="mock-model", base_url="http://unused.invalid", concurrency=1,
        )
        self.client = Mock(spec=LLMClient)
        self.client.budget_left_usd = None
        self.client.calls = 0
        self.client.spend_usd = 0.0
        self.client.estimate_cost.side_effect = (
            lambda prompt, completion: None if prompt is None or completion is None
            else prompt * 0.001 + completion * 0.002
        )
        self.finding = Finding(
            finding_id="command-flow", scanner="codeql", cwe="CWE-78",
            code_context=CodeContext(
                file_path="src/Handler.php", start_line=3, language="php", snippet="runCommand($target);",
            ),
        )
        self.packages = []
        real_build = builder.build

        def capture_package(*args, **kwargs):
            pkg = real_build(*args, **kwargs)
            self.packages.append(pkg)
            return pkg

        for patcher in (
            patch("appsec_triage.pipeline.builder.build", side_effect=capture_package),
            patch("socket.socket.connect", side_effect=AssertionError("network access forbidden")),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def pipeline(self):
        return TriagePipeline(
            self.client, self.provider, self.cfg, source=SourceResolver([self.root]), history=None, symbols=None,
        )

    @staticmethod
    def verdict(*, resolved=False, reason=None, quotes=()):
        return json.dumps({
            "verdict": "confirmed" if resolved else "unknown",
            "evidence_class": "EXPLOITABLE_DATAFLOW" if resolved else "INSUFFICIENT_CONTEXT",
            "confidence": 0.9 if resolved else 0.4,
            "confidence_rationale": "Based on the supplied repository evidence.",
            "exploitability": "moderate", "impact": "high", "cwe": "CWE-78",
            "vulnerable_symbol": {
                "name": "runCommand", "kind": "sink", "location": "src/Handler.php:3",
                "why": "The helper receives the request value.",
            },
            "dataflow": [],
            "evidence": [{"quote": quote, "why": "Repository evidence."} for quote in quotes],
            "reason": reason or ("The helper executes the request value." if resolved else "Helper body needed."),
            "missing_information": [] if resolved else ["How does runCommand process the request value?"],
            "blocking_question": None,
            "requires_human_review": not resolved,
        })

    @staticmethod
    def response(text, n=1):
        return LLMResponse(
            text=text, model="mock-model", prompt_tokens=10 * n, completion_tokens=2 * n,
            latency_ms=7 * n, attempts=n,
        )

    @staticmethod
    def plan(pattern="cmd.raw[on]"):
        return json.dumps({"requests": [{"action": "search", "path": "", "line": 1, "pattern": pattern}]})

    def test_enriched_source_and_config_reach_prompt_and_quotable_package(self):
        self.cfg.context_retrieval_rounds = 0
        self.cfg.post_validation.enabled = True
        quotes = ("2 | $target = $_GET['target'];", "2 |   access_control: []")
        self.client.complete.return_value = self.response(self.verdict(quotes=quotes))

        record = self.pipeline().triage_one(self.finding)

        self.client.complete.assert_called_once()
        pkg = self.packages[0]
        prompt = self.client.complete.call_args.args[1]
        self.assertEqual(pkg.code_context, "runCommand($target);")
        self.assertFalse(pkg.in_noisy_zone)
        self.assertEqual(prompt, builder.render_for_prompt(pkg))
        self.assertEqual(prompt, pkg.quotable_text())
        for quote in quotes:
            self.assertIn(quote, prompt)
            self.assertNotIn(quote, pkg.code_context)
        self.assertIn("[static config]", prompt)
        self.assertIn("not effective runtime configuration", prompt)
        self.assertEqual([e.quote for e in record.verdict.evidence], list(quotes))
        self.assertTrue(all(e.grounded for e in record.verdict.evidence))
        self.assertFalse(any("evidence" in override for override in record.overrides), record.overrides)
        self.assertIsNone(record.error)

    def test_adaptive_literal_search_second_verdict_and_aggregate_metrics(self):
        self.write("src/Decoy.php", "<?php\n$mode = 'cmdXrawo';\n")
        final = self.verdict(resolved=True, quotes=("return shell_exec($target);",))
        self.client.complete.side_effect = [
            self.response(self.verdict(), 1), self.response(self.plan(), 2), self.response(final, 3),
        ]

        record = self.pipeline().triage_one(self.finding)

        self.assertEqual(self.client.complete.call_count, 3)
        initial, planner, second = self.client.complete.call_args_list
        self.assertEqual(initial.kwargs["json_schema"], VERDICT_SCHEMA)
        self.assertEqual(second.kwargs["json_schema"], VERDICT_SCHEMA)
        self.assertEqual(planner.kwargs["json_schema"]["required"], ["requests"])
        self.assertIn("literal", planner.args[0])
        self.assertIn("Unresolved questions:", planner.args[1])
        self.assertIn("How does runCommand process the request value?", planner.args[1])
        self.assertNotIn("shell_exec", initial.args[1])
        self.assertNotIn("shell_exec", planner.args[1])
        self.assertIn("4 |     return shell_exec($target);", second.args[1])
        self.assertNotIn("cmdXrawo", second.args[1])
        self.assertEqual(initial.args[0], second.args[0])
        self.assertEqual(second.args[1], self.packages[0].quotable_text())
        self.assertEqual(record.verdict, parse_verdict(final))
        self.assertEqual(record.decided_by, "llm")
        self.assertEqual(record.latency_ms, 42)
        self.assertEqual(record.prompt_tokens, 60)
        self.assertEqual(record.completion_tokens, 12)
        self.assertEqual(record.attempts, 6)
        self.assertAlmostEqual(record.cost_usd, 0.084)
        self.assertEqual(self.client.estimate_cost.call_args_list, [call(10, 2), call(20, 4), call(30, 6)])

    def test_no_new_evidence_stops_without_another_verdict(self):
        for plan in (self.plan("missing.literal"), self.plan("runCommand($target);"), '{"requests": []}'):
            with self.subTest(plan=plan):
                self.client.reset_mock()
                initial = self.verdict()
                self.client.complete.side_effect = [self.response(initial), self.response(plan, 2)]

                record = self.pipeline().triage_one(self.finding)

                self.assertEqual(self.client.complete.call_count, 2)
                self.assertEqual(record.verdict, parse_verdict(initial))
                self.assertEqual(record.latency_ms, 21)
                self.assertAlmostEqual(record.cost_usd, 0.042)
                self.assertIsNone(record.error)

    def test_zero_retrieval_rounds_never_calls_planner(self):
        self.cfg.context_retrieval_rounds = 0
        initial = self.verdict()
        self.client.complete.side_effect = [self.response(initial)]

        record = self.pipeline().triage_one(self.finding)

        self.client.complete.assert_called_once()
        self.assertEqual(self.client.complete.call_args.kwargs["json_schema"], VERDICT_SCHEMA)
        self.assertEqual(record.verdict, parse_verdict(initial))
        self.assertEqual(record.prompt_tokens, 10)

    def test_failed_replacement_cannot_ground_old_hallucination(self):
        self.cfg.post_validation.enabled = True
        first = self.verdict(resolved=True, quotes=("return shell_exec($target);",))
        data = json.loads(first)
        data["missing_information"] = ["Need the helper body"]
        self.client.complete.side_effect = [
            self.response(json.dumps(data)), self.response(self.plan()), LLMError("unavailable"),
        ]
        with self.assertLogs("appsec_triage.pipeline", level="WARNING"):
            record = self.pipeline().triage_one(self.finding)
        self.assertNotIn("return shell_exec", self.packages[0].quotable_text())
        self.assertEqual(record.verdict.verdict, VerdictLabel.unknown)
        self.assertTrue(any("hallucinated" in item for item in record.overrides))

    def test_collected_source_counts_when_scanner_has_no_snippet(self):
        self.cfg.context_retrieval_rounds = 0
        self.cfg.post_validation.enabled = True
        finding = self.finding.model_copy(deep=True)
        finding.code_context.snippet = None
        self.client.complete.return_value = self.response(self.verdict(
            resolved=True, quotes=("$target = $_GET['target'];",),
        ))
        record = self.pipeline().triage_one(finding)
        self.assertTrue(self.packages[0].repository_code_collected)
        self.assertEqual(self.packages[0].code_source, "description_only")
        self.assertFalse(any("without any code context" in item for item in record.overrides))

    def test_retrieval_failures_retain_last_valid_verdict(self):
        failures = {
            "malformed planner JSON": [self.response("not JSON", 2)],
            "planner non-object": [self.response("[]", 2)],
            "requests non-array": [self.response('{"requests": {}}', 2)],
            "planner provider failure": [LLMError("planner unavailable")],
            "malformed second verdict": [self.response(self.plan(), 2), self.response("not JSON", 3)],
            "invalid second verdict schema": [
                self.response(self.plan(), 2), self.response('{"verdict": "bogus"}', 3),
            ],
            "second verdict provider failure": [self.response(self.plan(), 2), LLMError("verdict unavailable")],
        }
        for name, replies in failures.items():
            with self.subTest(name=name):
                self.client.reset_mock()
                initial = self.verdict(reason="Keep this valid assessment.")
                first = self.response(initial)
                self.client.complete.side_effect = [first, *replies]

                with self.assertLogs("appsec_triage.pipeline", level="WARNING"):
                    record = self.pipeline().triage_one(self.finding)

                self.assertEqual(record.verdict, parse_verdict(initial))
                self.assertEqual(record.decided_by, "llm")
                self.assertIsNone(record.error)
                self.assertEqual(self.client.complete.call_count, 1 + len(replies))
                self.assertIn("retaining the last valid verdict", " ".join(self.packages[-1].context_notes))
                answered = [r for r in [first, *replies] if isinstance(r, LLMResponse)]
                self.assertEqual(record.latency_ms, sum(r.latency_ms for r in answered))
                self.assertEqual(record.prompt_tokens, sum(r.prompt_tokens for r in answered))
                self.assertEqual(record.completion_tokens, sum(r.completion_tokens for r in answered))
                self.assertEqual(record.attempts, sum(r.attempts for r in answered))
                self.assertAlmostEqual(record.cost_usd, sum(0.014 * r.attempts for r in answered))

    def test_later_planner_failure_retains_updated_verdict(self):
        updated = self.verdict(reason="Helper found; production exposure still needs checking.")
        self.client.complete.side_effect = [
            self.response(self.verdict()), self.response(self.plan(), 2), self.response(updated, 3),
            LLMError("second planner unavailable"),
        ]

        with self.assertLogs("appsec_triage.pipeline", level="WARNING"):
            record = self.pipeline().triage_one(self.finding)

        self.assertEqual(self.client.complete.call_count, 4)
        self.assertEqual(record.verdict, parse_verdict(updated))
        self.assertEqual(record.latency_ms, 42)
        self.assertAlmostEqual(record.cost_usd, 0.084)

    def test_unknown_token_usage_remains_unknown_in_aggregate(self):
        planner = self.response(self.plan(), 2)
        planner.prompt_tokens = None
        self.client.complete.side_effect = [
            self.response(self.verdict()), planner, self.response(self.verdict(resolved=True), 3),
        ]

        record = self.pipeline().triage_one(self.finding)

        self.assertIsNone(record.prompt_tokens)
        self.assertEqual(record.completion_tokens, 12)
        self.assertEqual(record.latency_ms, 42)
        self.assertIsNone(record.cost_usd)

    def test_run_forwards_supported_scanner_findings_with_traces(self):
        self.cfg.context_retrieval_rounds = 0
        self.cfg.resolve_vulnerable_symbols = True
        traced = []
        excluded = []
        for scanner in ("CodeQL", "psalm", "unsupported"):
            finding = self.finding.model_copy(update={
                "finding_id": scanner, "scanner": scanner,
                "trace": [TraceStep(file_path="src/Handler.php", line=2, role="source")],
            })
            (excluded if scanner == "unsupported" else traced).append(finding)
            excluded.append(finding.model_copy(update={"finding_id": scanner + "-no-trace", "trace": []}))
        dependency = self.finding.model_copy(update={
            "finding_id": "dependency", "scanner": "sca",
            "dependency": DependencyInfo(package="acme/command", ecosystem="composer", installed_version="1.0"),
        })
        chain_result = SimpleNamespace(
            closes=False, summary=Mock(return_value=None), render=Mock(return_value="Dependency analysis marker"),
        )
        self.client.complete.return_value = self.response(self.verdict())
        with patch("appsec_triage.sca.chain.DependencyChain", autospec=True) as chain_type:
            chain_type.return_value.run.return_value = chain_result
            pipeline = self.pipeline()
            run = pipeline.run([*traced, *excluded, dependency])

        chain_type.assert_called_once()
        chain_type.return_value.run.assert_called_once_with(dependency, codeql_findings=traced)
        self.assertEqual(len(run.records), 7)
        self.assertTrue(all(record.error is None for record in run.records))
        self.assertTrue(all(record.decided_by == "llm" for record in run.records))
        self.assertEqual(self.client.complete.call_count, 7)
        pkg = next(pkg for pkg in self.packages if pkg.finding_id == "dependency")
        prompt = self.client.complete.call_args_list[-1].args[1]
        self.assertIn("Dependency analysis marker", prompt)
        self.assertIn("access_control: []", prompt)
        self.assertEqual(prompt, pkg.quotable_text())
        self.assertEqual(run.records[-1].kind, "dependency")
        self.assertIs(run.records[-1].verdict.verdict, VerdictLabel.unknown)


if __name__ == "__main__":
    unittest.main()
