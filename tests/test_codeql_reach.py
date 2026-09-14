import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from appsec_triage.sca.codeql_reach import _DIALECTS, Answer, Reached
from appsec_triage.sca.unreached import Audit, audit_closure
from appsec_triage.sca.verdict import CVEVerdict, decide


class CodeQLReachTests(unittest.TestCase):
    def test_negative_answer_requires_an_evaluated_site(self):
        answer = Answer(asked={("stdlib.go", 10)}, evaluated=set())
        self.assertIsNone(answer.verdict([("stdlib.go", 10)]))

        answer.evaluated.add(("stdlib.go", 10))
        self.assertFalse(answer.verdict([("stdlib.go", 10)]))

    def test_reached_answer_wins_over_negative_sites(self):
        reached = Reached("handler.go", 20, "request.go", 5)
        answer = Answer(
            asked={("handler.go", 20), ("other.go", 30)},
            evaluated={("handler.go", 20), ("other.go", 30)},
            reached={reached.site: reached},
        )
        self.assertIs(answer.verdict([("other.go", 30), ("handler.go", 20)]), reached)

    def test_positive_dataflow_reaches_verdict_with_graph_reachability(self):
        reachability = SimpleNamespace(
            reachable=True,
            render=lambda: "Wolfee path",
            trace=["handler.go:20"],
        )
        decision = decide(
            None, None, None,
            reachability=reachability,
            dataflow=Reached("handler.go", 20, "request.go", 5),
        )
        self.assertIs(decision.verdict, CVEVerdict.ACTUAL)
        self.assertIn("CodeQL", decision.reasons[0])

    def test_call_site_evidence_still_closes_with_negative_dataflow(self):
        reachability = SimpleNamespace(
            reachable=True,
            render=lambda: "Wolfee path",
            trace=["handler.go:20"],
        )
        call_site = SimpleNamespace(lowers=True, render=lambda: "call-site caveat")
        decision = decide(
            None, None, None,
            reachability=reachability,
            call_site=call_site,
            dataflow=False,
            input_driven=True,
        )
        self.assertIs(decision.verdict, CVEVerdict.CONDITION_ABSENT)


class JavaScriptArgumentShapeTests(unittest.TestCase):
    """Options objects are where JS libraries take their dangerous input."""

    def test_object_and_array_literal_values_are_sinks(self):
        helpers = _DIALECTS["javascript"]["helpers"]
        self.assertIn("(ObjectExpr).getAProperty().getInit()", helpers)
        self.assertIn("(ArrayExpr).getAnElement()", helpers)
        self.assertIn("argumentPart(c.getAnArgument())", _DIALECTS["javascript"]["argument"])

    def test_not_every_subexpression_is_a_sink(self):
        # A blanket child-expression match would let f(sanitize(req.body)) hit req.body.
        self.assertNotIn("getAChildExpr", _DIALECTS["javascript"]["helpers"])

    def test_go_is_unchanged_until_checked_on_a_real_database(self):
        self.assertEqual(_DIALECTS["go"]["argument"], "n.asExpr() = c.getAnArgument()")


class ChainCodeQLBinaryTests(unittest.TestCase):
    """The chain queries with the configured CLI, not whatever `codeql` PATH has."""

    def test_configured_binary_reaches_the_query(self):
        from appsec_triage.sca.chain import DependencyChain

        with tempfile.TemporaryDirectory() as root:
            Path(root, "server.js").write_text("yaml.load(req.body)\n", encoding="utf-8")
            chain = DependencyChain(None, [root], codeql_databases={"javascript": root},
                                    codeql_binary="/opt/tools/codeql/codeql")
            answer = Answer(asked={("server.js", 1)}, evaluated={("server.js", 1)})
            with patch("appsec_triage.sca.chain.support.codeql_reach.run", return_value=answer) as run:
                verdict = chain._dataflow_for(None, SimpleNamespace(ecosystem="npm"), [("server.js", 1)])
        self.assertIs(verdict, False)
        self.assertEqual(run.call_args.kwargs["binary"], "/opt/tools/codeql/codeql")

    def test_every_question_is_recorded_with_who_asked(self):
        from appsec_triage.sca.chain import DependencyChain

        with tempfile.TemporaryDirectory() as root:
            Path(root, "server.js").write_text("yaml.load(req.body)\n", encoding="utf-8")
            chain = DependencyChain(None, [root], codeql_databases={"javascript": root})
            answer = Answer(asked={("server.js", 1)}, evaluated={("server.js", 1)})
            record: list[str] = []
            with patch("appsec_triage.sca.chain.support.codeql_reach.run", return_value=answer) as run:
                chain._dataflow_for(None, SimpleNamespace(ecosystem="npm"), [("server.js", 1)],
                                    record=record, asked_by="модель (шаг эксплуатируемости)")
                chain._dataflow_for(None, SimpleNamespace(ecosystem="npm"), [("server.js", 1)],
                                    record=record, asked_by="модель (шаг эксплуатируемости)")
        run.assert_called_once()
        self.assertEqual(len(record), 2)
        self.assertTrue(record[0].startswith("модель (шаг эксплуатируемости) → CodeQL, позиции server.js:1"))
        self.assertIn("путь от пользовательского ввода не найден", record[0])
        self.assertNotIn("кэша", record[0])
        self.assertIn("(ответ из кэша прогона)", record[1])


class AnalyserCacheConcurrencyTests(unittest.TestCase):
    """Different questions run in parallel; the same question runs once."""

    def test_different_keys_do_not_wait_for_each_other(self):
        import threading
        from appsec_triage.sca.chain import DependencyChain

        chain, cache, results = DependencyChain(None, []), {}, {}
        both_running = threading.Barrier(2, timeout=5)

        def ask(tag):
            def compute():
                both_running.wait()  # only passes if the other computation runs at the same time
                return tag
            results[tag] = chain._once(cache, ("k", tag), compute)

        threads = [threading.Thread(target=ask, args=(tag,)) for tag in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(results, {"a": ("a", False), "b": ("b", False)})

    def test_same_key_is_computed_once(self):
        import threading
        import time
        from appsec_triage.sca.chain import DependencyChain

        chain, cache, calls, results = DependencyChain(None, []), {}, [], []

        def compute():
            calls.append(1)
            time.sleep(0.2)
            return "answer"

        threads = [threading.Thread(target=lambda: results.append(chain._once(cache, "same", compute)))
                   for _ in range(3)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(10)
        self.assertEqual(len(calls), 1)
        self.assertEqual(sorted(results), [("answer", False), ("answer", True), ("answer", True)])


class NegativeDataflowClosureTests(unittest.TestCase):
    """A CodeQL "no path" closes an input-driven CVE only after its audit ran.

    The closure skips the model entirely, and "no path from the sources CodeQL
    models" misses queues, CLI arguments and unmodelled frameworks.
    """

    def _decide(self, closure_audit=None):
        return decide(None, None, None, dataflow=False, input_driven=True,
                      closure_audit=closure_audit)

    def test_unaudited_negative_does_not_close(self):
        decision = self._decide()
        self.assertIs(decision.verdict, CVEVerdict.PRESENT_UNPROVEN)
        self.assertFalse(decision.closes)

    def test_audit_that_did_not_run_does_not_close(self):
        decision = self._decide(Audit(detail="модель не подключена — закрытие не проверено"))
        self.assertIs(decision.verdict, CVEVerdict.PRESENT_UNPROVEN)
        self.assertIn("модель не подключена", " ".join(decision.reasons))

    def test_audit_of_another_closure_does_not_count(self):
        decision = self._decide(Audit(kind="unused", checked=True))
        self.assertIs(decision.verdict, CVEVerdict.PRESENT_UNPROVEN)

    def test_audited_negative_closes(self):
        decision = self._decide(Audit(kind="no_input_path", checked=True))
        self.assertIs(decision.verdict, CVEVerdict.CONDITION_ABSENT)
        self.assertTrue(decision.closes)

    def test_reopening_audit_keeps_it_open(self):
        decision = self._decide(Audit(invisible_path=True, quote="consumer.on('message', h)",
                                      kind="no_input_path", checked=True))
        self.assertIs(decision.verdict, CVEVerdict.PRESENT_UNPROVEN)

    def test_negative_without_input_requirement_is_not_this_closure(self):
        decision = decide(None, None, None, dataflow=False, input_driven=None)
        self.assertIsNot(decision.verdict, CVEVerdict.CONDITION_ABSENT)


class ClosureAuditRanTests(unittest.TestCase):
    advisory = SimpleNamespace(advisory_id="GHSA-test", summary="s", details="d", package="js-yaml")
    symbol = SimpleNamespace(function="load")

    @staticmethod
    def _client(*answers):
        replies = iter(answers)
        return SimpleNamespace(
            complete=lambda *a, **k: SimpleNamespace(text=json.dumps(next(replies))))

    def test_no_client_is_not_checked(self):
        result = audit_closure("no_input_path", "claim", ".", self.advisory, self.symbol, None)
        self.assertFalse(result.checked)

    def test_empty_search_is_checked(self):
        client = self._client({"patterns": [], "why": "nothing"})
        result = audit_closure("no_input_path", "claim", ".", self.advisory, self.symbol, client)
        self.assertTrue(result.checked)
        self.assertEqual(result.kind, "no_input_path")

    def test_completed_audit_is_checked(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "worker.js").write_text("queue.consume(msg => yaml.load(msg))\n", encoding="utf-8")
            client = self._client({"patterns": ["consume"], "why": "queues"},
                                  {"closure_wrong": False, "quote": "", "why": "no"})
            result = audit_closure("no_input_path", "claim", root, self.advisory, self.symbol, client)
        self.assertTrue(result.checked)
        self.assertFalse(result.reopens)


if __name__ == "__main__":
    unittest.main()
