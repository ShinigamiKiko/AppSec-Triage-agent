import unittest

from appsec_triage.config import HeuristicsConfig
from appsec_triage.context.heuristics import evaluate
from appsec_triage.models import CodeContext, Finding
from appsec_triage.prompts.registry import render_system


class TrainingContextAndHeuristicsTests(unittest.TestCase):
    def test_test_path_is_hard_false_positive(self):
        finding = Finding(
            finding_id="test-1",
            scanner="test",
            code_context=CodeContext(file_path="internal/test/handler.go", snippet="fmt.Println(value)"),
        )
        result = evaluate(finding, HeuristicsConfig())
        self.assertTrue(result.hard_fp)
        self.assertEqual(result.hard_fp_reason, "finding is inside a test-only path")

    def test_training_context_is_attached_to_system_prompt(self):
        system, _ = render_system(None)
        self.assertIn("Project-specific context", system)
        self.assertIn("Kubernetes API client functionality", system)


if __name__ == "__main__":
    unittest.main()
