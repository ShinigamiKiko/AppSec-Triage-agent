import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock

from appsec_triage.llm.base import LLMResponse
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import _needs_llm_advisory
from appsec_triage.sca.llm_advisory import lookup


class LLMAdvisoryTests(unittest.TestCase):
    def test_lookup_returns_structured_untrusted_context_and_caches(self):
        client = Mock()
        client.complete.return_value = LLMResponse(
            text=json.dumps({
                "summary": "A parser accepts attacker-controlled input.",
                "vulnerable_symbols": ["Parse"],
                "attack_conditions": ["attacker controls request body"],
                "impact": "denial of service",
            }), model="deepseek-chat",
        )
        with tempfile.TemporaryDirectory() as directory:
            context = lookup(client, "CVE-2099-0001", "example/pkg", "1.0.0", cache_dir=Path(directory))
            cached = lookup(Mock(), "CVE-2099-0001", "example/pkg", "1.0.0", cache_dir=Path(directory))

        self.assertEqual(context, cached)
        self.assertIn("[LLM-provided advisory context", context)
        self.assertEqual(client.complete.call_count, 1)

    def test_fallback_requires_missing_context_and_trace_is_checked_by_caller(self):
        self.assertTrue(_needs_llm_advisory(Advisory(advisory_id="CVE-1", summary="CVE-1")))
        self.assertFalse(_needs_llm_advisory(Advisory(advisory_id="CVE-1", details="full details")))
        self.assertFalse(_needs_llm_advisory(Advisory(advisory_id="CVE-1", symbols=["Parse"])))


if __name__ == "__main__":
    unittest.main()
