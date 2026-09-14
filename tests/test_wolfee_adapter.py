import json
import tempfile
import unittest
from pathlib import Path

from appsec_triage.ingest.sarif import parse
from appsec_triage.sca.chain import _call_site_position


class WolfeeAdapterTests(unittest.TestCase):
    def test_sarif_reachability_becomes_dependency_metadata(self):
        document = {
            "runs": [{
                "tool": {"driver": {"name": "wolfee", "rules": [{
                    "id": "GO-2026-0001",
                    "shortDescription": {"text": "test vulnerability"},
                }]}},
                "results": [{
                    "ruleId": "GO-2026-0001",
                    "level": "error",
                    "message": {"text": "GO-2026-0001 in go/example.org/vulnerable@v1.0.0 - fixed=v1.1.0"},
                    "locations": [{"logicalLocations": [{
                        "name": "go/example.org/vulnerable@v1.0.0", "kind": "package",
                    }]}],
                     "properties": {
                        "reachability": "reachable",
                        "callSite": "internal/handler.go:42",
                         "callLine": "dangerous(input)",
                     },
                     "codeFlows": [{"threadFlows": [{"locations": [
                         {"location": {"physicalLocation": {"artifactLocation": {"uri": "cmd/main.go"}, "region": {"startLine": 18}}}, "kinds": ["entrypoint"]},
                         {"location": {"physicalLocation": {"artifactLocation": {"uri": "internal/handler.go"}, "region": {"startLine": 42}}}, "kinds": ["vulnerable-function"]},
                     ]}]}],
                 }],
            }],
        }
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "wolfee.sarif.json"
            path.write_text(json.dumps(document), encoding="utf-8")
            finding = next(parse(path))

        self.assertIsNotNone(finding.dependency)
        self.assertEqual(finding.dependency.reachability, "reachable")
        self.assertEqual(finding.dependency.call_site, "internal/handler.go:42")
        self.assertEqual(finding.dependency.call_line, "dangerous(input)")
        self.assertEqual(len(finding.trace), 2)
        self.assertEqual(finding.trace[0].role, "source")
        self.assertEqual(finding.trace[-1].role, "sink")

    def test_call_site_position_handles_windows_drive_letters(self):
        self.assertEqual(_call_site_position("C:/repo/handler.go:42"), ("C:/repo/handler.go", 42))
        self.assertIsNone(_call_site_position("handler.go:not-a-line"))


if __name__ == "__main__":
    unittest.main()
