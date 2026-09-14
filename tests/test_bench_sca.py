import io
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest.mock import patch

from appsec_triage.config import load_pipeline_config
from appsec_triage.evals.metrics import score
from appsec_triage.evals.runner import BenchSetupError, run_bench
from appsec_triage.ingest import native
from appsec_triage.models import EvidenceClass, SCASummary, TriageRecord, Verdict, VerdictLabel
from appsec_triage.sca import cassette


class _Response(io.BytesIO):
    def __init__(self, body: bytes, url: str) -> None:
        super().__init__(body)
        self._url = url

    def geturl(self) -> str:
        return self._url


class _Opener:
    def __init__(self, body=b"", error=None):
        self.body, self.error, self.calls = body, error, 0

    def open(self, request, timeout):
        self.calls += 1
        if self.error is not None:
            raise self.error
        return _Response(self.body, request.full_url + "#final")


class CassetteTests(unittest.TestCase):
    url = "https://api.osv.dev/v1/query"

    def _request(self, body=b'{"package": "js-yaml"}'):
        return urllib.request.Request(self.url, data=body)

    def test_off_without_directory_goes_live(self):
        opener = _Opener(b"live")
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(cassette.DIR_ENV, None)
            with cassette.urlopen(self._request(), timeout=1, opener=opener) as response:
                self.assertEqual(response.read(), b"live")
        self.assertEqual(opener.calls, 1)

    def test_record_then_replay_without_network(self):
        with tempfile.TemporaryDirectory() as tape:
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "record"}):
                cassette.urlopen(self._request(), timeout=1, opener=_Opener(b'{"vulns": []}'))
            dead = _Opener(error=urllib.error.URLError("network down"))
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "replay"}):
                with cassette.urlopen(self._request(), timeout=1, opener=dead) as response:
                    self.assertEqual(json.load(response), {"vulns": []})
                    self.assertEqual(response.geturl(), self.url + "#final")
            self.assertEqual(dead.calls, 0)

    def test_request_body_is_part_of_the_key(self):
        with tempfile.TemporaryDirectory() as tape:
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "record"}):
                cassette.urlopen(self._request(b"a"), timeout=1, opener=_Opener(b"A"))
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "replay"}):
                with self.assertRaises(urllib.error.URLError):
                    cassette.urlopen(self._request(b"b"), timeout=1, opener=_Opener(b"B"))

    def test_replay_miss_is_a_failure_not_an_empty_answer(self):
        with tempfile.TemporaryDirectory() as tape:
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "replay"}):
                with self.assertRaises(urllib.error.URLError):
                    cassette.urlopen(self._request(), timeout=1, opener=_Opener(b"never"))

    def test_not_found_is_recorded_and_replayed(self):
        missing = urllib.error.HTTPError(self.url, 404, "Not Found", None, None)
        with tempfile.TemporaryDirectory() as tape:
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "record"}):
                with self.assertRaises(urllib.error.HTTPError):
                    cassette.urlopen(self._request(), timeout=1, opener=_Opener(error=missing))
            with patch.dict(os.environ, {cassette.DIR_ENV: tape, cassette.MODE_ENV: "replay"}):
                with self.assertRaises(urllib.error.HTTPError) as caught:
                    cassette.urlopen(self._request(), timeout=1, opener=_Opener())
            self.assertEqual(caught.exception.code, 404)


def _record(finding_id, kind, label, outcome=None):
    return TriageRecord(
        finding_id=finding_id, cwe="CWE-502", file_path="x", kind=kind,
        verdict=Verdict(verdict=label, evidence_class=EvidenceClass.identifier_only, confidence=0.9),
        sca=SCASummary(outcome=outcome) if outcome else None,
    )


class ScoreByKindTests(unittest.TestCase):
    def test_sast_and_sca_are_scored_apart(self):
        records = [
            _record("sast-1", "weakness", VerdictLabel.confirmed),
            _record("sca-closed-wrong", "dependency", VerdictLabel.false_positive, "condition_absent"),
            _record("sca-model-wrong", "dependency", VerdictLabel.false_positive, "present"),
            _record("sca-right", "dependency", VerdictLabel.false_positive, "unused"),
        ]
        labels = {"sast-1": "confirmed", "sca-closed-wrong": "confirmed",
                  "sca-model-wrong": "confirmed", "sca-right": "false_positive"}
        by_kind = score(records, labels, provider="p", model="m").as_dict()["by_kind"]

        self.assertEqual(by_kind["weakness"]["agreement_decided"], 100.0)
        self.assertEqual(by_kind["weakness"]["dangerous_misses"], 0)
        dependency = by_kind["dependency"]
        self.assertEqual(dependency["n"], 3)
        self.assertEqual(dependency["dangerous_misses"], 2)
        self.assertEqual(dependency["closed_without_model"], 2)
        self.assertEqual(dependency["dangerous_closure_ids"], ["sca-closed-wrong"])


class NativeDependencyTests(unittest.TestCase):
    def test_reachability_and_call_site_survive_ingest(self):
        row = {"finding_id": "d-1", "scanner": "wolfee", "rule_id": "GHSA-x", "file_path": "package-lock.json",
               "dependency": {"package": "js-yaml", "ecosystem": "npm", "installed_version": "4.1.0",
                              "reachability": "reachable", "call_site": "src/config.js:12"}}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "corpus.jsonl")
            path.write_text(json.dumps(row) + "\n", encoding="utf-8")
            (finding,) = native.parse(path)
        self.assertEqual(finding.dependency.reachability, "reachable")
        self.assertEqual(finding.dependency.call_site, "src/config.js:12")


class BenchGuardTests(unittest.TestCase):
    def test_sca_chain_refuses_materialized_snippets(self):
        row = {"finding_id": "d-1", "scanner": "wolfee", "rule_id": "GHSA-x", "file_path": "package-lock.json",
               "dependency": {"package": "js-yaml", "ecosystem": "npm"}, "label": "false_positive"}
        with tempfile.TemporaryDirectory() as tmp:
            corpus = Path(tmp, "corpus.jsonl")
            corpus.write_text(json.dumps(row) + "\n", encoding="utf-8")
            with self.assertRaises(BenchSetupError):
                run_bench(corpus, ["deepseek"], load_pipeline_config(None), Path(tmp, "out"),
                          resolve_symbols=True)


if __name__ == "__main__":
    unittest.main()
