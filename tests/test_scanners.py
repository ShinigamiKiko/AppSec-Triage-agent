import argparse
import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from appsec_triage.cli import cmd_scan
from appsec_triage.config import ScannerConfig
from appsec_triage.scanners import scan_all, write_manifest
from appsec_triage.scanners.base import Availability
from appsec_triage.scanners.tools import WolfeeScanner


class ScannerTests(unittest.TestCase):
    def test_cli_unavailable_scanner_returns_explanation(self):
        scanner = WolfeeScanner(ScannerConfig())
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "missing" / "scans"
            stderr = io.StringIO()
            with (patch('appsec_triage.scanners.build_scanner', return_value=scanner),
                  patch.object(scanner, 'available', return_value=Availability(False, detail='not installed')),
                  redirect_stderr(stderr), redirect_stdout(io.StringIO())):
                status = cmd_scan(argparse.Namespace(target=tmp, out=output, scanner=['wolfee']))
            self.assertEqual(status, 1)
            self.assertIn("not installed", stderr.getvalue())
            self.assertTrue((output / "scan-manifest.json").is_file())

    def test_unavailable_scanner_manifest_creates_parents(self):
        scanner = WolfeeScanner(ScannerConfig())
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp)
            output = target / 'missing' / 'scans'
            with patch('appsec_triage.scanners.build_scanner', return_value=scanner), \
                    patch.object(scanner, 'available', return_value=Availability(False, detail='not installed')):
                    results = scan_all(target, ['wolfee'], output)
            self.assertFalse(output.exists())
            manifest = write_manifest(target, results, output)
            doc = json.loads(manifest.read_text())
            self.assertEqual(doc['total_findings'], 0)
            self.assertFalse(doc['scans'][0]['ok'])
            self.assertEqual(doc['scans'][0]['error'], 'not installed')
            self.assertEqual(write_manifest(target, [], output), manifest)

    def test_wolfee_uses_native_sarif_file_output(self):
        scanner = WolfeeScanner(ScannerConfig(binary='/usr/local/bin/wolfee'))
        target = Path('/work/repo with spaces')
        output = Path('/out/wolfee.sarif.json')
        argv = scanner._native_scan_argv(target, output)
        self.assertEqual(argv[:4], ['/usr/local/bin/wolfee', 'scan', '--reachable', str(target)])
        self.assertIn('--format', argv)
        self.assertEqual(argv[argv.index('--format') + 1], 'sarif')
        self.assertEqual(argv[argv.index('--output') + 1], str(output))
        self.assertFalse(scanner.writes_stdout)

    def test_wolfee_accepts_enrichment_exit_code_when_report_exists(self):
        scanner = WolfeeScanner(ScannerConfig(binary='/usr/local/bin/wolfee'))
        self.assertIn(1, scanner.success_exit_codes)
        self.assertIn(2, scanner.success_exit_codes)
        self.assertIn(3, scanner.success_exit_codes)


if __name__ == '__main__':
    unittest.main()
