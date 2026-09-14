import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_triage.config import ScannerConfig
from appsec_triage.ingest.sarif import parse
from appsec_triage.sca.presence import Hit
from appsec_triage.sca.reach import _taint_into
from appsec_triage.scanners import build_scanner
from appsec_triage.scanners.base import Availability
from appsec_triage.scanners.tools import PsalmScanner


class PsalmTests(unittest.TestCase):
    def test_failed_invocation_cannot_reuse_stale_report(self):
        scanner = PsalmScanner(ScannerConfig(run_in_target=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'psalm.xml.dist').write_text('<psalm/>')
            output = root / 'out'
            output.mkdir()
            report = output / 'psalm.sarif.json'
            report.write_text('{"runs":[{"results":[]}]}')
            with (patch.object(scanner, 'available', return_value=Availability(True, mode='native')),
                  patch('appsec_triage.scanners.base.subprocess.run', return_value=subprocess.CompletedProcess(
                      args=['psalm'], returncode=1, stdout='', stderr='configuration failed'))):
                result = scanner.scan(root, output)
            self.assertFalse(result.ok)
            self.assertIn('no report written', result.error)
            self.assertFalse(report.exists())

    def test_missing_config_and_autoloader_use_autonomous_mode(self):
        scanner = PsalmScanner(ScannerConfig(run_in_target=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with (patch.object(scanner, 'available', return_value=Availability(True, mode='native')),
                  patch('appsec_triage.scanners.base.subprocess.run') as run):
                result = scanner.scan(root, root / 'out')
                self.assertFalse(result.ok)
                self.assertIn('no report written', result.error)
                args = run.call_args.args[0]
                self.assertTrue(any(arg.startswith('--config=') for arg in args))
                self.assertFalse(list((root / 'out').glob('psalm-autonomous-*.xml')))

    def test_empty_successful_report_is_not_unreachability(self):
        scanner = PsalmScanner(ScannerConfig())
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'report.sarif.json'
            report.write_text(json.dumps({'runs': [{'results': []}]}))
            self.assertIsNone(scanner.report_health(report))
            self.assertEqual(list(parse(report)), [])
            report.write_text('{"runs": []}')
            self.assertIsNotNone(scanner.report_health(report))

    def test_real_interfile_taint_and_sanitizer(self):
        scanner = build_scanner('psalm')
        availability = scanner.available()
        self.assertTrue(availability.usable, f'Real Psalm execution is required: {availability}')
        scanner.cfg.timeout_s = 90
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'src').mkdir()
            (root / 'psalm.xml').write_text(
                '<psalm xmlns="https://getpsalm.org/schema/config" errorLevel="8" '
                'resolveFromConfigFile="true"><projectFiles><directory name="src"/>'
                '</projectFiles></psalm>'
            )
            (root / 'src' / 'Sink.php').write_text(
                '<?php\nfunction unsafeCommand(string $command): void {\n'
                '    shell_exec($command);\n}\n'
            )
            entry = root / 'src' / 'Entry.php'
            entry.write_text(
                "<?php\nrequire_once __DIR__ . '/Sink.php';\n"
                "unsafeCommand((string) $_GET['command']);\n"
            )
            result = scanner.scan(root, root / 'out')
            self.assertTrue(result.ok, result.error)
            findings = list(parse(result.output_path))
            shell = [f for f in findings if f.cwe == 'CWE-78']
            self.assertTrue(shell, 'Psalm did not emit the expected interfile taint finding')
            for finding in shell:
                self.assertEqual(finding.scanner, 'Psalm')
                self.assertGreaterEqual(len(finding.trace), 2)
                files = {Path(step.file_path).name for step in finding.trace}
                self.assertTrue({'Entry.php', 'Sink.php'}.issubset(files), files)
                sink = finding.trace[-1]
                path, problem, tool = _taint_into([finding], [Hit(sink.file_path, sink.line, '')], root)
                self.assertTrue(path, f'{problem}; trace={finding.trace!r}; hit={sink.file_path}:{sink.line}')
                self.assertEqual(tool, 'psalm')
            entry.write_text(
                "<?php\nrequire_once __DIR__ . '/Sink.php';\n"
                "unsafeCommand('printf %s ' . escapeshellarg((string) $_GET['command']));\n"
            )
            result = scanner.scan(root, root / 'out')
            self.assertTrue(result.ok, result.error)
            self.assertFalse([f for f in parse(result.output_path) if f.cwe == 'CWE-78'])
