import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_triage.scanners.selection import scanners_for_target


class PHPSelectionTests(unittest.TestCase):
    def test_php_and_mixed_projects_select_psalm_and_codeql(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.php').touch()
            with patch('appsec_triage.scanners.selection.usable_scanners',
                       return_value=['psalm', 'codeql', 'wolfee']):
                self.assertEqual(scanners_for_target(root), ['psalm', 'wolfee'])
                (root / 'frontend.js').touch()
                selected = scanners_for_target(root)
                self.assertEqual(set(selected), {'psalm', 'codeql', 'wolfee'})

    def test_no_fallback_when_psalm_is_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'app.PHP').touch()
            with patch('appsec_triage.scanners.selection.usable_scanners', return_value=['codeql', 'wolfee']):
                self.assertEqual(scanners_for_target(root), ['wolfee'])

    def test_unknown_language_keeps_available_scanners(self):
        with (tempfile.TemporaryDirectory() as directory,
              patch('appsec_triage.scanners.selection.usable_scanners', return_value=['codeql', 'psalm', 'wolfee'])):
            self.assertEqual(scanners_for_target(Path(directory)), ['wolfee'])
