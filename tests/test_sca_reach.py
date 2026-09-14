import unittest
from pathlib import Path
from unittest.mock import patch

from appsec_triage.models import CodeContext, Finding, TraceStep
from appsec_triage.sca.presence import Hit
from appsec_triage.sca.reach import Reachability, _taint_into, assess

ROOT = Path('/work/repo')
HIT = Hit('app/handler.php', 20, 'sink($input);')


def finding(scanner='CodeQL', file='app/handler.php', line=20):
    return Finding(
        finding_id='test', scanner=scanner, rule_id='test-taint',
        code_context=CodeContext(file_path=file, start_line=line),
        trace=[TraceStep(file_path='app/handler.php', line=5, role='source'),
               TraceStep(file_path=file, line=line, role='sink')],
    )


class ReachTests(unittest.TestCase):
    def test_matching_scanners_and_provenance(self):
        for scanner in ('CodeQL', 'Psalm'):
            with self.subTest(scanner=scanner), \
                    patch('appsec_triage.sca.reach._entrypoint_above', return_value=('route', '')):
                result = assess([HIT], ROOT, lsp=object(), routes=None,
                                codeql_findings=[finding(scanner)])
                self.assertIs(result.verdict, Reachability.REACHABLE)
                self.assertEqual(result.tools_used, ['lsp', scanner.lower()])
                self.assertIn(scanner.lower(), result.detail)
                self.assertIn(scanner.lower(), result.taint_path)

    def test_repo_path_normalization(self):
        for file in ('./app/handler.php', r'app\handler.php', '/work/repo/app/handler.php',
                     'file:///work/repo/app/handler.php',
                      'app/other/../handler.php'):
            with self.subTest(file=file):
                self.assertTrue(_taint_into([finding(file=file)], [HIT], ROOT)[0])
        spaced = Hit('app/my handler.php', 20, '')
        self.assertTrue(_taint_into(
            [finding(file='file:///work/repo/app/my%20handler.php')], [spaced], ROOT)[0])
        absolute = Hit('/work/repo/app/handler.php', 20, '')
        self.assertTrue(_taint_into([finding()], [absolute], ROOT)[0])

    def test_unrelated_paths_and_incomplete_traces_do_not_match(self):
        cases = [finding(file=file) for file in (
            'other/handler.php', 'handler.php', '/other/repo/app/handler.php',
            '/work/repository/app/handler.php', '../app/handler.php',
            'file://remote/work/repo/app/handler.php', '/src/../app/handler.php',
            'file:///work/repo/app/handler.php?query',
            'file:///work/repo/app/handler.php#fragment',
            'file:app/handler.php', 'file://[broken',
            'file:///work/repo/app/handler.php%00',
        )]
        cases += [finding('other'), finding(line=21), finding(line=24), finding(line=None), finding(line=0),
                  finding('CodeQL', '/src/app/handler.php')]
        for trace in ([], [TraceStep(file_path=HIT.file, line=HIT.line)]):
            item = finding()
            item.trace = trace
            cases.append(item)
        for item in cases:
            with self.subTest(item=item):
                path, problem, scanner = _taint_into([item], [HIT], ROOT)
                self.assertEqual((path, scanner), ('', ''))
                self.assertIn('unknown', problem)

    def test_source_paths_are_normalized_and_validated(self):
        for scanner, source in (
            ('Psalm', 'file:///work/repo/app/handler.php'),
            ('CodeQL', 'file://localhost/work/repo/app/handler.php'),
        ):
            item = finding(scanner)
            item.trace[0].file_path = source
            path, problem, tool = _taint_into([item], [HIT], ROOT)
            self.assertEqual(problem, '')
            self.assertEqual(tool, scanner.lower())
            self.assertIn('app/handler.php:5 -> app/handler.php:20', path)
        for source in ('<unknown>', '../outside.php', '/elsewhere/source.php',
                       'file://remote/work/repo/source.php', ''):
            item = finding()
            item.trace[0].file_path = source
            self.assertFalse(_taint_into([item], [HIT], ROOT)[0])

    def test_literal_percent_paths_do_not_alias_decoded_paths(self):
        item = finding(file='app/handler%20name.php')
        self.assertFalse(_taint_into([item], [Hit('app/handler name.php', 20, '')], ROOT)[0])
        self.assertTrue(_taint_into([item], [Hit('app/handler%20name.php', 20, '')], ROOT)[0])

    def test_no_match_is_unknown_even_when_tools_have_results(self):
        for findings in ([], [finding('CodeQL', 'other.php')], [finding('Psalm', 'other.php')]):
            for entry in (('', 'no route found'), ('route', '')):
                with self.subTest(findings=findings, entry=entry), \
                        patch('appsec_triage.sca.reach._entrypoint_above', return_value=entry):
                    result = assess([HIT], ROOT, lsp=object(), routes=None, codeql_findings=findings)
                    self.assertIs(result.verdict, Reachability.UNKNOWN)
                    self.assertNotIn('codeql', result.tools_used)
                    self.assertNotIn('psalm', result.tools_used)

    def test_trace_without_entrypoint_is_unknown(self):
        result = assess([HIT], ROOT, lsp=None, routes=None, codeql_findings=[finding()])
        self.assertIs(result.verdict, Reachability.UNKNOWN)
        self.assertEqual(result.tools_used, ['codeql'])

    def test_model_provenance_is_not_codeql(self):
        with patch('appsec_triage.sca.reach._entrypoint_above', return_value=('route', '')), \
                patch('appsec_triage.sca.reach._taint_by_model', return_value=('yes', 'quote', 'reason')):
            result = assess([HIT], ROOT, lsp=object(), routes=None)
        self.assertIs(result.verdict, Reachability.REACHABLE)
        self.assertNotIn('codeql', result.tools_used)
        self.assertNotIn('CodeQL', result.detail)


if __name__ == '__main__':
    unittest.main()
