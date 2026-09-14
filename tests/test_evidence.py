import re
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from appsec_triage.context.evidence import RepositoryEvidence
from appsec_triage.context.source import SourceResolver


class RepositoryEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.collector = RepositoryEvidence(SourceResolver([self.root]))
        self.pkg = self.package()

    @staticmethod
    def package():
        return SimpleNamespace(evidence_blocks=[], context_notes=[])

    def write(self, name, text):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def numbered(self, name="app.py", count=150):
        return self.write(name, "\n".join(f"source_{n}" for n in range(1, count + 1)))

    def read_request(self, name, line=1):
        return {"action": "read", "path": str(name), "line": line}

    def text(self):
        return "\n".join(self.pkg.evidence_blocks)

    def test_snippet_and_structured_locations(self):
        files = [self.numbered(f"{name}.py") for name in ("input", "sink", "hit", "site", "trace", "finding")]
        chain = SimpleNamespace(
            dataflow=SimpleNamespace(source_file=str(files[0]), source_line=40, file=str(files[1]), line=40),
            presence=SimpleNamespace(hits=[SimpleNamespace(file=str(files[2]), line=40)]),
            reachability=SimpleNamespace(sites=[(str(files[3]), 40)]),
        )
        finding = SimpleNamespace(
            code_context=SimpleNamespace(file_path=str(files[5]), start_line=40),
            trace=[SimpleNamespace(file_path=str(files[4]), line=40)],
        )
        self.assertIsNone(self.collector.enrich(self.pkg, finding, chain))
        self.assertEqual(len(self.pkg.evidence_blocks), 6)
        for block in self.pkg.evidence_blocks:
            self.assertIn("24 | source_24", block)
            self.assertIn("56 | source_56", block)
            self.assertNotIn("23 | source_23", block)
            self.assertNotIn("57 | source_57", block)
        before = list(self.pkg.evidence_blocks)
        self.collector.enrich(self.pkg, finding, chain)
        self.assertEqual(self.pkg.evidence_blocks, before)

    def test_config_priority_order_and_resources(self):
        self.write("config/packages/security.yaml", "security:\n  firewalls:\n    first: yes\n    second: no\n")
        self.write("config/packages/prod/security.yaml", "security:\n  access_control: []\n")
        self.write("config/packages/framework.yml", "framework:\n  secret: '%env(APP_SECRET)%'\n")
        self.write("config/packages/api_platform.yaml", "api_platform:\n  graphql: true\n")
        self.write("config/routes.yaml", "imports:\n  - { resource: outside.yaml }\n")
        self.write("config/services.xml", '<container><imports resource="other.xml"/></container>')
        self.write("config/api_platform/book.yaml", "resources:\n  App\\Entity\\Book: ~\n")
        self.write("mapping/book.xml", '<resources><resource class="Book"/></resources>')
        self.write("src/Entity/Book.php", "<?php\n#[ApiResource]\nclass Book {}")
        self.write("src/Unrelated.php", "<?php\nclass Unrelated {}")
        self.write("unrelated.json", '{"not_config": true}')
        self.collector.enrich(self.pkg, SimpleNamespace(trace=[]))
        text = self.text()
        self.assertIn("static config; environment override: prod", text)
        self.assertLess(text.index("first: yes"), text.index("second: no"))
        self.assertLess(text.index("security.yaml"), text.index("framework.yml"))
        self.assertLess(text.index("framework.yml"), text.index("api_platform.yaml"))
        for token in ("outside.yaml", "other.xml", "#[ApiResource]", "<resources>", "resources:"):
            self.assertIn(token, text)
        self.assertNotIn("Unrelated", text)
        self.assertNotIn("not_config", text)
        notes = " ".join(self.pkg.context_notes)
        self.assertIn("not effective runtime", notes)
        self.assertIn("not proof", notes)
        self.assertIn("never executed", notes)

    def test_deployment_and_go_build_evidence_are_collected(self):
        self.write("Dockerfile", "FROM golang:1.24-alpine\nENV CGO_ENABLED=0\n")
        self.write("go.mod", "module example\ngo 1.24\n")
        self.write(".gitlab-ci.yml", "build:\n  script: go build ./...\n")
        self.write("src/main.go", "package main\nfunc main() {}\n")
        self.collector.enrich(self.pkg, SimpleNamespace(trace=[]))
        text = self.text()
        self.assertIn("golang:1.24-alpine", text)
        self.assertIn("CGO_ENABLED=0", text)
        self.assertIn("go 1.24", text)
        self.assertIn("deployment/build evidence", text)

    def test_redacts_low_entropy_high_entropy_and_multiline(self):
        self.write("settings.yaml", "password: weakpass\nsecret: shortsecret\ntoken: tinytoken\n"
                   "api_key: smallkey\nprivate_key: |\n  hidden_line_one\n  hidden_line_two\n"
                   "safe: true\nsecret: '%env(APP_SECRET)%'\npassword: ${DB_PASSWORD}\n"
                   'random: "A9b2C7d4E1f8G3h6J5k0L9m2"\n')
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("settings.yaml")]))
        text = self.text()
        for secret in ("weakpass", "shortsecret", "tinytoken", "smallkey", "hidden_line", "A9b2C7d4"):
            self.assertNotIn(secret, text)
        self.assertIn("%env(APP_SECRET)%", text)
        self.assertIn("${DB_PASSWORD}", text)
        self.assertIn("8 | safe: true", text)
        self.assertIn("REDACTED", text)

    def test_redacts_php_json_xml_and_block_interior(self):
        self.write("config.php", "<?php\n['password' => 'veryweak', 'api_key' => 'weakkey'];\n")
        self.write("config.json", '{"password": "weakjson", "token": "weaktoken"}')
        self.write("config.xml", '<parameters><parameter key="secret">weakxml</parameter>'
                   '<password>weakpass</password><parameter name="token" value="weakattr"/>'
                   '<parameter value="reverseweak" key = "password"/></parameters>')
        self.write("block.yml", "private_key: |\n  interior_secret\nother: true\n")
        for name in ("config.php", "config.json", "config.xml"):
            self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request(name)]))
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("block.yml", 2)]))
        for secret in ("veryweak", "weakkey", "weakjson", "weaktoken", "weakxml", "weakpass", "weakattr",
                       "reverseweak", "interior_secret"):
            self.assertNotIn(secret, self.text())

    def test_strict_paths_and_explicit_src_mapping(self):
        path = self.write("nested/app.py", "allowed_source")
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("/src/nested/app.py")]))
        self.assertIn(str(path.resolve()), self.text())
        self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request(path)]))
        for name in ("app.py", "/unrelated/nested/app.py", "wrong/nested/app.py", "../repo/nested/app.py",
                     "/etc/passwd", "nested/../nested/app.py", "bad\x00.py"):
            with self.subTest(name=name):
                self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request(name)]))

    def test_secret_collections_preserve_line_numbers(self):
        fixtures = {
            "list.yaml": "api_tokens:\n  - firstcred\n  - secondcred\n  - nested:\n      value: thirdcred\nsafe: true\n",
            "map.yaml": "api_tokens:\n  first: firstcred\n  nested:\n    value: secondcred\nsafe: true\n",
            "flat.yaml": "api_tokens:\n- firstcred\n- secondcred\nsafe: true\n",
            "flow.yaml": "api_tokens: [firstcred, {nested: [secondcred, thirdcred]}]\nsafe: true\n",
            "list.json": '{"api_tokens": [\n"firstcred",\n{"nested": ["secondcred", "thirdcred"]}\n],\n"safe": true}\n',
            "map.json": '{"api_tokens": {"first": "firstcred", "nested": {"value": "secondcred"}},\n"safe": true}\n',
            "singular.json": '{"password": {"value": "firstcred"}, "safe": true}\n',
            "singular.yaml": "password:\n  value: firstcred\nsafe: true\n",
        }
        for name, content in fixtures.items():
            with self.subTest(name=name):
                self.write(name, content)
                pkg = self.package()
                self.assertTrue(self.collector.retrieve(pkg, [self.read_request(name)]))
                text = "\n".join(pkg.evidence_blocks)
                for secret in ("firstcred", "secondcred", "thirdcred"):
                    self.assertNotIn(secret, text)
                self.assertIn(f"{len(content.splitlines())} |", text)
                self.assertIn("safe", text)

    def test_auth_configuration_and_flags_are_preserved(self):
        content = (
            "access_token:\n  token_handler: App\\Security\\Handler\n"
            "password_hashers:\n  App\\Entity\\User: auto\n"
            "token_id: authenticate\ncsrf_protection: true\n"
            "csrf_token: false\nsecret: true\npassword: off\n"
            "token: App\\Security\\TokenProvider\n"
            "api_tokens: false\npassword_hasher: auto\n"
            "access_token: {token_handler: App\\Security\\Handler}\n"
        )
        self.write("auth.yaml", content)
        self.collector.retrieve(self.pkg, [self.read_request("auth.yaml")])
        for n, line in enumerate(content.splitlines(), 1):
            self.assertIn(f"{n} | {line}", self.text())
        self.write("auth.json", '{"access_token": {"token_handler": "App\\\\Security\\\\Handler"}, "csrf_token": false}')
        self.collector.retrieve(self.pkg, [self.read_request("auth.json")])
        self.assertIn('"token_handler": "App\\\\Security\\\\Handler"', self.text())
        self.assertIn('"csrf_token": false', self.text())

    def test_retrieval_prioritizes_reads_and_caches_bytes_per_round(self):
        self.write("a.py", "unrelated\n" * 20)
        target = self.write("z.py", "\n".join(f"line_{n}" for n in range(1, 151)))
        requests = [
            {"action": "search", "pattern": "missing"},
            self.read_request("z.py"),
            self.read_request("z.py", 81),
            {"action": "search", "pattern": "line_150"},
        ]
        with patch("appsec_triage.context.evidence.MAX_TOTAL_BYTES", target.stat().st_size):
            with patch.object(self.collector, "_load", wraps=self.collector._load) as load:
                self.assertTrue(self.collector.retrieve(self.pkg, requests))
                self.assertEqual(sum(call.args[1] == target for call in load.call_args_list), 1)
            self.assertIn("150 | line_150", self.text())
            # A separate round must observe edits rather than a shared cache.
            target.write_text("fresh_content", encoding="utf-8")
            pkg = self.package()
            self.assertTrue(self.collector.retrieve(pkg, [self.read_request("z.py")]))
            self.assertIn("fresh_content", "\n".join(pkg.evidence_blocks))

    def test_searches_reuse_content_after_a_miss(self):
        path = self.write("app.py", "needle\n")
        with (patch("appsec_triage.context.evidence.MAX_TOTAL_BYTES", path.stat().st_size),
              patch.object(self.collector, "_load", wraps=self.collector._load) as load):
            self.assertTrue(self.collector.retrieve(self.pkg, [
                {"action": "search", "pattern": "missing"},
                {"action": "search", "pattern": "needle"},
            ]))
            self.assertEqual(load.call_count, 1)

    def test_enrichment_reserves_retrieval_characters(self):
        self.numbered(count=300)
        self.write("target.php", "<?php\nfunction target() {}")
        collector = RepositoryEvidence(SourceResolver([self.root]), max_chars=1200)
        collector.enrich(self.pkg, {"trace": [{"file_path": "app.py", "line": n} for n in (20, 60, 100)]})
        initial = sum(map(len, self.pkg.evidence_blocks))
        self.assertLessEqual(initial, 900)
        self.assertTrue(collector.retrieve(self.pkg, [self.read_request("target.php")]))
        self.assertIn("function target()", self.text())
        self.assertLessEqual(sum(map(len, self.pkg.evidence_blocks)), 1200)

    def test_only_successfully_added_code_sets_collection_flag(self):
        for name in ("config.yaml", "config.xml", "config.json"):
            self.write(name, "configuration")
            self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request(name)]))
            self.assertFalse(getattr(self.pkg, "repository_code_collected", False))
        self.write("app.php", "<?php\nfunction example() {}")
        self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("app.php", 100)]))
        self.assertFalse(getattr(self.pkg, "repository_code_collected", False))
        zero = RepositoryEvidence(SourceResolver([self.root]), max_chars=1)
        self.assertFalse(zero.retrieve(self.pkg, [self.read_request("app.php")]))
        self.assertFalse(getattr(self.pkg, "repository_code_collected", False))
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("app.php")]))
        self.assertTrue(self.pkg.repository_code_collected)
        pkg = self.package()
        self.collector.enrich(pkg, {"trace": [{"file_path": "app.php", "line": 1}]})
        self.assertTrue(pkg.repository_code_collected)

    def test_exclusions_and_symlinks(self):
        outside = Path(self.temp.name) / "outside.py"
        outside.write_text("outside_private", encoding="utf-8")
        self.write("safe.py", "safe_source")
        (self.root / "link.py").symlink_to(outside)
        (self.root / "internal.py").symlink_to(self.root / "safe.py")
        (self.root / "linked_dir").symlink_to(Path(self.temp.name), target_is_directory=True)
        names = [".env", ".env.local.json", ".git/config.json", "vendor/lib.py", "node_modules/lib.js",
                 "private.pem", "private.key", "secrets/vault.yaml", "keys/key.json", "credentials.json"]
        for name in names:
            self.write(name, "private_marker")
        self.write("disguised.py", "-----BEGIN PRIVATE KEY-----\nprivate_marker")
        for name in names + ["link.py", "internal.py", "linked_dir/outside.py", "disguised.py"]:
            self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request(name)]))
        self.assertFalse(self.collector.retrieve(self.pkg, [{"action": "search", "pattern": "private"}]))
        self.assertEqual(self.pkg.evidence_blocks, [])

    def test_read_bound_and_overlap_dedup(self):
        self.numbered()
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("app.py", 20)]))
        self.assertIn("99 | source_99", self.text())
        self.assertNotIn("100 | source_100", self.text())
        self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("app.py", 20)]))
        self.assertTrue(self.collector.retrieve(self.pkg, [self.read_request("app.py", 40)]))
        numbers = re.findall(r"^(\d+) \|", self.text(), re.MULTILINE)
        self.assertEqual(len(numbers), len(set(numbers)))
        self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("app.py", 1000)]))

    def test_literal_search_windows_and_no_new_evidence(self):
        self.write("app.py", "\n".join("a.*b" if n == 30 else f"line_{n}" for n in range(1, 70)))
        request = {"action": "search", "pattern": "a.*b"}
        self.assertTrue(self.collector.retrieve(self.pkg, [request]))
        self.assertIn("20 | line_20", self.text())
        self.assertIn("40 | line_40", self.text())
        self.assertNotIn("19 | line_19", self.text())
        self.assertNotIn("41 | line_41", self.text())
        self.assertFalse(self.collector.retrieve(self.pkg, [request]))
        self.assertFalse(self.collector.retrieve(self.pkg, [{"action": "search", "pattern": "a.+b"}]))
        self.assertFalse(self.collector.retrieve(self.pkg, []))

    def test_character_budget_across_calls_and_packages(self):
        self.numbered()
        collector = RepositoryEvidence(SourceResolver([self.root]), max_chars=400)
        collector.enrich(self.pkg, {"trace": [{"file_path": "app.py", "line": 25}]})
        collector.retrieve(self.pkg, [self.read_request("app.py", 60)])
        self.assertLessEqual(sum(map(len, self.pkg.evidence_blocks)), 400)
        self.assertIn("character budget", " ".join(self.pkg.context_notes))
        first = list(self.pkg.evidence_blocks)
        self.assertFalse(collector.retrieve(self.pkg, [self.read_request("app.py", 60)]))
        self.assertEqual(first, self.pkg.evidence_blocks)
        zero = RepositoryEvidence(SourceResolver([self.root]), max_chars=0)
        self.assertFalse(zero.retrieve(self.package(), [self.read_request("app.py")]))
        packages = [self.package() for _ in range(8)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda pkg: collector.retrieve(pkg, [self.read_request("app.py")]), packages))
        self.assertTrue(all(results))
        self.assertTrue(all(pkg.evidence_blocks == packages[0].evidence_blocks for pkg in packages))

    def test_file_byte_entry_and_request_bounds(self):
        for i in range(10):
            self.write(f"file{i}.py", "needle" * 10)
        with patch("appsec_triage.context.evidence.MAX_FILES", 2):
            self.collector.retrieve(self.pkg, [{"action": "search", "pattern": "needle"}])
        self.assertEqual(len(self.pkg.evidence_blocks), 2)
        self.assertIn("file limit", " ".join(self.pkg.context_notes))
        with patch("appsec_triage.context.evidence.MAX_ENTRIES", 2):
            self.assertFalse(self.collector.retrieve(self.package(), [{"action": "search", "pattern": "needle"}]))
        with patch("appsec_triage.context.evidence.MAX_FILE_BYTES", 4):
            self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("file9.py")]))
        with patch("appsec_triage.context.evidence.MAX_TOTAL_BYTES", 60):
            pkg = self.package()
            self.collector.retrieve(pkg, [self.read_request("file8.py"), self.read_request("file9.py")])
            self.assertEqual(len(pkg.evidence_blocks), 1)
        pkg = self.package()
        self.collector.retrieve(pkg, [self.read_request(f"file{i}.py") for i in range(10)])
        self.assertEqual(len(pkg.evidence_blocks), 6)
        self.assertIn("six requests", " ".join(pkg.context_notes))

    def test_unreadable_and_invalid_requests(self):
        self.write("app.py", "content")
        with patch.object(Path, "open", side_effect=PermissionError("denied")):
            self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("app.py")]))
        self.assertIn("unreadable", " ".join(self.pkg.context_notes))
        for request in (None, {}, {"action": "execute"}, self.read_request("app.py", -1),
                        self.read_request("app.py", True), {"action": "search", "pattern": ""}):
            self.assertFalse(self.collector.retrieve(self.pkg, [request]))
        count = len(self.pkg.context_notes)
        self.collector.retrieve(self.pkg, [{}])
        self.assertEqual(count, len(self.pkg.context_notes))

    def test_config_priority_with_tight_traversal_limit(self):
        for i in range(10):
            self.write(f"app{i}.py", "unrelated")
            self.write(f"config/unrelated{i}.yaml", "unrelated: true")
        self.write("config/packages/aaa.yaml", "unrelated: true")
        self.write("config/packages/security.yaml", "security: true")
        with patch("appsec_triage.context.evidence.MAX_FILES", 1):
            self.collector.enrich(self.pkg, {})
        self.assertIn("security: true", self.text())
        self.assertNotIn("unrelated", self.text())

    def test_search_match_limit_and_long_line_budget(self):
        self.write("app.py", "needle\n" * 200)
        with patch("appsec_triage.context.evidence.MAX_LOCATIONS", 2):
            self.assertTrue(self.collector.retrieve(self.pkg, [{"action": "search", "pattern": "needle"}]))
        self.assertIn("match limit", " ".join(self.pkg.context_notes))
        self.assertNotIn("13 |", self.text())
        self.write("long.py", "x" * 40000)
        self.assertFalse(self.collector.retrieve(self.pkg, [self.read_request("long.py")]))
        self.assertLessEqual(sum(map(len, self.pkg.evidence_blocks)), 32000)


if __name__ == "__main__":
    unittest.main()
