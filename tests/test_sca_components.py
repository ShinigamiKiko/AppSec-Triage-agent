import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from appsec_triage import deployment as deployment_ctx
from appsec_triage.deployment import DeploymentContext, OutOfScopeComponent
from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.sca import components
from appsec_triage.sca.advisories import Advisory
from appsec_triage.sca.chain import DependencyChain
from appsec_triage.sca.verdict import CVEVerdict

QUOTE = "Applications which misuse the ServerConfig.PublicKeyCallback callback may be susceptible to an authorization bypass."

SSH_SERVER = OutOfScopeComponent(
    id="ssh_server", requires="no_ssh_server_in_workloads",
    describe="The service itself accepts SSH connections.",
    why="в подах SSH-сервер не запускается", keywords=["ssh", "sshd"],
    markers=["NewServerConn", "openssh-server"])


def _deployment(fact=True):
    return DeploymentContext(enabled=True, description="k8s", facts={"no_ssh_server_in_workloads": fact},
                             out_of_scope=[SSH_SERVER])


def _advisory(details=QUOTE, summary="Misuse of ServerConfig.PublicKeyCallback"):
    return Advisory(advisory_id="GHSA-v778-237x-gjrc", package="golang.org/x/crypto", ecosystem="go",
                    summary=summary, details=details, symbols=["golang.org/x/crypto/ssh.NewServerConn"])


def _client(answer):
    return SimpleNamespace(complete=Mock(return_value=SimpleNamespace(text=json.dumps(answer))))


class DeploymentLoaderTests(unittest.TestCase):
    def test_component_is_in_effect_only_with_its_fact(self):
        yaml_text = (
            "enabled: true\ndescription: k8s\nfacts:\n  no_ssh_server_in_workloads: {fact}\n"
            "out_of_scope_components:\n  - id: ssh_server\n    requires: no_ssh_server_in_workloads\n"
            "    describe: >-\n      accepts SSH\n    keywords: [ssh]\n    markers: [NewServerConn]\n"
            "    why: no sshd\n")
        with tempfile.TemporaryDirectory() as tmp:
            on, off = Path(tmp, "on.yaml"), Path(tmp, "off.yaml")
            on.write_text(yaml_text.format(fact="true"), encoding="utf-8")
            off.write_text(yaml_text.format(fact="false"), encoding="utf-8")
            active = deployment_ctx.load(on).components_out_of_scope()
            inert = deployment_ctx.load(off).components_out_of_scope()
        self.assertEqual([c.id for c in active], ["ssh_server"])
        self.assertEqual(active[0].markers, ["NewServerConn"])
        self.assertEqual(inert, [])

    def test_repository_config_declares_the_ssh_fact(self):
        loaded = deployment_ctx.load(Path(__file__).resolve().parents[1] / "configs" / "deployment.yaml")
        (ssh,) = [c for c in loaded.components_out_of_scope() if c.id == "ssh"]
        self.assertEqual(ssh.requires, "no_ssh_in_workloads")
        # Operator decision: SSH is out of scope on both sides, so the description must say so.
        self.assertIn("either side", ssh.describe)


class ClassifyTests(unittest.TestCase):
    def test_no_keyword_means_no_question(self):
        client = _client({"component": "ssh_server", "quote": QUOTE, "why": ""})
        advisory = Advisory(advisory_id="GHSA-x", package="lodash", summary="Code injection in template")
        self.assertIsNone(components.classify(advisory, _deployment(), client, []))
        client.complete.assert_not_called()

    def test_fact_not_set_means_no_question(self):
        client = _client({"component": "ssh_server", "quote": QUOTE, "why": ""})
        self.assertIsNone(components.classify(_advisory(), _deployment(fact=False), client, []))
        client.complete.assert_not_called()

    def test_grounded_server_answer_excludes_and_reports_the_antipattern(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.go").write_text("package main\n\nconn, _, _, _ := ssh.NewServerConn(c, cfg)\n",
                                             encoding="utf-8")
            client = _client({"component": "ssh_server", "quote": QUOTE, "why": "server-side callback"})
            exclusion = components.classify(_advisory(), _deployment(), client, [root])
        self.assertIsNotNone(exclusion)
        self.assertEqual(exclusion.markers, ["main.go:3 (NewServerConn)"])
        decision = exclusion.decision()
        self.assertIs(decision.verdict, CVEVerdict.CONDITION_ABSENT)
        self.assertTrue(decision.closes)
        self.assertIn("АНТИПАТТЕРН", exclusion.render())

    def test_quote_not_in_the_advisory_is_discarded(self):
        client = _client({"component": "ssh_server", "quote": "servers are always affected", "why": ""})
        self.assertIsNone(components.classify(_advisory(), _deployment(), client, []))

    def test_none_and_unknown_components_are_not_excluded(self):
        for answer in ({"component": "none", "quote": QUOTE, "why": "client too"},
                       {"component": "docker_daemon", "quote": QUOTE, "why": ""}):
            with self.subTest(answer=answer["component"]):
                self.assertIsNone(components.classify(_advisory(), _deployment(), _client(answer), []))

    def test_markers_skip_dependency_trees(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "vendor", "golang.org").mkdir(parents=True)
            Path(root, "vendor", "golang.org", "server.go").write_text("NewServerConn\n", encoding="utf-8")
            Path(root, "Dockerfile").write_text("FROM alpine\nRUN apk add openssh-server\n", encoding="utf-8")
            hits = components.markers_in([root], ["NewServerConn", "openssh-server"])
        self.assertEqual(hits, ["Dockerfile:2 (openssh-server)"])

    def test_dependency_trees_are_not_walked(self):
        import os
        visited: list[str] = []
        real_walk = os.walk

        def walk(top, *args, **kwargs):
            for parent, dirnames, filenames in real_walk(top, *args, **kwargs):
                visited.append(parent)
                yield parent, dirnames, filenames

        with tempfile.TemporaryDirectory() as root:
            Path(root, "node_modules", "big", "lib").mkdir(parents=True)
            Path(root, "node_modules", "big", "lib", "ssh.js").write_text("NewServerConn\n", encoding="utf-8")
            Path(root, "src").mkdir()
            Path(root, "src", "main.go").write_text("ssh.NewServerConn(c, cfg)\n", encoding="utf-8")
            with patch("appsec_triage.sca.components.os.walk", side_effect=walk):
                hits = components.markers_in([root], ["NewServerConn"])
        self.assertEqual(hits, ["src/main.go:1 (NewServerConn)"])
        self.assertFalse(any("node_modules" in parent for parent in visited))


class ChainExclusionTests(unittest.TestCase):
    def test_excluded_cve_skips_the_symbol_search_and_codeql(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "main.go").write_text("ssh.NewServerConn(conn, config)\n", encoding="utf-8")
            client = _client({"component": "ssh_server", "quote": QUOTE, "why": "server side"})
            chain = DependencyChain(client, [root], deployment=_deployment())
            chain._resolver.resolve = Mock()
            chain._codeql_api_for = Mock()
            finding = Finding(
                finding_id="f-ssh", scanner="wolfee", rule_id="GHSA-v778-237x-gjrc",
                code_context=CodeContext(file_path="go.mod"),
                dependency=DependencyInfo(package="golang.org/x/crypto", ecosystem="go",
                                          installed_version="v0.29.0"))
            with patch("appsec_triage.sca.chain.orchestration.adv.collect", return_value=_advisory()):
                result = chain.run(finding)
        self.assertTrue(result.closes)
        self.assertEqual(result.route, "excluded")
        self.assertIs(result.decision.verdict, CVEVerdict.CONDITION_ABSENT)
        chain._resolver.resolve.assert_not_called()
        chain._codeql_api_for.assert_not_called()
        summary = result.summary(finding.dependency)
        self.assertEqual(summary.route, "excluded")
        self.assertIn("main.go:1 (NewServerConn)", summary.audit)
        self.assertEqual(chain.stats["out_of_scope"], 1)


if __name__ == "__main__":
    unittest.main()
