import unittest

from appsec_triage.context.builder import build
from appsec_triage.context.heuristics import HeuristicResult
from appsec_triage.models import CodeContext, DependencyInfo, Finding
from appsec_triage.validate.postvalidation import check_deployment_mismatch


class DeploymentGateTests(unittest.TestCase):
    def test_windows_only_vulnerability_on_linux_deployment(self):
        finding = Finding(
            finding_id="gov-windows",
            scanner="govulncheck",
            rule_id="GO-2026-4971",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go", installed_version="1.26.0"),
            raw={"advisory": {"details": "The Dial and LookupPort functions panic on Windows when provided with an input containing a NUL (0)."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        reason = check_deployment_mismatch(finding, pkg)
        self.assertIsNotNone(reason)
        self.assertIn("Windows", reason)

    def test_kernel_vulnerability_is_fp(self):
        finding = Finding(
            finding_id="gov-kernel",
            scanner="govulncheck",
            rule_id="GO-2026-5001",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go"),
            raw={"advisory": {"details": "A Linux kernel syscall vulnerability allows local privilege escalation."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        reason = check_deployment_mismatch(finding, pkg)
        self.assertIsNotNone(reason)
        self.assertIn("kernel", reason)

    def test_windows_cross_platform_is_not_fp(self):
        finding = Finding(
            finding_id="gov-cross-platform",
            scanner="govulncheck",
            rule_id="GO-2026-5002",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go"),
            raw={"advisory": {"details": "A cross-platform issue affects Windows and Linux."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        self.assertIsNone(check_deployment_mismatch(finding, pkg))

    def test_cgo_vulnerability_with_cgo_disabled(self):
        finding = Finding(
            finding_id="gov-cgo",
            scanner="govulncheck",
            rule_id="GO-2026-4981",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go", installed_version="1.26.0"),
            raw={"advisory": {"details": "When using LookupCNAME with the cgo DNS resolver, a very long CNAME response can trigger a double-free of C memory and a crash."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())
        # Inject CGO evidence into evidence_blocks
        pkg.evidence_blocks.append("deployment/build evidence (CGO config: ENV CGO_ENABLED=0)")

        reason = check_deployment_mismatch(finding, pkg)
        self.assertIsNotNone(reason)
        self.assertIn("CGO", reason)
        self.assertIn("CGO_ENABLED=0", reason)

        pkg.evidence_blocks.clear()
        self.assertIsNone(check_deployment_mismatch(finding, pkg))

    def test_server_tls_vulnerability_without_incoming_tls(self):
        finding = Finding(
            finding_id="gov-tls",
            scanner="govulncheck",
            rule_id="GO-2026-4870",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go", installed_version="1.26.0"),
            raw={"advisory": {"details": "If one side of the TLS connection sends multiple key update messages post-handshake in a single record, the connection can deadlock, causing uncontrolled consumption of resources. This can lead to a denial of service.\n\nThis only affects TLS 1.3."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        reason = check_deployment_mismatch(finding, pkg)
        self.assertIsNotNone(reason)
        self.assertIn("server-side TLS", reason)
        self.assertIn("terminated at the ingress", reason)

    def test_client_tls_vulnerability_is_not_fp(self):
        finding = Finding(
            finding_id="gov-client-tls",
            scanner="govulncheck",
            rule_id="GO-2026-4871",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="stdlib", ecosystem="go"),
            raw={"advisory": {"details": "A client TLS certificate validation flaw permits a man-in-the-middle attack."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        self.assertIsNone(check_deployment_mismatch(finding, pkg))

    def test_container_anti_pattern_vulnerabilities_are_fp(self):
        cases = {
            "ssh": "SSH client host-key validation bypass.",
            "ldap": "LDAP authentication bypass.",
            "ftp": "FTP directory traversal.",
            "nfs": "NFS RPC remote code execution.",
            "smb": "SMB authentication bypass.",
        }
        for component, details in cases.items():
            with self.subTest(component=component):
                finding = Finding(
                    finding_id=f"container-{component}",
                    scanner="wolfee",
                    code_context=CodeContext(file_path="Dockerfile", start_line=1),
                    raw={"advisory": {"details": details}},
                )
                pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
                    "code_context_lines": 0, "dataflow_context_lines_after": 0,
                    "dataflow_context_lines_before": 0, "max_code_chars": 1000,
                    "max_trace_steps": 12, "redact_secrets": False,
                    "lsp": type("L", (), {"required_languages": []})(),
                })())
                self.assertIsNotNone(check_deployment_mismatch(finding, pkg))

    def test_removed_categories_are_triaged_normally(self):
        cases = {
            "curl": "curl command-line utility buffer overflow.",
            "wget": "wget command-line utility buffer overflow.",
            "telnet": "telnet authentication bypass.",
            "x11": "X11 display server memory corruption.",
            "systemd": "systemd unit-file privilege escalation.",
        }
        for word, details in cases.items():
            with self.subTest(word=word):
                finding = Finding(
                    finding_id=f"removed-{word}",
                    scanner="wolfee",
                    code_context=CodeContext(file_path="Dockerfile", start_line=1),
                    raw={"advisory": {"details": details}},
                )
                pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
                    "code_context_lines": 0, "dataflow_context_lines_after": 0,
                    "dataflow_context_lines_before": 0, "max_code_chars": 1000,
                    "max_trace_steps": 12, "redact_secrets": False,
                    "lsp": type("L", (), {"required_languages": []})(),
                })())
                self.assertIsNone(check_deployment_mismatch(finding, pkg))

    def test_common_words_do_not_close_application_flaws(self):
        cases = {
            "driver": "SQL injection in the PostgreSQL driver when query parameters are interpolated.",
            "gui": "Stored cross-site scripting in the admin GUI.",
            "qt": "Remote code execution in the Qt-style template renderer.",
        }
        for word, details in cases.items():
            with self.subTest(word=word):
                finding = Finding(
                    finding_id=f"app-{word}",
                    scanner="wolfee",
                    code_context=CodeContext(file_path="go.mod", start_line=1),
                    dependency=DependencyInfo(package="github.com/example/lib", ecosystem="go"),
                    raw={"advisory": {"details": details}},
                )
                pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
                    "code_context_lines": 0, "dataflow_context_lines_after": 0,
                    "dataflow_context_lines_before": 0, "max_code_chars": 1000,
                    "max_trace_steps": 12, "redact_secrets": False,
                    "lsp": type("L", (), {"required_languages": []})(),
                })())
                self.assertIsNone(check_deployment_mismatch(finding, pkg))

    def test_no_mismatch_for_generic_vulnerability(self):
        finding = Finding(
            finding_id="gov-generic",
            scanner="govulncheck",
            rule_id="GO-2026-5005",
            code_context=CodeContext(file_path="main.go", start_line=10),
            dependency=DependencyInfo(package="golang.org/x/crypto", ecosystem="go", installed_version="0.48.0"),
            raw={"advisory": {"details": "A vulnerability in the bcrypt package allows excessive resource consumption."}},
        )
        pkg = build(finding, HeuristicResult([], False, None, False, None), type("C", (), {
            "code_context_lines": 0, "dataflow_context_lines_after": 0,
            "dataflow_context_lines_before": 0, "max_code_chars": 1000,
            "max_trace_steps": 12, "redact_secrets": False,
            "lsp": type("L", (), {"required_languages": []})(),
        })())

        reason = check_deployment_mismatch(finding, pkg)
        self.assertIsNone(reason)


if __name__ == "__main__":
    unittest.main()
