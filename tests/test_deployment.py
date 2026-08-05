"""Where the app runs changes priority and exposure — and nothing else.

The value and the danger are the same fact. "Behind an ingress" genuinely
settles whether an image needs a HEALTHCHECK; it settles nothing at all about a
SQL injection, because the ingress passes the request through unchanged.
"""

from __future__ import annotations

import textwrap

import pytest

from appsec_triage import deployment


def _write(tmp_path, body: str):
    path = tmp_path / "deployment.yaml"
    path.write_text(textwrap.dedent(body), encoding="utf-8")
    return deployment.load(path)


BASE = """
    enabled: true
    description: Runs in Kubernetes behind an ingress.
    facts:
      liveness_probes_by_platform: true
      run_as_non_root_by_platform: false
    platform_handles:
      - rule: "DS-0026"
        requires: liveness_probes_by_platform
        why: the kubelet probes the pod
      - rule: "DS-0002"
        requires: run_as_non_root_by_platform
        why: podSecurityContext sets the user
    """


def test_a_platform_owned_check_closes_when_its_fact_is_declared(tmp_path):
    ctx = _write(tmp_path, BASE)
    entry = ctx.handled_by_platform("DS-0026")
    assert entry is not None and "kubelet" in entry.why


def test_an_entry_whose_fact_is_not_declared_is_inert(tmp_path):
    # The list describes what the platform does. A claim nobody confirmed does
    # not get to close a finding — otherwise it becomes a bucket of exceptions.
    assert _write(tmp_path, BASE).handled_by_platform("DS-0002") is None


def test_an_unlisted_rule_is_never_platform_handled(tmp_path):
    assert _write(tmp_path, BASE).handled_by_platform("DS-0001") is None


def test_nothing_is_claimed_when_the_file_is_absent(tmp_path):
    ctx = deployment.load(tmp_path / "missing.yaml")
    assert ctx.usable is False
    assert ctx.render() == ""
    assert ctx.handled_by_platform("DS-0026") is None


def test_a_disabled_context_makes_no_claims(tmp_path):
    ctx = _write(tmp_path, BASE.replace("enabled: true", "enabled: false"))
    assert ctx.usable is False
    assert ctx.handled_by_platform("DS-0026") is None


def test_the_rendered_section_forbids_closing_a_dataflow_finding(tmp_path):
    """The guardrail is in the prompt, not just in the docstring.

    Without it, "we are behind an ingress" is an invitation to close every
    injection in the codebase.
    """
    text = _write(tmp_path, BASE).render()
    assert "priority and exposure" in text
    assert "does **not** close an injection" in text
    assert "does **not** make a committed credential safe" in text
    # Only declared-true facts are stated; a false one must not be advertised.
    assert "liveness probes by platform" in text
    assert "run as non root" not in text


def test_a_broken_file_is_loud_and_claims_nothing(tmp_path, caplog):
    path = tmp_path / "deployment.yaml"
    path.write_text("enabled: true\nfacts: [this is not a mapping", encoding="utf-8")
    ctx = deployment.load(path)
    assert ctx.usable is False
    assert any("deployment context unavailable" in r.message for r in caplog.records)
