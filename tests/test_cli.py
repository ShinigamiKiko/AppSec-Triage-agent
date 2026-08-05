"""CLI/config surface: strict-LSP config and the --fail-on CI gate."""

from __future__ import annotations


def test_lsp_config_makes_first_class_languages_mandatory():
    """The shipped lsp.yaml must keep php/python/go/ts strict, and every strict
    key must own the file types it claims — a regression that drops one silently
    lets an untraced dataflow closure ship as a decided verdict."""
    from appsec_triage.config import load_lsp_config

    lsp = load_lsp_config()
    assert set(lsp.required_languages) == {"php", "python", "go", "typescript"}, lsp.required_languages

    # Each strict language must resolve to a server that actually owns its files;
    # a required key with no matching server is a no-op that never fires.
    strict_files = {
        "php": "src/Cfg.php",
        "python": "app/handlers.py",
        "go": "cmd/main.go",
        "typescript": "web/api.ts",
    }
    for lang, path in strict_files.items():
        assert lsp.language_for(path) == lang, (path, lsp.language_for(path))

    # ts/js share the `typescript` server: .js/.jsx must be covered by the same
    # strict key, or JS findings quietly bypass the mandate.
    for js_path in ("web/app.js", "web/comp.jsx", "web/api.tsx"):
        assert lsp.language_for(js_path) == "typescript", (js_path, lsp.language_for(js_path))
        assert lsp.language_for(js_path) in lsp.required_languages


def test_fail_on_gate_counts():
    """The CI gate must trip on confirmed (and on unknown when set to review),
    and never on closed findings — closing noise is the tool doing its job."""
    from appsec_triage.cli import _gate_count

    # gate off -> None regardless of counts
    assert _gate_count("none", {"confirmed": 5, "unknown": 5, "false_positive": 5}) is None

    # confirmed: only confirmed verdicts trip it
    assert _gate_count("confirmed", {"confirmed": 2, "unknown": 3, "false_positive": 9}) == 2
    assert _gate_count("confirmed", {"confirmed": 0, "unknown": 3, "false_positive": 9}) == 0

    # review: confirmed + unknown (an abstention still needs a human); closed never counts
    assert _gate_count("review", {"confirmed": 2, "unknown": 3, "false_positive": 9}) == 5
    assert _gate_count("review", {"confirmed": 0, "unknown": 0, "false_positive": 40}) == 0
