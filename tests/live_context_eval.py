"""Opt-in synthetic baseline/enriched comparison; never discovered by unittest.

Run: PYTHONPATH=. python3 tests/live_context_eval.py
Requires DEEPSEEK_API_KEY. Sends synthetic PHP only, no project source or secrets.
"""

import json
import logging
import tempfile
from pathlib import Path

from appsec_triage.config import HeuristicsConfig, PipelineConfig, load_provider_config
from appsec_triage.context.source import SourceResolver
from appsec_triage.llm.openai_compat import DeepSeekClient
from appsec_triage.models import CodeContext, Finding
from appsec_triage.pipeline import TriagePipeline


def main():
    # Provider error bodies are not logged: some gateways echo request details.
    logging.disable(logging.CRITICAL)
    provider = load_provider_config("deepseek-reasoner")
    provider.max_retries = 0
    provider.concurrency = 1
    rows = []
    client = DeepSeekClient(provider)
    try:
        for safe in (False, True):
            with tempfile.TemporaryDirectory(prefix="synthetic-context-") as directory:
                root = Path(directory)
                (root / "src").mkdir()
                (root / "config" / "packages").mkdir(parents=True)
                (root / "src" / "Handler.php").write_text(
                    "<?php\nrequire_once __DIR__ . '/Command.php';\n"
                    "$target = $_GET['target'];\necho runCommand($target);\n", encoding="utf-8",
                )
                body = ("    return shell_exec('printf %s ' . escapeshellarg($target));"
                        if safe else "    return shell_exec($target);")
                (root / "src" / "Command.php").write_text(
                    "<?php\nfunction runCommand($target) {\n" + body + "\n}\n", encoding="utf-8",
                )
                (root / "config" / "packages" / "security.yaml").write_text(
                    "security:\n  access_control:\n    - { path: ^/, roles: PUBLIC_ACCESS }\n",
                    encoding="utf-8",
                )
                finding = Finding(
                    finding_id="synthetic-safe" if safe else "synthetic-unsafe",
                    scanner="codeql", cwe="CWE-78", title="Request passed to command helper",
                    code_context=CodeContext(file_path="src/Handler.php", start_line=4,
                                             snippet="echo runCommand($target);", language="php"),
                )
                for enriched in (False, True):
                    cfg = PipelineConfig(
                        max_workers=1, code_context_lines=0, secrets_without_model=False,
                        heuristics=HeuristicsConfig(enabled=False),
                        context_retrieval_rounds=2 if enriched else 0,
                    )
                    cfg.lsp.enabled = False
                    cfg.lsp.required_languages = []
                    cfg.verification.enabled = False
                    pipeline = TriagePipeline(client, provider, cfg, source=SourceResolver([root]))
                    if not enriched:
                        pipeline.repository_evidence = None
                    calls = client.calls
                    record = pipeline.triage_one(finding)
                    row = {
                        "case": finding.finding_id, "enriched": enriched,
                        "expected": "false_positive" if safe else "confirmed",
                        "verdict": record.verdict.verdict.value,
                        "missing_information": record.verdict.missing_information,
                        "reason": record.verdict.reason if not record.error else "Provider call failed",
                        "grounded_quotes": sum(e.grounded is True for e in record.verdict.evidence),
                        "calls": client.calls - calls, "prompt_tokens": record.prompt_tokens,
                        "completion_tokens": record.completion_tokens, "error": bool(record.error),
                    }
                    rows.append(row)
                    print(json.dumps(row, ensure_ascii=False), flush=True)
                    if record.error:
                        return 1
        print(json.dumps({"total_calls": client.calls,
                          "total_prompt_tokens": client.prompt_tokens_total,
                          "total_completion_tokens": client.completion_tokens_total,
                          "note": "Synthetic smoke comparison, not a labelled production evaluation."}))
        return 0
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
