"""Pre-check layer: cheap, deterministic, runs before any token is spent.

Two jobs:
 1. Produce `HeuristicSignal`s that go *into* the evidence package, so the model
    reasons over facts rather than re-deriving them from raw text.
 2. Optionally short-circuit obvious garbage entirely (`hard_fp`), which is the
    difference between paying for 746 findings and paying for 300.

Every signal carries a direction, which post-validation later uses to catch a
model that closed a high-entropy literal as a "test placeholder".
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..config import HeuristicsConfig
from ..models import Finding, HeuristicSignal
from ..testpaths import is_test

TEMPLATE_PATTERNS = [
    re.compile(r"\$\{[A-Za-z0-9_.\-]+\}"),
    re.compile(r"\{\{\s*[A-Za-z0-9_.\-]+\s*\}\}"),
    re.compile(r"%[A-Z][A-Z0-9_]{2,}%"),
    re.compile(r"%env\([^)]*\)%"),
    re.compile(r"%[a-z][\w.]*%"),
    re.compile(r"@[A-Za-z0-9_.\-]+@"),
    re.compile(r"<[A-Z][A-Z0-9_]{2,}>"),
]

UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
HEX_ID_RE = re.compile(r"\b(?:trace|request|span|correlation|session)[_-]?id\b", re.IGNORECASE)

DEFAULT_PLACEHOLDER_MARKERS = [
    "placeholder", "dummy", "sample", "example", "changeme", "change_me",
    "your_", "xxxx", "todo", "fixme", "redacted", "notreal", "fake",
    "test", "mock", "stub", "foobar", "lorem",
]

DEFAULT_NOISY_PATHS = [
    r"(^|/)tests?/", r"(^|/)__tests__/", r"(^|/)spec/", r"[._-]test\.",
    r"[._-]spec\.", r"(^|/)docs?/", r"(^|/)examples?/", r"(^|/)samples?/",
    r"(^|/)fixtures?/", r"(^|/)testdata/", r"(^|/)vendor/", r"(^|/)third[_-]?party/",
    r"(^|/)node_modules/", r"(^|/)target/", r"(^|/)build/", r"(^|/)dist/",
    r"\.generated\.", r"_pb2\.py$", r"\.min\.js$",
]

KNOWN_SECRET_SHAPES = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (re.compile(r"\bghp_[A-Za-z0-9]{36}\b"), "github_pat"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "slack_token"),
    (re.compile(r"\bsk-[A-Za-z0-9]{32,}\b"), "openai_style_key"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private_key_block"),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"), "jwt"),
]

SECRETISH_VAR_RE = re.compile(
    r"\b(pass(word|wd)?|secret|token|api[_-]?key|apikey|private[_-]?key|credential|passphrase)\b", re.IGNORECASE
)

DISABLED_TLS_RE = re.compile(
    r"""(verify\s*=\s*False
      | InsecureSkipVerify\s*:\s*true
      | CURLOPT_SSL_VERIFYPEER\s*,?\s*(?:=>?\s*)?(?:0|false)
      | CURLOPT_SSL_VERIFYHOST\s*,?\s*(?:=>?\s*)?0
      | rejectUnauthorized\s*:\s*false
      | NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['\"]?0
      | ServerCertificateValidationCallback\s*(?:\+)?=\s*.*true
      | checkServerTrusted\s*\([^)]*\)\s*\{\s*\}
      | ALLOW_ALL_HOSTNAME_VERIFIER
      | NSAllowsArbitraryLoads
      | ssl\._create_unverified_context
      | CERT_NONE)""",
    re.IGNORECASE | re.VERBOSE,
)

SQL_INTERPOLATION_RE = re.compile(
    r"""(?:                              # PHP / JS / shell: "... SELECT ... $var ..."
          "[^"\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"\n]*(?:\$\{?\w+|\{\$\w+)
        | `[^`\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^`\n]*\$\{\w+   # JS template literal
        | f["'][^"'\n]*\b(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM)\b[^"'\n]*\{\w+  # Python f-string
          # Concatenation. `[\w$]` because a PHP variable starts with `$`, and
          # requiring `\w` alone silently missed the commonest PHP form.
        | \b(?:SELECT|INSERT|UPDATE|DELETE)\b[^;\n]*["']\s*[+.]\s*[\w$]
        )""",
    re.IGNORECASE | re.VERBOSE,
)

SQL_INJECTION_CWES = {"CWE-89", "CWE-564", "CWE-943"}

FRAMEWORK_DEFAULT_CONFIG_RE = re.compile(r"(^|/)\.env(\.(dist|example|test|dev))?$", re.IGNORECASE)

CLASS_FQN_RE = re.compile(
    r"^(?:\\?[A-Za-z_]\w*\\){2,}[A-Za-z_]\w*$"
    r"|^(?:[a-z][\w]*\.){2,}[A-Z]\w*$"
    r"|^[A-Za-z_]\w*(?:::[A-Za-z_]\w*)+$"
)

LITERAL_RE = re.compile(r"""["'`]([^"'`\n]{4,200})["'`]""")


SECRET_FAMILY_CWES = {"CWE-798", "CWE-259", "CWE-321", "CWE-256", "CWE-522", "CWE-540", "CWE-547"}


RANDOMNESS_FAMILY_CWES = {"CWE-330", "CWE-338", "CWE-336", "CWE-337"}

SECURITY_CONSUMER_RE = re.compile(
    r"\b\w*(session[_-]?id|csrf|xsrf|nonce|salt|otp|api[_-]?key|secret|token|password|"
    r"reset[_-]?code|invite[_-]?code|auth[_-]?code|iv|seed|key)\w*\b",
    re.IGNORECASE,
)
NONSECURITY_CONSUMER_RE = re.compile(
    r"\b\w*(jitter|backoff|delay|sleep|shuffle|sample|shard|replica|"
    r"animation|placeholder|cache[_-]?bust|dither|noise)\w*\b",
    re.IGNORECASE,
)


def _is_randomness_family(cwe: str | None) -> bool:
    return bool(cwe) and cwe.upper() in RANDOMNESS_FAMILY_CWES


def _is_secret_family(cwe: str | None) -> bool:
    if not cwe:
        return True
    return cwe.upper() in SECRET_FAMILY_CWES


@dataclass(slots=True)
class HeuristicResult:
    signals: list[HeuristicSignal]
    hard_fp: bool
    hard_fp_reason: str | None
    in_noisy_zone: bool
    noisy_zone_reason: str | None


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _noisy_zone(path: str, patterns: list[str]) -> tuple[bool, str | None]:
    normalized = path.replace("\\", "/")
    for pat in patterns:
        if re.search(pat, normalized, re.IGNORECASE):
            return True, pat
    return False, None


def _is_test_path(path: str) -> bool:
    """Identify code that is not part of the production artifact.

    The list is the one in prompts/training-context.md, shared with the prompts
    and the dependency chain, so the three cannot disagree about what a test is.
    """
    return is_test(path)


def evaluate(finding: Finding, cfg: HeuristicsConfig) -> HeuristicResult:
    signals: list[HeuristicSignal] = []
    snippet = finding.code_context.snippet or ""
    haystack = f"{snippet}\n{finding.title or ''}\n{finding.description or ''}"
    path = finding.code_context.file_path

    noisy_patterns = cfg.noisy_path_patterns or DEFAULT_NOISY_PATHS
    markers = cfg.placeholder_markers or DEFAULT_PLACEHOLDER_MARKERS

    in_noisy, noisy_reason = _noisy_zone(path, noisy_patterns)
    in_test_path = _is_test_path(path)
    if in_test_path:
        signals.append(
            HeuristicSignal(
                name="test_path",
                detail=f"path is test-only code: {path}",
                direction="toward_fp",
                weight=1.0,
            )
        )
    if in_noisy:
        signals.append(
            HeuristicSignal(
                name="noisy_zone",
                detail=f"path matches {noisy_reason!r}",
                direction="toward_fp",
                weight=0.4,
            )
        )

    for pat in TEMPLATE_PATTERNS:
        if m := pat.search(snippet):
            signals.append(
                HeuristicSignal(
                    name="template_expression",
                    detail=m.group(0),
                    direction="toward_fp",
                    weight=0.6,
                )
            )
            break

    if m := UUID_RE.search(snippet):
        signals.append(
            HeuristicSignal(name="uuid_literal", detail=m.group(0), direction="toward_fp", weight=0.4)
        )
    if m := HEX_ID_RE.search(haystack):
        signals.append(
            HeuristicSignal(name="correlation_identifier", detail=m.group(0), direction="toward_fp", weight=0.3)
        )

    lowered = snippet.lower()
    hits = [mk for mk in markers if mk in lowered]
    if hits:
        signals.append(
            HeuristicSignal(
                name="placeholder_marker",
                detail=", ".join(sorted(hits)[:5]),
                direction="toward_fp",
                weight=0.4,
            )
        )

    for pat, label in KNOWN_SECRET_SHAPES:
        if pat.search(snippet):
            signals.append(
                HeuristicSignal(
                    name="known_secret_shape",
                    detail=label,
                    direction="toward_confirmed",
                    weight=0.9,
                )
            )
            break

    literals = LITERAL_RE.findall(snippet) if _is_secret_family(finding.cwe) else []
    if literals:
        best = max(literals, key=lambda s: (shannon_entropy(s), len(s)))
        ent = shannon_entropy(best)
        templated = any(p.search(best) for p in TEMPLATE_PATTERNS)

        if CLASS_FQN_RE.match(best.strip()):
            signals.append(
                HeuristicSignal(
                    name="class_or_type_reference",
                    detail=f"{best.strip()[:60]!r} is a fully-qualified class/type name, not a credential",
                    direction="toward_fp",
                    weight=0.6,
                )
            )
        elif not templated and len(best) >= cfg.min_secret_length and ent >= cfg.min_secret_entropy:
            signals.append(
                HeuristicSignal(
                    name="high_entropy_literal",
                    detail=f"len={len(best)} entropy={ent:.2f}",
                    direction="toward_confirmed",
                    weight=0.7,
                )
            )
        else:
            signals.append(
                HeuristicSignal(
                    name="low_entropy_literal",
                    detail=f"len={len(best)} entropy={ent:.2f}",
                    direction="toward_fp",
                    weight=0.2,
                )
            )

    if (finding.cwe or "").upper() in SQL_INJECTION_CWES and (m := SQL_INTERPOLATION_RE.search(snippet)):
        signals.append(
            HeuristicSignal(
                name="sql_value_interpolated",
                detail=f"{m.group(0)[:70]!r} — the value is pasted into the SQL text. Quoting it inside "
                "the string is not parameterisation; the quotes are SQL characters an attacker can close",
                direction="toward_confirmed",
                weight=0.8,
            )
        )

    if m := DISABLED_TLS_RE.search(snippet):
        signals.append(
            HeuristicSignal(
                name="tls_validation_disabled",
                detail=f"{m.group(0)!r} disables certificate validation — exploitable by any network attacker "
                "regardless of who controls the URL",
                direction="toward_confirmed",
                weight=0.85,
            )
        )

    if _is_randomness_family(finding.cwe):
        if m := SECURITY_CONSUMER_RE.search(snippet):
            signals.append(
                HeuristicSignal(
                    name="security_context_hint",
                    detail=f"weak randomness assigned to {m.group(0)!r} — a security-relevant consumer",
                    direction="toward_confirmed",
                    weight=0.8,
                )
            )
        elif m := NONSECURITY_CONSUMER_RE.search(snippet):
            signals.append(
                HeuristicSignal(
                    name="nonsecurity_context_hint",
                    detail=f"random value used for {m.group(0)!r}",
                    direction="toward_fp",
                    weight=0.4,
                )
            )

    if SECRETISH_VAR_RE.search(snippet):
        signals.append(
            HeuristicSignal(
                name="secretish_identifier",
                detail="variable name suggests a credential",
                direction="neutral",
                weight=0.1,
            )
        )

    if FRAMEWORK_DEFAULT_CONFIG_RE.search(path.replace("\\", "/")):
        signals.append(
            HeuristicSignal(
                name="framework_default_config",
                detail="committed .env — by framework convention holds development defaults, "
                "with real secrets in the gitignored .env.local",
                direction="toward_fp",
                weight=0.3,
            )
        )

    if finding.corroborated_by:
        signals.append(
            HeuristicSignal(
                name="corroborated_by_another_scanner",
                detail=f"also reported by {', '.join(finding.corroborated_by)} at the same location",
                direction="toward_confirmed",
                weight=0.5,
            )
        )

    if not snippet.strip():
        signals.append(
            HeuristicSignal(
                name="no_code_context",
                detail="analyzer provided no snippet; verdict must rest on description and path",
                direction="neutral",
                weight=0.0,
            )
        )

    names = {s.name for s in signals}
    toward_confirmed = any(s.direction == "toward_confirmed" for s in signals)
    hard_fp = False
    hard_fp_reason = None
    if in_test_path and not toward_confirmed:
        hard_fp, hard_fp_reason = True, "finding is inside a test-only path"
    elif cfg.autoclose_on_hard_fp and not toward_confirmed:
        if "template_expression" in names:
            hard_fp, hard_fp_reason = True, "literal is a config template expression"
        elif "uuid_literal" in names and in_noisy:
            hard_fp, hard_fp_reason = True, "UUID literal inside a test/docs path"

    return HeuristicResult(
        signals=signals,
        hard_fp=hard_fp,
        hard_fp_reason=hard_fp_reason,
        in_noisy_zone=in_noisy,
        noisy_zone_reason=noisy_reason,
    )
