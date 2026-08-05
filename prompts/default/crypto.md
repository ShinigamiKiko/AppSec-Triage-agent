---
id: crypto
version: "3.0"
applies_to: ["CWE-327", "CWE-328", "CWE-326", "CWE-916", "CWE-780", "CWE-347",
             "CWE-295", "CWE-297", "CWE-298", "CWE-299", "CWE-599", "CWE-319"]
extends: base
includes: [_sanitizers]
---
## Broken / risky cryptography

Same trap as CWE-330: the algorithm alone does not decide. **What it protects** does.

| Evidence | Direction |
|---|---|
| MD5/SHA-1 hashing a **password** | `confirmed` |
| MD5/SHA-1 as a **checksum**, cache key, ETag, dedup fingerprint, test-file digest | `false_positive` — non-security use |
| MD5/SHA-1 verifying a **signature** or download integrity against tampering | `confirmed` |
| DES, 3DES, RC4, Blowfish for confidentiality | `confirmed` |
| ECB mode for anything longer than one block | `confirmed` |
| CBC with a **static or zero IV** | `confirmed` |
| CBC with a per-message random IV | `false_positive` on the IV question |
| RSA with PKCS#1 v1.5 padding for encryption | `confirmed` |
| RSA/OAEP, AES-GCM, ChaCha20-Poly1305 | `false_positive` — analyzer misfired |
| Key size < 2048 (RSA) / < 224 (EC) | `confirmed` |
| Password stored with a fast hash (no bcrypt/scrypt/argon2/PBKDF2) | `confirmed` |
| `verify=False`, `InsecureSkipVerify: true`, `CURLOPT_SSL_VERIFYPEER = 0`, trust-all `X509TrustManager`, `NSAllowsArbitraryLoads` | `confirmed` unless the path is a test fixture, then `unknown` |
| Plain `http://` for anything carrying credentials, tokens or updates | `confirmed` |
| JWT verified with `alg: none` or signature check skipped | `confirmed` |

### Certificate validation — the trap that caught a real reviewer

Disabled certificate validation is **transport security**. It has nothing to do with taint, user input, or where the URL came from. The following arguments are all invalid and must never appear in your reasoning:

* *"The URL is a hardcoded constant, not user-controlled."* Irrelevant. An attacker on the network path substitutes the response regardless of who chose the URL.
* *"It only fetches public data / a version file / a package index."* Still `confirmed`. Whoever controls that response controls what your program then parses and acts on.
* *"It's over HTTPS anyway."* HTTPS with `verify=False` is HTTPS with the authentication removed. It encrypts to whoever answers.
* *"There is probably a reason."* If a comment documents the reason, it is a `confirmed` finding with a documented risk acceptance, not a false positive.

The only path to `false_positive` here is evidence that validation is in fact enabled — a custom CA bundle passed on the same call, a session-level `verify=` set elsewhere and visible in the input, or a pinning implementation you were shown. If the finding is in a test fixture, answer `unknown`, not `false_positive`.

### Rules

If you cannot see what the hash output is used for → `unknown`, `INSUFFICIENT_CONTEXT`. "MD5 appears in the file" is not evidence of a vulnerability; quote the line showing the *use*.

Legacy interop (an explicit comment naming a protocol that mandates the weak primitive) does not make it a false positive — it is a `confirmed` finding with a documented risk acceptance. Say so in `reason` and set `requires_human_review: true`.
