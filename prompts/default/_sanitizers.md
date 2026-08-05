---
id: _sanitizers
version: "1.0"
applies_to: []
shared: true
---
## Is the defence actually effective?

"Something filters the value" is not a verdict. Three different mechanisms get confused with each other, and only one of them removes the danger completely.

| Mechanism | What it does | Removes the danger? |
|---|---|---|
| **Parameterisation** | The value never enters the code/query text; the engine receives it separately. | Yes, completely. |
| **Validation** | The value is checked against a rule before use. | Only if the rule excludes every attack string. |
| **Escaping / encoding** | Dangerous characters are neutralised *for one specific context*. | Only in that exact context. |

### Validation: allowlist works, blocklist does not

**Allowlist — effective.** The value is constrained to a set that cannot express the attack:

- `is_numeric()`, `ctype_digit()`, `(int)$x`, `intval()`, `parseInt(x, 10)` — the result is a number, and a number cannot carry a quote, a semicolon or a shell metacharacter.
- Membership in an enum or a fixed array of permitted values.
- An **anchored** regex: `^[a-z0-9_]{1,32}$`. Anchors are what make it an allowlist — `/[a-z]+/` without `^…$` matches a substring and permits everything around it.
- A cast to a typed value: UUID parse, date parse, enum parse.

**Blocklist — not effective.** Removing or rejecting specific bad characters:

- `str_replace(['&&', ';'], '', $x)` — bypassed with `&`, `|`, a newline, `$(...)`, backticks, `%0a`.
- Stripping `<script>` — bypassed with `<img onerror=>`, `<svg onload=>`, case and encoding tricks.
- Blocking `../` — bypassed with `....//`, `..%2f`, absolute paths, unicode.

A blocklist is evidence the author *knew* about the risk, not evidence the risk is gone. When you see one, the verdict leans `confirmed`, not `false_positive`. If you cannot demonstrate a bypass, `unknown` is honest — but never `false_positive` on a blocklist alone.

### Escaping is bound to one context

An encoder is correct for the context it was written for and useless everywhere else:

| Function | Correct for | Useless for |
|---|---|---|
| `htmlspecialchars`, `htmlentities`, template auto-escaping | HTML body / attribute | SQL, shell, JS strings, URLs |
| `mysqli_real_escape_string`, `addslashes` | a value **inside quotes** in SQL | a value used unquoted (numeric context); shell; HTML |
| `escapeshellarg` | one shell argument | the command name itself; SQL |
| `escapeshellcmd` | weak — escapes some metacharacters, leaves argument injection open | anything where correctness matters |
| `encodeURIComponent`, `urlencode` | a URL query value | HTML, SQL, shell |
| `JSON.stringify` | a JS value | HTML — `</script>` still terminates the block |

Escaping into the wrong context is the same as no escaping at all. Name the context in your reasoning.

### Two things that invalidate any defence

**Order.** The check must happen *after* the last untrusted assignment and *before* the sink. Sanitising and then concatenating more input is not sanitising. Quote both lines if you see this.

**Path.** The defence must be on the path the analyzer reported. A validation in a different branch, a different method, or an `if` the code can skip does not protect the reported flow.

### How to write the verdict

- Defence is parameterisation, or an allowlist that excludes the attack → `false_positive`, `SANITIZED_DATAFLOW`. Quote the defence.
- Defence is a blocklist, or escaping for the wrong context, or applied before further concatenation → `confirmed`, and say which of the three it is.
- A defence exists but you cannot see enough to judge its coverage → `unknown`. Do not resolve it by assuming the author got it right.
