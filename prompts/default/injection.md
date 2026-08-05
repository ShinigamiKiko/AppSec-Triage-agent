---
id: injection
version: "3.0"
applies_to: ["CWE-89", "CWE-78", "CWE-79", "CWE-77", "CWE-90", "CWE-91", "CWE-611", "CWE-643", "CWE-917"]
extends: base
includes: [_sanitizers]
---
## Injection family — the verdict rests on the dataflow, not the sink

A dangerous sink is not a vulnerability. **Untrusted source → dangerous sink → no effective sanitizer** is a vulnerability. If any of the three legs is missing from the evidence, you cannot confirm.

### Quoting is not parameterisation — read this before anything else

This is the single most common way to get an injection verdict wrong, measured on a labelled corpus: seven vulnerable queries were closed as false positives on exactly this reasoning.

```
"SELECT first_name FROM users WHERE user_id = '$id';"
```

The quotes around `$id` are **characters in the SQL text**, not a binding. The value is pasted into the query before the database ever sees it, and an attacker who supplies `' OR '1'='1` closes your quote and continues writing SQL. If you find yourself writing "the variable is properly quoted, so it is safe" — stop. That sentence is always wrong.

Parameterisation means **the value never becomes part of the SQL text**:

| Form | Parameterised? |
|---|---|
| `"... WHERE id = '$id'"` then `mysqli_query($c, $q)` | **No.** String interpolation. |
| `"... WHERE id = " . $id` then `->query($q)` | **No.** Concatenation. |
| `f"... WHERE id = {id}"`, `` `...${id}...` ``, `"...#{id}..."` | **No.** Same thing in Python, JS, Ruby. |
| `prepare("... WHERE id = ?")` + `bind_param`/`execute([$id])` | Yes. |
| `prepare("... WHERE id = :id")` + named binding | Yes. |
| ORM query builder passing values as arguments | Yes. |

**`mysqli_query`, `->query()`, `exec()` and `createNativeQuery()` execute a finished string.** They cannot be parameterised, whatever that string looks like. Seeing `prepare` in the *name* of a function is not enough — the placeholders and the bind call have to be there.

**Escaping is not parameterisation either.** `mysqli_real_escape_string`, `addslashes` and friends escape quote characters. That helps only when the value sits inside quotes *and* the connection charset is right. When the value is interpolated in a numeric context — `WHERE user_id = $id`, no quotes — escaping does nothing at all, because the attacker never needs a quote.

### Step order for this class

1. **Is the source actually untrusted?** HTTP request/header/cookie/body, CLI arg, file upload, message-queue payload, third-party API response → untrusted. A compile-time constant, an enum, an internal ID from your own DB, a value from a config file → trusted.
2. **Is the sink actually dangerous in this form?** A parameterized query with `?`/`:name` placeholders is not injectable even if built nearby. String concatenation into the query/command/template is.
3. **Is there an effective sanitizer on the reported path?** Effective means: correct for *this* sink (HTML-escaping does not stop SQL injection), applied *after* the last untrusted assignment, and not bypassable by the reported input.

### Rules

| Evidence | Direction |
|---|---|
| Concatenated user input into SQL string | `confirmed` / `EXPLOITABLE_DATAFLOW` |
| Prepared statement, ORM query builder, bound parameters | `false_positive` / `SANITIZED_DATAFLOW` |
| Table/column name interpolated from an allowlist | `false_positive` — quote the allowlist |
| Table/column name interpolated from request input | `confirmed` — placeholders cannot bind identifiers |
| `exec`/`system` with a shell string built from input | `confirmed` |
| `execve`-style array argv, no shell | `false_positive` unless argv[0] is attacker-controlled |
| Output encoded by the template engine's auto-escaping | `false_positive` — name the engine in evidence |
| `\|safe`, `dangerouslySetInnerHTML`, `v-html`, `.innerHTML =` on user input | `confirmed` |
| XML parser with `DTD`/external entities explicitly disabled | `false_positive` |
| Sanitizer present but applied **before** further concatenation | `confirmed` — order matters, quote both lines |

### Trace discipline

The `TRACE` section is the only dataflow you may reason about. If the trace stops before reaching a sink, or the sanitizer status is `not reported`, the honest answer is `unknown` with `"sanitizer status not reported"` in `missing_information`. Never assume a framework sanitizes by default; say you cannot see it.
