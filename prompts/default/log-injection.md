---
id: log-injection
version: "1.0"
applies_to: ["CWE-117", "CWE-93", "CWE-116"]
extends: base
includes: [_sanitizers]
---
## Log injection — the taint path is not the question

Writing user input to a log is what every application does, all day. So "does
untrusted input reach the log call" is answered `yes` on nearly every finding of
this class and decides nothing. Measured on a real Go project: given only that
question, 33 of 45 findings came back `confirmed`, which is not triage — it is
the scanner's output restated.

What decides it is whether the attacker can **forge or alter a log record**, and
whether anything downstream is hurt by that. Work these three questions in
order, and quote the code for each.

### 1. Can the injected text break out of its field?

This is the whole vulnerability, and it turns on the log call, not the input.

* **Plain-text logging** — `log.Printf`, `fmt.Fprintf(logfile, ...)`,
  `logger.info(f"...")`, string concatenation into a message. One record is one
  line, so a `\n` in the value starts a second record that looks genuine. This
  is forgeable: say so and quote the call.
* **Structured logging** — `slog.Info("msg", "key", value)`, `zap.String(...)`,
  `logrus.WithField(...)`, `logger.info("msg", extra={...})`, anything emitting
  JSON or logfmt. The encoder escapes control characters inside the field, so a
  newline stays inside the value and forges nothing. That is a *named defence*:
  quote the call and close it as `SANITIZED_DATAFLOW`.
* If the value is passed as a **format argument** (`%s`, `{}`) into a plain-text
  writer, it is still plain text — the placeholder is not an escape.

### 2. Was the value already constrained before it got there?

A value that cannot contain a newline cannot forge a record. These are genuine
closures when you can quote them: an integer, a UUID, an enum or a value checked
against a fixed set, a database identifier, a length-bounded token matched by a
character-class regex. A cache key assembled from such parts is likewise
constrained — but only if you can see the parts.

Do **not** treat "it comes from JSON" or "it went through a struct field" as a
constraint. Neither restricts the characters.

### 3. Who reads the log, and does the evidence say?

This is what separates a real finding from a note.

* Forged records in a log a SIEM parses, or that is used for audit or billing —
  real, and worth confirming.
* A log rendered into a web page or dashboard without escaping — that is XSS by
  another route, and worth confirming.
* A developer-facing debug line that nothing parses — technically forgeable and
  practically inert.

If the evidence does not say who consumes the log, do not invent an answer and
do not assume the worst. Confirm on the strength of steps 1 and 2, and put the
consumer question in `blocking_question` so the reviewer settles it.

### Deciding

| Evidence | Verdict |
|---|---|
| Structured logger encodes the field | `false_positive`, `SANITIZED_DATAFLOW` — quote the call |
| Value is typed or validated so it cannot hold a newline | `false_positive` — quote the constraint |
| Plain-text log call, unconstrained attacker-controlled string | `confirmed`, `EXPLOITABLE_DATAFLOW` |
| Plain-text call, but the trace does not reach the value's origin | `unknown` — name the missing leg |

`vulnerable_symbol` is the **log call**, kind `sink` — not the variable and not
the HTTP handler. The fix goes there: escape the value or move to a structured
logger, and that is what belongs in `reason`.

### On truncated traces

A trace may arrive with middle steps omitted; the first and last steps are kept
because they are the source and the sink. Missing middle steps are not grounds
for `unknown` on their own — steps 1 and 2 are answered from the sink and the
value, both of which you can see. Abstain when the *origin* is genuinely
unknown, not merely when the path is long.
