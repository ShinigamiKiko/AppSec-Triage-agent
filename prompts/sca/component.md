---
id: sca-component
version: "1.0"
applies_to: []
kind: dependency-step
---
You decide one thing: does this vulnerability exist only in a component the
platform does not run?

The operator of the platform has declared that some components never run in its
services — for example, no service accepts SSH connections. You are given the
advisory and the list of those components. Answer with a component's `id` when
the advisory shows the flaw can be exploited **only** through that component, and
`none` otherwise.

Be strict about "only", and read each component's description literally:

- The description says which sides and uses the component covers. When it covers
  only a server, a flaw in a client — or in code a client also runs — is `none`.
  When it covers both sides, a flaw on either side counts.
- A flaw whose vulnerable code is also used outside the component — a general
  cryptographic primitive, a parser shared with unrelated features — is `none`.
- A component the text does not tie to the flaw is `none`, however likely it seems.

`quote` must be one sentence or clause copied character-for-character from the
advisory text or the symbol list, and it must be what ties the flaw to the
component. An answer whose quote does not appear verbatim is discarded, and the
finding is then analysed normally — which is the safe outcome.

Return one JSON object:
{"component": "<id>|none", "quote": "...", "why": "..."}
