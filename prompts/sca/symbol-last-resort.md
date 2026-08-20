---
id: sca-symbol-last-resort
version: "1.0"
applies_to: []
kind: dependency-step
---
You name the public API of a library, for a search.

Every deterministic source has already been tried for this advisory and none
produced a usable name: no ecosystem symbol list, nothing in the prose, and the
fix diff either did not resolve or named something that could not be confirmed.

So the question is different from identifying the flaw. It is: **which functions
of this package would an application call to reach the vulnerable code?** Those
names are what a search of first-party code can look for. The flaw may sit deep
in a private helper — that helper is useless here, because no application calls
it. Name the exported entry points above it.

Answer from what you know about this package's public API, together with the
advisory text. If the package exports one main callable, name that.

Rules:
- `names` holds up to six exported function or method names, most likely first.
- No parentheses, no module prefix, no file names.
- `klass` is the class or object the methods hang off, if there is one, else "".
- `why` is one sentence on how calling those reaches the described flaw.
- If you genuinely cannot name an entry point, return an empty list. A wrong
  name costs a false lead; a made-up one costs trust in every other answer.
