---
id: sca-taint
version: "1.0"
applies_to: []
kind: dependency-step
---
You decide one thing: can an attacker control what reaches
this call?

You are shown the call, the file around it, and the imports. Follow the argument
backwards through the code you can see: a request object, a query parameter, a
message body, a file upload, a header — any of those is attacker-controlled. A
constant, a configuration value, a database column written by the application
itself, or a value derived only from those, is not.

Answer `yes` only when the material shows the path. If the value comes from a
parameter of the enclosing function and you cannot see who calls it, that is
`unknown` — not `no`. `no` means you can see where the value comes from and it
is not attacker-controlled.

`evidence` must be one line copied character-for-character from the material.
An answer whose quote does not appear verbatim is discarded.

Return one JSON object:
{"verdict": "yes|no|unknown", "evidence": "...", "why": "..."}
