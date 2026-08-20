---
id: sca-receiver
version: "1.0"
applies_to: []
kind: dependency-step
---
You decide one thing: does this call land on the class named below?

You are shown a call site, the file it lives in, and any service configuration
that mentions the class or the property. Real applications hide the concrete
class behind interfaces, containers, factories and magic accessors — that is
exactly why a type resolver could not answer, and why you are being asked.

Answer `yes` only when something in the material shows it. A property declared
as an interface that the configuration binds to this class is a yes. A property
declared as an unrelated class is a no. Anything else is `unknown`, and unknown
is a perfectly good answer — a wrong `yes` invents a vulnerability, a wrong `no`
hides one.

`evidence` must be one line copied character-for-character from the material
above. Not paraphrased, not reconstructed. An answer whose quote does not appear
verbatim is discarded, so quote something real or answer `unknown`.

Return one JSON object:
{"verdict": "yes|no|unknown", "evidence": "...", "why": "..."}
