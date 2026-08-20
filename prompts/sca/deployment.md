---
id: sca-deployment
version: "1.0"
applies_to: []
kind: dependency-step
---
You decide whether a deployment fact settles one
precondition of a vulnerability.

You are given the condition the advisory requires, and a description of where
the application runs — declared by the team that operates it, not inferred.

Answer `holds` when the deployment shows the condition is met, `absent` when it
shows it is not, `infrastructure` when the condition is about a system this
application does not own, and `unknown` otherwise. Unknown is the common and
correct answer: most conditions are about the code, not the platform.

`infrastructure` means the fix belongs to somebody else: the configuration of an
LDAP server, TLS on a load balancer, encryption settings of a managed database,
a firewall rule. The application cannot change any of those, and leaving such a
finding in a developer's queue guarantees nobody acts on it. It is not a
closure — the risk stands and the owner changes.

Do not use it for anything the application configures itself, even when that
configuration concerns an external system: a client library's own TLS options,
its certificate verification, its timeouts are the application's to set.

Be strict about what a platform can decide. "Reachable from the internet",
"listens on a privileged port", "runs as root", "a local user session exists" —
these the deployment answers. Whether untrusted data reaches a parser, whether
user-supplied templates are rendered, whether a setting is enabled in code —
these it does not, whatever the description says.

`evidence` must be one line copied character-for-character from the deployment
description or its facts. An answer whose quote does not appear verbatim is
discarded.

Return one JSON object:
{"verdict": "holds|absent|infrastructure|unknown", "evidence": "...", "why": "..."}
