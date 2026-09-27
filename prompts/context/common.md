# Project Context

This context is attached to every model request, together with the part for each
ecosystem listed in `APPSEC_ECOSYSTEMS` (`npm.md`, `go.md`, ... in this directory).
It is not a replacement for the system prompt. Use it to avoid spending analysis
on technologies and deployment modes that are outside this project, but always
prefer concrete evidence from the finding and repository over assumptions here.

## Platform

- Linux (Alpine) containers; deployment may run on Kubernetes.
- docker-compose files describe a developer's machine, not the production
  deployment. A finding in one is a false positive, and nothing read from one
  (`--host`, debug ports, local databases) says anything about production.

## Not Applicable Unless Repository Evidence Says Otherwise

- SSH server or SSH client functionality.
- Kubernetes API client functionality. Kubernetes is a deployment platform,
  not an application dependency.
- MongoDB, Elasticsearch, Kafka, gRPC, and GraphQL.
- Windows-only runtime behavior.
- Docker SDK or Docker Engine API calls from the application.
- TLS termination handled by the application itself when TLS is terminated at
  the ingress.
- Advanced x509 policy-mapping, ECH, or PSK-specific behavior without a direct
  call/configuration in the repository.

## Test And Non-Production Paths

Code under the paths below is test code, not production code. Findings there are
test-scope findings: treat them as false positives unless the evidence explicitly
shows that the test code is shipped or invoked by production code. A dependency
imported only from these paths is not used by the shipped application.

This list is also read by the agent's own code — the dependency search, the
CodeQL import gate, the condition search and the SAST heuristics use exactly
these patterns, from this file and every ecosystem file next to it, whatever
`APPSEC_ECOSYSTEMS` says. Edit them here, and only here. A pattern ending in `/`
is a directory name matched against any segment of a path; any other pattern is
a file-name glob. The language-specific patterns live in the ecosystem files.

Only conventions the whole language or its standard test runner uses belong
here. Every pattern added makes more code count as test code, which makes a
closure easier to reach — a name one project happens to use is not a reason to
widen the list for everybody.

Directories, any ecosystem:

- `test/`
- `tests/`
- `testing/`
- `spec/`
- `specs/`
- `fixture/`
- `fixtures/`
- `mocks/`
- `e2e/`
- `features/`

File names, any ecosystem:

- `*.feature`

## Triage Rules

- A dependency being present is not enough: check version, actual use, call
  reachability, and the advisory precondition.
- A govulncheck or Wolfee closure is strong evidence, but an LLM audit must
  still consider reflection, callbacks, interface dispatch, generated code,
  plugins, and build constraints.
- A reachable call is not automatically exploitable. Check whether attacker
  controlled input reaches the vulnerable operation and whether deployment
  conditions required by the advisory are present.
- OSV, EPSS, and CISA KEV data are supporting evidence. A network timeout is
  missing evidence, not evidence that the vulnerability is absent.
- An opt-in feature — a sandbox, a security policy, an adapter, an
  authenticator, a decorator, a client wrapper, a route option — is on only when
  the project's own code or configuration turns it on. Installed packages do not
  switch on another package's features behind the project's back. When a search
  of the project's code and configuration finds no name that would turn the
  feature on, the feature is off: that is a checked absence and a valid reason to
  close, not missing context. Never keep a finding open, or list as missing
  information, that the feature "might be enabled somewhere the search did not
  cover".
- Values the deployment sets — environment variables, `.env` files, service
  configuration, secrets, endpoints of the organisation's own services — belong to
  the operator, not to an attacker. A flaw that needs attacker control of such a
  value is not exploitable through it, unless repository evidence shows the value
  is built from request data.
- A flaw that fires only when a third-party infrastructure component misbehaves —
  a malicious or compromised message broker, database server, cache, object store,
  mail server, registry or other service the application connects to — is a false
  positive: those components belong to the operator, like the values the
  deployment sets. The exception is a component whose address comes from request
  data, where the application connects wherever the user says: then the attacker
  is the server.
- Before you confirm a flaw that fires in a client — an HTTP, HTTP/2 or TLS
  client, a certificate check, a parser of responses — name who sends the bytes
  it fires on. When that is a service the application calls at an address from
  its own configuration — another company's API, the organisation's own service,
  a broker, a database, an object store — the answer is `false_positive`: the
  service belongs to the operator, and so does everything it sends back —
  response bodies, headers, redirects, TLS certificates. A call path from the
  application's code to that client proves the client runs, not that an
  attacker feeds it. The exception is again an address taken from request data.
- `unknown` is not an answer when what is left is decided by the rules above. If
  the facts you have gathered show that the remaining condition needs an attacker
  to control a value the operator sets (configuration, environment), needs a
  third-party infrastructure component or external service to misbehave, or is
  checked absent in the code, answer `false_positive` and name that fact. A value
  the operator sets closes nothing when the flaw needs only that the value be on:
  an operator who switched the vulnerable mode on made that part of the condition
  hold, and the rest of the condition still has to be checked. Writing
  "exploitation cannot be confirmed" while stating the very fact that closes it
  leaves a person to repeat your work.
- A condition with several parts ("a route declares an alternation requirement
  and an untrusted value reaches the URL generator") fails as soon as one
  required part is checked absent. Do not keep a finding open to establish the
  other parts: with no such route, what reaches the URL generator no longer
  matters.
- A framework calls the code it registers: an event listener or subscriber, a
  handler or service named in configuration, a console command, a template
  filter or function. A package that only names such a class, and never calls
  the method, still reaches it — "the parent never calls it" is not "not
  called". Decide by whether the registration is active in production, not by
  whether a call site exists.
