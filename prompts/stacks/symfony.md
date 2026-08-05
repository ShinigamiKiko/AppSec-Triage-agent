---
id: symfony
version: "1.0"
name: Symfony / Doctrine (PHP)
detect:
  files: ["composer.json", "composer.lock"]
  contains:
    - "symfony/framework-bundle"
    - "symfony/http-kernel"
    - "doctrine/orm"
---
**Configuration placeholders.** `%env(VAR)%`, `%env(resolve:VAR)%`, `%env(int:VAR)%` and
`%kernel.project_dir%` are resolved when the container is compiled. The literal in the YAML is a
reference, never a secret — the value lives in the environment. Same for `%parameter.name%`.

**Where secrets actually live.** A committed `.env` is documented Symfony practice for *non-secret
defaults*; the file itself usually says so. Real values go in `.env.local`, `.env.$APP_ENV.local`
or the vault, all of which are gitignored. So:
- a credential-looking value in `.env` or `.env.dist` → usually a development default
- the same in `.env.local`, `.env.prod.local`, or a deployed `secrets/` bundle → judge it on its merits
- `APP_SECRET` in a committed `.env` is a development value, but if it is high-entropy and the file
  is `.env.prod`, say so rather than closing it

**Doctrine.** `?` and `:name` are bound parameters — safe regardless of what the value contains.
`createNativeQuery($sql, $rsm)` and `executeQuery($sql, $params)` take raw SQL, so the question is
only ever whether anything was interpolated into `$sql` *before* the call. A `{$where}` fragment
built from a fixed list of hardcoded conditions is safe; a fragment built from request input is not.
Doctrine cannot bind table or column *names* — those get interpolated, and that is where real
injections live.

**Type mappings are not credentials.** `types: { foo: 'App\Doctrine\Type\FooType' }` in
`doctrine.yaml` is a class name. Fully-qualified class names look high-entropy and are never secrets.

**Twig.** Auto-escaping is on by default for HTML context. `{{ value }}` is escaped;
`{{ value|raw }}`, `{% autoescape false %}` and `|json_encode` into an inline `<script>` are the
places to look.

**Request input.** Untrusted sources are `$request->query`, `$request->request`,
`$request->getContent()`, `$request->headers`, `$request->cookies`, route parameters via
`$request->attributes`, and anything deserialized from them. `$request->attributes` also carries
framework-set values (`_route`, `_controller`) which are not user input.

**Validation and serialization.** A DTO with `#[Assert\...]` constraints, or an API Platform input
transformer, means the value was validated — but validation constrains *shape*, not safety. A
`#[Assert\NotBlank]` string is still a string an attacker chose.

**Security.** `#[IsGranted]`, voters and `security.yaml` `access_control` govern authorisation.
A controller with no access control is only a finding if the route is not covered by a firewall
pattern — check `security.yaml` before asserting it.
