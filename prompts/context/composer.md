# PHP (Composer)

## Stack

- Symfony applications (HttpFoundation, Doctrine, Messenger, Serializer). Laravel,
  Laminas and other PHP frameworks are not used.
- Request input often reaches a controller as a DTO filled by a ParamConverter or
  the Serializer: follow the DTO back to the request, the taint scanner cannot.

## Test And Non-Production Paths

File names, PHP — the CamelCase suffix convention and PHPT tests:

- `*Test.*`
- `*Tests.*`
- `*TestCase.*`
- `*Spec.*`
- `*.phpt`

## Analysis

- Psalm resolves calls by type, not by name: always give a class fully qualified
  (`Symfony\Component\Yaml\Yaml`), never its short name.
- A project method that shares a library method's name is not the library's:
  `App\DateParser::parse` is not `Symfony\Component\Yaml\Yaml::parse`.
- Frameworks wire services through a container; a package they load by
  configuration never appears in an import.
- Installed packages are under `vendor/`.

## Where Symfony Turns a Feature On

A feature is on in production only if one of these names it:

- `config/bundles.php` — which bundles load, per environment.
- `config/packages/*.yaml` and `config/packages/prod/` — framework options:
  `framework.cache`, `framework.http_client`, `twig`, the authenticators under
  `security.firewalls` (`x509`, `form_login`, `remote_user`, ...).
- `config/services.yaml` — services, `decorates:`, tags such as `twig.extension`.
- Route annotations and attributes, `config/routes/` — `requirements`.
- Code — `new SomeClass(`, `->addExtension(`, `->setSecurityPolicy(`.

`config/packages/dev/`, `config/packages/test/`, `when@dev` and `when@test`
blocks, and bundles registered only for `dev`/`test`, are not production.

## What Symfony Reads, and From Where

- Routes exist only where `config/routes.yaml` or `config/routes/` imports
  them: the project's controllers (annotations, attributes) and the route
  files of bundles the project imports there. A bundle adds no route on its
  own, so every route and its `requirements` are in those files — read them
  instead of asking about "routes a bundle might register".
- The framework parses YAML only from the project's own files — `config/`,
  translations, validation and serializer mappings — while it builds the
  container and warms the cache. That is the developer's input. The Yaml
  component reaches attacker input only through the project's own
  `Yaml::parse`, `Yaml::parseFile` or `new Parser` over a request, an upload,
  a queue message or an HTTP response.
- A cache pool's adapter is set in `framework.cache` (or in a pool that
  configuration defines); with nothing set, the app cache is the filesystem.
  `PdoAdapter`, `RedisAdapter` and the rest exist only where that
  configuration names them. `driver: pdo_*` in `doctrine.yaml` is the
  database connection, not a cache adapter.

## Calls a Call Graph Misses

`call_user_func`, `call_user_func_array`, `new $class`, `$object->$method(`,
`__call`/`__callStatic`, and services resolved from the container by name.

Symfony calls these itself, so they have no call site:

- Event subscribers and listeners (`getSubscribedEvents`, `#[AsEventListener]`,
  the `kernel.event_listener` tag) — the event dispatcher calls them.
- Services a bundle defines in its own `Resources/config/` (authentication
  handlers, firewall listeners) — the container builds them and the framework
  calls them.
- Console commands — run through `bin/console`, and only when the bundle that
  registers them is loaded in production.
- Twig filters and functions — called from `.twig` templates by the filter
  name (`format_args`, `spaceless`), never by the PHP method name.
