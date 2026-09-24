# PHP (Composer)

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

## Calls a Call Graph Misses

`call_user_func`, `call_user_func_array`, `new $class`, `$object->$method(`,
`__call`/`__callStatic`, and services resolved from the container by name.
