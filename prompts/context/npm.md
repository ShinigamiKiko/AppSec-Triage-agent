# JavaScript and TypeScript (npm)

## Stack

- JavaScript/TypeScript on Node.js. Front-end code is bundled and runs in the
  user's browser; only the server entry and what it loads run in Node.
- Development tooling — bundlers and their dev servers, compilers, linters,
  test runners — runs on developer machines and in CI. It is part of the running
  application only where the server's production code path loads it.

## Test And Non-Production Paths

Directories, JavaScript and TypeScript:

- `__tests__/`
- `__mocks__/`
- `__fixtures__/`
- `__snapshots__/`
- `cypress/`

File names, JavaScript and TypeScript:

- `*.test.*`
- `*.spec.*`
- `*-test.*`
- `*-spec.*`
- `*.cy.*`
- `*.stories.*`

## Analysis

- CodeQL (JavaScript/TypeScript) resolves calls through a package's own exports:
  `require`, `import`, destructuring, per-function modules such as `lodash/template`.
- Installed packages are under `node_modules/`; a parent's source is readable there.

## Calls a Call Graph Misses

When checking a "not reached" closure, look for: `require(` or `import(` with a
variable, `eval`, `new Function(`, calls through a computed property (`obj[name](`),
and code a bundler or plugin loads by configuration.
