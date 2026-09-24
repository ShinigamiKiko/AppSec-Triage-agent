# C# (NuGet)

## Test And Non-Production Paths

File names, C# — the CamelCase suffix convention:

- `*Test.*`
- `*Tests.*`
- `*TestCase.*`
- `*Spec.*`

## Calls a Call Graph Misses

`Type.GetType`, `Activator.CreateInstance`, `MethodInfo.Invoke`, and services a
container resolves by configuration.
