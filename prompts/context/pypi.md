# Python (PyPI)

## Test And Non-Production Paths

File names, Python:

- `*_test.py`
- `test_*.py`
- `conftest.py`

## Calls a Call Graph Misses

`getattr`, `__import__`, `importlib.import_module`, `eval`, `exec`, and entry points
a framework loads from settings by dotted name.
