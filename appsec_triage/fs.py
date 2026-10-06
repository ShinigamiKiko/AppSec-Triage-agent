"""What a walk over the target repository never descends into."""

# Installed dependencies, virtualenvs, VCS metadata and build output: none of it is
# the project's own code. A walk that needs more adds to this set, never copies it.
SKIP_DIRS = frozenset({".git", "vendor", "node_modules", "venv", ".venv", "target", "build", "dist", "__pycache__"})
