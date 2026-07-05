"""Root pytest conftest — ensures the repo root is importable so tests can do
`from schema.ocsf import ...` regardless of the working directory pytest is
launched from."""
import os
import sys

_ROOT = os.path.dirname(os.path.abspath(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)
