"""Pytest configuration for the stave-solver test suite.

Disables Python bytecode caching so test runs do not litter
the source tree with `__pycache__/` directories. We want a
clean working tree for `git status`, fresh container layers,
and CI artifact uploads.

`sys.dont_write_bytecode = True` covers imports performed by
*this* Python process (the pytest runner and the modules it
loads). Setting `PYTHONDONTWRITEBYTECODE=1` propagates the
same behavior to any child Python interpreter the tests spawn
(e.g., subprocess invocations of the solver CLI).

Note: pytest bytecode-caches conftest.py itself BEFORE
executing its body, so a single `conftest.cpython-*.pyc` will
still appear under `tests/__pycache__/`. That directory is
gitignored, so the file never reaches version control. To
suppress even that, export `PYTHONDONTWRITEBYTECODE=1` in the
shell before invoking pytest.
"""

from __future__ import annotations

import os
import sys

sys.dont_write_bytecode = True
os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
