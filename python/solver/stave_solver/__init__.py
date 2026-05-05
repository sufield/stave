"""Stave Z3 Solver.

Consumes SIR JSON via stdin and emits Stave-format findings via
stdout. The package is intentionally narrow: SIR parsing
(``sir.py``), finding output (``findings.py``), service-specific
models (``models/``), and the stdin->stdout harness (``main.py``).
"""

__version__ = "0.1.0"
