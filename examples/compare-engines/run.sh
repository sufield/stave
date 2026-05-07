#!/usr/bin/env bash
# Multi-engine comparison harness convenience wrapper.
# Activates the venv where Clingo + pysat live, ensures
# Souffle from ~/.local/bin is on PATH, then runs compare.py
# with whatever args the caller passed.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)

# Make Souffle reachable if it lives in the user's local bin.
if [[ -x "$HOME/.local/bin/souffle" ]]; then
    export PATH="$HOME/.local/bin:$PATH"
fi

# Activate tools venv if present (for Clingo + pysat presence
# checks; the harness invokes the venv's python3 directly when
# running the engines themselves, but the available_check uses
# the venv's import resolution).
if [[ -f "$repo_root/.tools-venv/bin/activate" ]]; then
    # shellcheck disable=SC1091
    source "$repo_root/.tools-venv/bin/activate"
fi

python3 "$script_dir/compare.py" "$@"
