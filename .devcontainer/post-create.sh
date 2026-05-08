#!/usr/bin/env bash
# Codespaces post-create: build Stave once, provision the Python tools venv
# at the location the engine harness expects (parent of the stave/ checkout).
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
stave_root=$(cd "$script_dir/.." && pwd)
repo_root=$(cd "$stave_root/.." && pwd)
venv_dir="$repo_root/.tools-venv"

echo "[stave devcontainer] stave_root=$stave_root"
echo "[stave devcontainer] venv_dir=$venv_dir"

if [[ ! -d "$venv_dir" ]]; then
    python3 -m venv "$venv_dir"
fi
"$venv_dir/bin/pip" install --upgrade --quiet pip
"$venv_dir/bin/pip" install --quiet clingo python-sat pyyaml

echo "[stave devcontainer] building stave binary"
( cd "$stave_root" && make build )

echo "[stave devcontainer] verifying engine availability"
"$stave_root/cmd/stave/stave" --version || true
z3 --version
cvc5 --version | head -1
swipl --version
command -v souffle && souffle --version | head -1 || echo "souffle: not installed (non-amd64 host)"
"$venv_dir/bin/python3" -c 'import clingo, pysat, yaml; print("python deps:", clingo.__version__, "clingo |", "pysat ok |", yaml.__version__)'

echo "[stave devcontainer] ready"
