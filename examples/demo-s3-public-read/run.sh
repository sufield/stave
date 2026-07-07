#!/usr/bin/env bash
# S3 demo: Public Read via Bucket Policy
# Migrated from docs-content/demo/scenarios/public-read/. Pure stave + python
# stdlib pipeline; no Docker required — the Codespaces devcontainer
# has every tool this script invokes.
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
# Workspace fallback: when the script lives outside a built
# repo (e.g. the Coder image installs the binary at
# /usr/local/bin/stave), fall back to the one on PATH.
[ -x "${stave_bin}" ] || stave_bin="$(command -v stave || echo "${stave_bin}")"
# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

obs="$script_dir/fixtures/observations"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

fmt_section "Findings — Public Read via Bucket Policy"
# stave apply exits 3 when violations are found (expected here);
# capture output and continue.
"$stave_bin" apply --observations "$obs" \
    --eval-time 2026-01-15T00:00:00Z --max-unsafe 168h \
    --format json > "$tmp" 2>/dev/null || rc=$?
rc=${rc:-0}
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    echo "stave apply exited $rc (unexpected)" >&2
    exit "$rc"
fi
jq '{summary, status, controls: ([.findings[].control_id] | sort | unique), findings_count: (.findings | length)}' "$tmp"

fmt_section "Encoding — fact projection check"
"$stave_bin" export-sir --format jsonl --observations "$obs" \
    --eval-time 2026-01-15T00:00:00Z > "$tmp" 2>/dev/null
python3 "$stave_root/examples/explain/verify_encoding.py" --strict \
    "$tmp" "$obs"
