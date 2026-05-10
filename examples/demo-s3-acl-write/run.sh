#!/usr/bin/env bash
# S3 demo: ACL-Based Public Write
# Migrated from docs-content/demo/scenarios/acl-write/. Pure stave + python
# stdlib pipeline; no Docker required — the Codespaces devcontainer
# has every tool this script invokes.
set -uo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

obs="$script_dir/fixtures/observations"
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

fmt_section "Findings — ACL-Based Public Write"
# stave apply exits 3 when violations are found (expected here);
# capture output and continue.
"$stave_bin" apply --observations "$obs" \
    --now 2026-01-15T00:00:00Z --max-unsafe 168h --allow-unknown-input \
    --format json > "$tmp" 2>/dev/null || rc=$?
rc=${rc:-0}
if [ "$rc" -ne 0 ] && [ "$rc" -ne 3 ]; then
    echo "stave apply exited $rc (unexpected)" >&2
    exit "$rc"
fi
jq '{summary, status, controls: ([.findings[].control_id] | sort | unique), findings_count: (.findings | length)}' "$tmp"

fmt_section "Encoding — fact projection check"
"$stave_bin" export-sir --format jsonl --observations "$obs" \
    --now 2026-01-15T00:00:00Z > "$tmp" 2>/dev/null
python3 "$stave_root/examples/explain/verify_encoding.py" --strict \
    "$tmp" "$obs"
