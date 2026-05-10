#!/usr/bin/env bash
# Run compile_requirements.py + Z3 against a requirements.yaml.
# Reports COMPATIBLE (SAT — every requirement holds in some
# model) or CONTRADICTORY (UNSAT — unsat core names the
# conflicting subset).
#
# Usage:
#   run.sh                        # runs both bundled fixtures
#   run.sh path/to/requirements.yaml

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

if ! command -v z3 >/dev/null 2>&1; then
    echo "z3 not found on PATH (sudo apt install z3 | brew install z3)"
    exit 1
fi

run_one() {
    local req_file=$1
    local label
    label=$(basename "$(dirname "$req_file")")
    local query result
    query=$(mktemp --suffix=.smt2)
    result=$(mktemp)
    trap 'rm -f "$query" "$result"' RETURN

    fmt_block_header "Scenario — $label"
    python3 "$script_dir/compile_requirements.py" "$req_file" "$query" 2>&1 | sed 's/^/  /'
    z3 "$query" > "$result" 2>&1 || true

    local verdict
    verdict=$(head -1 "$result" | tr -d '[:space:]')
    case "$verdict" in
        sat)
            printf '  %s%s%s — every requirement holds in at least one model\n' \
                "$FMT_GREEN" "✓ COMPATIBLE (sat)" "$FMT_RESET"
            ;;
        unsat)
            printf '  %s%s%s — no configuration satisfies every requirement\n' \
                "$FMT_RED" "✗ CONTRADICTORY (unsat)" "$FMT_RESET"
            local core
            core=$(tail -n +2 "$result" | tr '\n' ' ' | sed 's/^[[:space:]]*(//; s/)[[:space:]]*$//')
            if [[ -n "$core" ]]; then
                printf '    %sunsat core (named):%s %s\n' "$FMT_DIM" "$FMT_RESET" "$core"
            fi
            ;;
        *)
            printf '  %s%s%s — z3 returned: %s\n' "$FMT_YELLOW" "? INCONCLUSIVE" "$FMT_RESET" "$verdict"
            ;;
    esac
    echo ""

    python3 "$script_dir/translate_core.py" "$req_file" "$result" | sed 's/^/  /'
    echo ""
}

if [[ $# -eq 0 ]]; then
    fmt_section "Compatibility Check — contradictory-requirements detection via Z3 unsat core"

    run_one "$script_dir/fixtures/compatible-requirements/requirements.yaml"
    run_one "$script_dir/fixtures/contradictory-requirements/requirements.yaml"

    fmt_interpretation <<'EOF'
The compatibility-check tool answers "can these requirements
all hold simultaneously?" by compiling them into one Z3 query
with named (! ... :named id) assertions, then asking
(check-sat).

Two scenarios bundled:

Scenario 1 (compatible-requirements): HIPAA "PHI never public"
+ business "marketing public via CloudFront". Both
requirements scope to different mechanisms — bucket ACL vs
CDN edge cache. Z3 finds a model where the bucket ACL is
private (HIPAA holds) AND CloudFront serves the marketing
content (business holds). SAT → COMPATIBLE.

Scenario 2 (contradictory-requirements): HIPAA "PHI never
public" + business "marketing public" + ops "identical PAB
across account". Three independently-defensible policies.
Together: if marketing must be public AND every bucket has
the same PAB AND PHI is in the same account → PHI is
necessarily public too → HIPAA violated. Z3 returns UNSAT;
(get-unsat-core) names the minimal conflicting subset:
PHI_BUCKET_EXISTS + PHI_MUST_NOT_BE_PUBLIC +
MARKETING_MUST_BE_PUBLIC + IDENTICAL_PAB.

In an AWS workflow: a security architect drafts new
requirements (HIPAA, business, ops). Before implementing them,
they run this tool. The contradictory case fails fast — the
architect rewrites one requirement (e.g. exempt marketing from
identical-PAB, or move marketing to its own account) BEFORE
deployment teams discover the contradiction through failed
configurations. The compatible case proves the requirements
can coexist; the model is a witness configuration the
implementation can target.
EOF
else
    fmt_section "Compatibility Check"
    run_one "$1"
fi
