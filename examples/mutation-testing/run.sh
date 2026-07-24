#!/usr/bin/env bash
# Demonstrate the mutation-testing framework on a Cognito
# safe-baseline fixture. Generates one mutation per boolean
# in the safe observation, runs `stave apply` on each, and
# reports KILLED / SURVIVED counts.
#
# Usage:
#   run.sh                  # default fixture: cognito-iteration2-unauth/remediated-config
#   run.sh <safe-obs-dir>   # any obs dir with bool-bearing assets

set -uo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"
# shellcheck source=../lib/raw_flag.sh
source "$example_root/lib/raw_flag.sh"
parse_raw_flag "$@"
set -- "${RAW_FLAG_ARGS[@]}"
safe_dir=${1:-$stave_root/examples/cognito-iteration2-unauth/fixtures/remediated-config/observations}

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin (run: cd $stave_root && make build)"
    exit 1
fi
if [[ ! -d "$safe_dir" ]]; then
    echo "safe observations directory not found: $safe_dir"
    exit 2
fi

if [[ "$FMT_RAW" != "1" ]]; then
    fmt_section "Mutation Testing — detection coverage on Cognito remediated baseline"
    fmt_kv "safe baseline" "$safe_dir"
fi

python3 "$script_dir/mutate.py" "$safe_dir" "$work_dir/mutations" 2>/dev/null
total_mutations=$(jq 'length' "$work_dir/mutations/manifest.json")
if [[ "$FMT_RAW" != "1" ]]; then
    fmt_kv "mutations generated" "$total_mutations (one per boolean leaf)"
    echo ""
fi

python3 "$script_dir/verify.py" "$stave_bin" "$safe_dir" "$work_dir/mutations" "$work_dir/report.json" 2>/dev/null

if [[ "$FMT_RAW" == "1" ]]; then
    cat "$work_dir/report.json"
    exit 0
fi

baseline=$(jq '.baseline_findings' "$work_dir/report.json")
killed=$(jq '.killed' "$work_dir/report.json")
survived=$(jq '.survived' "$work_dir/report.json")
score=$(jq '.mutation_score' "$work_dir/report.json")

fmt_block_header "Before — safe baseline"
fmt_findings "$baseline" "finding(s) on the unmutated observation"
echo ""

fmt_block_header "After — each mutation classified"
fmt_kv "total mutations" "$total_mutations"
fmt_kv "mutation score"  "$score (killed / total)"
printf '  %s%s killed%s — Stave fired a finding on the mutated observation\n' "$FMT_GREEN" "✓ $killed" "$FMT_RESET"
printf '  %s%s survived%s — no finding fired (compound predicate or coverage gap)\n' "$FMT_RED" "✗ $survived" "$FMT_RESET"
echo ""

if [[ "$killed" -gt 0 ]]; then
    mapfile -t killed_lines < <(jq -r '.killed_summary[] | "\(.path)  \(.before) → \(.after)  (Δ\(.delta) findings)"' "$work_dir/report.json")
    printf '  %sKilled mutations (Stave detected the change)%s\n' "$FMT_DIM" "$FMT_RESET"
    fmt_safe_list "${killed_lines[@]}"
    echo ""
fi
if [[ "$survived" -gt 0 ]]; then
    mapfile -t surv_lines < <(jq -r '.survivors[] | "\(.path)  \(.before) → \(.after)"' "$work_dir/report.json")
    printf '  %sSurviving mutations (no finding fired)%s\n' "$FMT_DIM" "$FMT_RESET"
    fmt_violations "${surv_lines[@]}"
    echo ""
fi

fmt_interpretation <<EOF
Mutation testing inverts the usual detection question. Instead
of "does Stave detect this configuration?" it asks "if I take
a known-safe configuration and break ONE thing, does Stave
notice?" Each surviving mutation is a property the framework
mutated but no control fired on — a candidate coverage gap
worth investigating.

Default baseline: cognito-iteration2-unauth/remediated-config —
an identity pool with allow_unauthenticated=false and 6
detail flags (unauth_role_broad, unauth_role_has_iam,
unauth_role_has_s3, unauth_role_has_ddb,
unauth_role_has_lambda, is_unauth_unused) all set safely.

The 1 KILL: flipping access.allow_unauthenticated false → true
trips CTL.COGNITO.IDENTITY.GUEST.001. That control reads only
the gate flag, so a single-property flip catches it.

The 6 SURVIVALS reveal a deliberate catalog-design pattern:
the detail controls (UNAUTH.S3, UNAUTH.IAM, etc.) all use
gate-AND-detail compound predicates — they require
allow_unauthenticated=true AS WELL AS their specific detail
boolean. Flipping the detail in isolation can't trip the
predicate because the gate stays false. That is intentional:
the catalog avoids false positives on partial misconfigurations
where guest access is off but a leftover detail flag is set.

So the 6 survivors are not coverage gaps — they're the
structural limit of single-property mutation testing. To kill
them you need pair-wise mutations (gate-flip + one detail
flip), which is exponential in property count and out of
scope for the MVP framework. The framework correctly surfaces
the limit without attempting to fix it.

In an AWS workflow: a catalog author adds a new control. They
run mutation testing against a clean fixture in their service
domain. A surviving mutation on a property the new control
should detect IS a real coverage gap; the framework names the
property and the operator (flip-boolean) so the author can
extend the predicate or add an additional control. A mutation
score that drops over time signals catalog drift — controls
that used to detect changes have stopped firing because some
upstream property shape changed.
EOF
