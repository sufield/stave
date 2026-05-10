#!/usr/bin/env bash
# Demonstrate the encoding-report pipeline: stave export-sir
# produces JSONL, format_facts.py renders it as a per-asset
# human-readable summary in cloud-security language.
#
# Default fixture: cognito-iteration2-unauth/cross-resource-config
# (an identity pool, a PHI bucket, a marketing bucket — three
# assets, ~30 encoded facts). Pass any observation directory as
# $1 to render its encoding instead.
#
# Read the output to verify "did Stave understand my
# configuration?" without reading SMT-LIB or Go source.

set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
example_root=$(cd "$script_dir/.." && pwd)
stave_root=$(cd "$example_root/.." && pwd)
stave_bin=${STAVE_BIN:-$stave_root/stave}
default_fixture="$stave_root/examples/cognito-iteration2-unauth/fixtures/cross-resource-config/observations"
obs_dir=${1:-$default_fixture}

# shellcheck source=../lib/format.sh
source "$example_root/lib/format.sh"

if [[ ! -x "$stave_bin" ]]; then
    echo "stave binary not found at $stave_bin (run: cd $stave_root && make build)"
    exit 1
fi
if [[ ! -d "$obs_dir" ]]; then
    echo "observations directory not found: $obs_dir"
    exit 2
fi

fmt_section "Encoding Report — what Stave extracted from the observations"
fmt_kv "fixture" "$obs_dir"
echo ""

facts_jsonl=$(mktemp)
trap 'rm -f "$facts_jsonl"' EXIT

"$stave_bin" export-sir --format jsonl --observations "$obs_dir" \
    --now 2026-05-09T12:00:00Z > "$facts_jsonl" 2>/dev/null

python3 "$script_dir/format_facts.py" "$facts_jsonl"

echo ""

fmt_section "Encoding Verifier — does each fact match the observation it claims to come from?"
fmt_kv "facts file" "$facts_jsonl"
fmt_kv "observations" "$obs_dir"
echo ""

python3 "$script_dir/verify_encoding.py" "$facts_jsonl" "$obs_dir" || true
echo ""

fmt_section "Verdict Report — solver output translated to cloud-security language"
fmt_kv "demo inputs" "$script_dir/tests/decoding/*.input.json"
echo ""

# Render each bundled verdict input — sat / unsat / unknown — so
# both translation boundaries appear back-to-back. Each input is
# self-contained: verdict + invariant + contributing facts. The
# format_facts.py output above shows the encoding side; verdict.py
# shows the decoding side.
for verdict_input in "$script_dir"/tests/decoding/*.input.json; do
    verdict_name=$(basename "$verdict_input" .input.json)
    verdict_kind=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('verdict','?'))" "$verdict_input")
    case "$verdict_kind" in
        sat)     fmt_block_header "Verdict: $verdict_name (sat → UNSAFE)" ;;
        unsat)   fmt_block_header "Verdict: $verdict_name (unsat → SAFE)" ;;
        *)       fmt_block_header "Verdict: $verdict_name ($verdict_kind → INCONCLUSIVE)" ;;
    esac
    python3 "$script_dir/verdict.py" "$verdict_input" | sed 's/^/  /'
    echo ""
done

fmt_interpretation <<'EOF'
This is the round trip from observation → SMT solver →
security engineer, with both translation boundaries plus the
encoding-correctness check rendered in cloud-security
language.

1. Encoding Report (format_facts.py) — what Stave's projector
   extracted from the observations. "Public read access:
   ENABLED" means the SIR carries has_public_read("...",
   "true") into the solver.

2. Encoding Verifier (verify_encoding.py) — for each
   verifiable fact, navigates the asset's actual JSON at the
   provenance path and compares the value to fact.object.
   Catches projector bugs (wrong path, wrong value, type
   coercion drift) BEFORE the solver runs. A green
   "Encoding verified: N/N facts match" means the encoding
   you saw above genuinely came from your observations; a
   red mismatch points at the projector.

3. Verdict Report (verdict.py) — what the solver's
   sat/unsat/unknown answer means. The word "sat" never
   appears; the engineer reads UNSAFE / SAFE / INCONCLUSIVE
   and a numbered chain of contributing facts.

The three steps are intentionally symmetric: PREDICATE_LABELS
and VALUE_LABELS are shared across all three Python tools, so
the same predicate ("Public read access") shows the same way
whether you're reading the encoding, verifying its
correctness, or reading the verdict.

Run all three test suites for golden-friendly isolation:

    bash examples/explain/tests/encoding/run_tests.sh   # 2 tests
    bash examples/explain/tests/verify/run_tests.sh     # 3 tests
    bash examples/explain/tests/decoding/run_tests.sh   # 3 tests

None of them invoke Stave or Z3. Encoding bugs (formatter),
verifier bugs (path navigation), and decoding bugs
(translator) surface independently — when a test fails the
failure points at one specific layer, not the solver.
EOF
