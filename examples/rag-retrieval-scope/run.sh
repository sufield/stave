#!/usr/bin/env bash
#
# RAG-004 reasoning spec — trap-triplet over both engines. retrieval's reachable
# set must be contained in the KB's declared data sources.
#
#   vuln : wildcard prefix hr-* overmatches hr-private-records (non-source)   -> EXCEEDS (FAIL)
#   fp   : retrieval scoped exactly to the declared source                    -> CONTAINED (PASS)
#   fn   : non-source bucket policy grants the retrieval role (resource-based) -> EXCEEDS (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/kb_data_source.facts"; : > "$d/retrieval_can_access.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'hr-public-docs\n'                       >> "$d/kb_data_source.facts"
      # s3://hr-* expands to both buckets; hr-private-records is NOT a declared source
      printf 'hr-public-docs\nhr-private-records\n'   >> "$d/retrieval_can_access.facts" ;;
    facts-fp)
      printf 'product-docs-v2\n'                      >> "$d/kb_data_source.facts"
      printf 'product-docs-v2\n'                      >> "$d/retrieval_can_access.facts" ;;
    facts-fn)
      printf 'legal-contracts\n'                      >> "$d/kb_data_source.facts"
      # IAM policy is scoped to legal-contracts, but legal-settlements' bucket
      # policy grants the retrieval role -> folded into reachable set
      printf 'legal-contracts\nlegal-settlements\n'   >> "$d/retrieval_can_access.facts" ;;
  esac
  {
    echo "(define-fun kb_data_source ((r String)) Bool (or"
    awk -F'\t' '{printf "  (= r \"%s\")\n",$1}' "$d/kb_data_source.facts"; echo "  false))"
    echo "(define-fun retrieval_can_access ((r String)) Bool (or"
    awk -F'\t' '{printf "  (= r \"%s\")\n",$1}' "$d/retrieval_can_access.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/scope.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/exceeds.csv" ] && echo EXCEEDS || echo CONTAINED)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-9s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
