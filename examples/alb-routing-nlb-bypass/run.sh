#!/usr/bin/env bash
#
# ALB-ROUTING-008 reasoning spec — trap-triplet over both graph engines.
# For each scenario build the ALB/NLB instance graph, run Soufflé and Z3, and
# print whether an NLB reaches an instance that sits behind a gated ALB. The two
# engines must agree on every scenario.
#
#   vuln : alb-1 (gated) -> i-abc,i-def ; nlb-1 -> i-abc,i-def        -> BYPASS  (FAIL)
#   fp   : alb-1 (gated) -> i-abc,i-def ; nlb-1 -> i-ghi,i-jkl        -> CLEAN   (PASS)
#   fn   : alb-1 (gated) -> i-abc (via TG) ; nlb-1 -> i-abc (IP target
#          resolved to the instance)                                  -> BYPASS  (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/alb_target_instance.facts"; : > "$d/nlb_target_instance.facts"; : > "$d/alb_has_security_controls.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'alb-1\ti-abc\nalb-1\ti-def\n' >> "$d/alb_target_instance.facts"
      printf 'nlb-1\ti-abc\nnlb-1\ti-def\n' >> "$d/nlb_target_instance.facts"
      printf 'alb-1\n'                      >> "$d/alb_has_security_controls.facts" ;;
    facts-fp)
      printf 'alb-1\ti-abc\nalb-1\ti-def\n' >> "$d/alb_target_instance.facts"
      printf 'nlb-1\ti-ghi\nnlb-1\ti-jkl\n' >> "$d/nlb_target_instance.facts"
      printf 'alb-1\n'                      >> "$d/alb_has_security_controls.facts" ;;
    facts-fn)
      printf 'alb-1\ti-abc\n'               >> "$d/alb_target_instance.facts"
      printf 'nlb-1\ti-abc\n'               >> "$d/nlb_target_instance.facts"  # IP target resolved to i-abc
      printf 'alb-1\n'                      >> "$d/alb_has_security_controls.facts" ;;
  esac
  {
    echo "(define-fun alb_target_instance ((alb String)(inst String)) Bool (or"
    awk -F'\t' '{printf "  (and (= alb \"%s\") (= inst \"%s\"))\n",$1,$2}' "$d/alb_target_instance.facts"; echo "  false))"
    echo "(define-fun nlb_target_instance ((nlb String)(inst String)) Bool (or"
    awk -F'\t' '{printf "  (and (= nlb \"%s\") (= inst \"%s\"))\n",$1,$2}' "$d/nlb_target_instance.facts"; echo "  false))"
    echo "(define-fun alb_has_security_controls ((alb String)) Bool (or"
    awk -F'\t' '{printf "  (= alb \"%s\")\n",$1}' "$d/alb_has_security_controls.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/nlb_bypass.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/nlb_bypasses_alb.csv" ] && echo BYPASS || echo CLEAN)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-7s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
