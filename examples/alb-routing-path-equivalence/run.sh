#!/usr/bin/env bash
#
# ALB-ROUTING-006 reasoning spec — trap-triplet over both graph engines.
# For each scenario build the routing graph, run Soufflé and Z3, and print
# whether some backend instance is reachable by a controlled AND an uncontrolled
# path. The two engines must agree on every scenario.
#
#   vuln : tg-shared via alb-1 (auth+ip+waf) AND alb-2 (none)        -> INCONSISTENT (FAIL)
#   fp   : tg-shared via alb-1 AND alb-2, both auth+ip+waf           -> CONSISTENT   (PASS)
#   fn   : i-abc in tg-app (auth rule) AND tg-catchall (default rule, no auth),
#          different target groups, SAME instance, same listener     -> INCONSISTENT (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/tg_instance.facts"; : > "$d/path_to_tg.facts"
  : > "$d/rule_auth.facts"; : > "$d/rule_sourceip.facts"; : > "$d/alb_waf.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'tg-shared\ti-abc\n'                  >> "$d/tg_instance.facts"
      printf 'tg-shared\talb-1\tl1\tr1\n'          >> "$d/path_to_tg.facts"
      printf 'tg-shared\talb-2\tl2\tr2\n'          >> "$d/path_to_tg.facts"
      printf 'r1\n'                                >> "$d/rule_auth.facts"
      printf 'r1\n'                                >> "$d/rule_sourceip.facts"
      printf 'alb-1\n'                             >> "$d/alb_waf.facts" ;;
    facts-fp)
      printf 'tg-shared\ti-abc\n'                  >> "$d/tg_instance.facts"
      printf 'tg-shared\talb-1\tl1\tr1\n'          >> "$d/path_to_tg.facts"
      printf 'tg-shared\talb-2\tl2\tr2\n'          >> "$d/path_to_tg.facts"
      printf 'r1\nr2\n'                            >> "$d/rule_auth.facts"
      printf 'r1\nr2\n'                            >> "$d/rule_sourceip.facts"
      printf 'alb-1\nalb-2\n'                      >> "$d/alb_waf.facts" ;;
    facts-fn)
      printf 'tg-app\ti-abc\n'                     >> "$d/tg_instance.facts"
      printf 'tg-catchall\ti-abc\n'                >> "$d/tg_instance.facts"
      printf 'tg-app\talb-1\tl1\tr1\n'             >> "$d/path_to_tg.facts"
      printf 'tg-catchall\talb-1\tl1\trdef\n'      >> "$d/path_to_tg.facts"
      printf 'r1\n'                                >> "$d/rule_auth.facts" ;;
  esac
  {
    echo "(define-fun tg_instance ((tg String)(inst String)) Bool (or"
    awk -F'\t' '{printf "  (and (= tg \"%s\") (= inst \"%s\"))\n",$1,$2}' "$d/tg_instance.facts"; echo "  false))"
    echo "(define-fun path_to_tg ((tg String)(alb String)(listener String)(rule String)) Bool (or"
    awk -F'\t' '{printf "  (and (= tg \"%s\") (= alb \"%s\") (= listener \"%s\") (= rule \"%s\"))\n",$1,$2,$3,$4}' "$d/path_to_tg.facts"; echo "  false))"
    echo "(define-fun rule_auth ((rule String)) Bool (or"
    awk -F'\t' '{printf "  (= rule \"%s\")\n",$1}' "$d/rule_auth.facts"; echo "  false))"
    echo "(define-fun rule_sourceip ((rule String)) Bool (or"
    awk -F'\t' '{printf "  (= rule \"%s\")\n",$1}' "$d/rule_sourceip.facts"; echo "  false))"
    echo "(define-fun alb_waf ((alb String)) Bool (or"
    awk -F'\t' '{printf "  (= alb \"%s\")\n",$1}' "$d/alb_waf.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/path_equivalence.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/inconsistent.csv" ] && echo INCONSISTENT || echo CONSISTENT)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-12s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
