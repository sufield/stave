#!/usr/bin/env bash
#
# ALB-ROUTING-002 reasoning spec — trap-triplet over both graph engines.
# For each scenario build the listener's rules, run Soufflé and Z3, and print
# whether an auth rule is shadowed by a higher-precedence non-auth rule. The two
# engines must agree on every scenario.
#
#   vuln : p10 "/*" (no auth) before p20 "/admin*" (auth)       -> SHADOWED   (FAIL)
#   fp   : p10 "/api/*" (no auth) before p20 "/admin/*" (auth)  -> CLEAR      (PASS)
#   fn   : p5 host-wildcard, NO path (no auth) before p15 "/admin*" (auth)
#          no-path normalizes to "" = /*, subsumes everything   -> SHADOWED   (FAIL)
set -uo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/listener_rule.facts"; : > "$d/rule_auth.facts"; : > "$d/rule_prefix.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'L1\tr10\t10\n'    >> "$d/listener_rule.facts"
      printf 'L1\tr20\t20\n'    >> "$d/listener_rule.facts"
      printf 'r20\n'            >> "$d/rule_auth.facts"
      printf 'r10\t\n'          >> "$d/rule_prefix.facts"   # "/*" -> empty prefix
      printf 'r20\t/admin\n'    >> "$d/rule_prefix.facts" ;;
    facts-fp)
      printf 'L1\tr10\t10\n'    >> "$d/listener_rule.facts"
      printf 'L1\tr20\t20\n'    >> "$d/listener_rule.facts"
      printf 'r20\n'            >> "$d/rule_auth.facts"
      printf 'r10\t/api/\n'     >> "$d/rule_prefix.facts"
      printf 'r20\t/admin/\n'   >> "$d/rule_prefix.facts" ;;
    facts-fn)
      printf 'L1\tr5\t5\n'      >> "$d/listener_rule.facts"
      printf 'L1\tr15\t15\n'    >> "$d/listener_rule.facts"
      printf 'r15\n'            >> "$d/rule_auth.facts"
      printf 'r5\t\n'           >> "$d/rule_prefix.facts"   # host wildcard, no path -> empty
      printf 'r15\t/admin\n'    >> "$d/rule_prefix.facts" ;;
  esac
  {
    echo "(define-fun listener_rule ((listener String)(rule String)(priority Int)) Bool (or"
    awk -F'\t' '{printf "  (and (= listener \"%s\") (= rule \"%s\") (= priority %s))\n",$1,$2,$3}' "$d/listener_rule.facts"; echo "  false))"
    echo "(define-fun rule_auth ((rule String)) Bool (or"
    awk -F'\t' '{printf "  (= rule \"%s\")\n",$1}' "$d/rule_auth.facts"; echo "  false))"
    echo "(define-fun rule_prefix ((rule String)(prefix String)) Bool (or"
    awk -F'\t' '{printf "  (and (= rule \"%s\") (= prefix \"%s\"))\n",$1,$2}' "$d/rule_prefix.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/rule_shadow.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/auth_shadowed.csv" ] && echo SHADOWED || echo CLEAR)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-9s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
