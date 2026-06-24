#!/usr/bin/env bash
# MICROVM-019 expiry reasoning spec — Soufflé derives the finding+reason, Z3
# confirms the finding condition. Must agree on every scenario.
#   vuln    : create, no expiration condition                 -> unconstrained (FAIL)
#   fp      : create, condition <= 30 min                     -> NONE          (PASS)
#   fn      : create, condition = 480 min                     -> excessive     (FAIL)
#   wildcard: lambda:*, no condition                 -> unconstrained (FAIL)
set -uo pipefail
cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"; : > "$d/role_permission.facts"; : > "$d/has_expiration_constraint.facts"
  local create="false" constrained="false" maxv="0"
  case "$(basename "$1")" in
    facts-vuln)     printf 'AppRole\tlambda\tCreateMicrovmAuthToken\n' >> "$d/role_permission.facts"; create=true ;;
    facts-fp)       printf 'Secure\tlambda\tCreateMicrovmAuthToken\n'  >> "$d/role_permission.facts"; printf 'Secure\t30\n'  >> "$d/has_expiration_constraint.facts"; create=true; constrained=true; maxv=30 ;;
    facts-fn)       printf 'TooLong\tlambda\tCreateMicrovmAuthToken\n' >> "$d/role_permission.facts"; printf 'TooLong\t480\n' >> "$d/has_expiration_constraint.facts"; create=true; constrained=true; maxv=480 ;;
    facts-wildcard) printf 'Wild\tlambda\t*\n'                         >> "$d/role_permission.facts"; create=true ;;
  esac
  printf '(declare-const create Bool)(assert (= create %s))\n' "$create" > "$d/facts.smt2"
  printf '(declare-const constrained Bool)(assert (= constrained %s))\n' "$constrained" >> "$d/facts.smt2"
  printf '(declare-const maxv Int)(assert (= maxv %s))\n' "$maxv" >> "$d/facts.smt2"
}
for s in vuln fp fn wildcard; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/expiry.dl" -F "$d" -D "$d/out" 2>/dev/null
  reason=$(cut -f2 "$d/out/bad_expiry.csv" 2>/dev/null); reason=${reason%%$'\n'*}; reason=${reason:-NONE}
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-9s souffle=%-13s z3=%-5s\n' "$s" "$reason" "$z3v"
done
