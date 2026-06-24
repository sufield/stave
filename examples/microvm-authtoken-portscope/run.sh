#!/usr/bin/env bash
# MICROVM-020 port-scope reasoning spec — Soufflé derives finding+reason
# (deriving lifecycle exposure from allowed_port INTERSECT lifecycle_port),
# Z3 confirms the finding condition. Must agree on every scenario.
#   vuln    : create, no port condition                       -> unscoped  (FAIL)
#   fp      : create, allowed={8080}, lifecycle=9090          -> NONE      (PASS)
#   fn      : create, allowed={8080,9090}, lifecycle=9090     -> lifecycle (FAIL)
#   wildcard: lambda:*, no port condition            -> unscoped  (FAIL)
set -uo pipefail
cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"
  : > "$d/role_permission.facts"; : > "$d/has_port_constraint.facts"; : > "$d/allowed_port.facts"; : > "$d/lifecycle_port.facts"
  local create="false" scoped="false" alc="false"
  case "$(basename "$1")" in
    facts-vuln)     printf 'Client\tlambda\tCreateMicrovmAuthToken\n' >> "$d/role_permission.facts"; create=true ;;
    facts-fp)       printf 'Secure\tlambda\tCreateMicrovmAuthToken\n' >> "$d/role_permission.facts"; printf 'Secure\n' >> "$d/has_port_constraint.facts"; printf 'Secure\t8080\n' >> "$d/allowed_port.facts"; printf '9090\n' >> "$d/lifecycle_port.facts"; create=true; scoped=true ;;
    facts-fn)       printf 'TooMany\tlambda\tCreateMicrovmAuthToken\n' >> "$d/role_permission.facts"; printf 'TooMany\n' >> "$d/has_port_constraint.facts"; printf 'TooMany\t8080\nTooMany\t9090\n' >> "$d/allowed_port.facts"; printf '9090\n' >> "$d/lifecycle_port.facts"; create=true; scoped=true; alc=true ;;
    facts-wildcard) printf 'Wild\tlambda\t*\n' >> "$d/role_permission.facts"; create=true ;;
  esac
  printf '(declare-const create Bool)(assert (= create %s))\n' "$create" > "$d/facts.smt2"
  printf '(declare-const port_scoped Bool)(assert (= port_scoped %s))\n' "$scoped" >> "$d/facts.smt2"
  printf '(declare-const allows_lifecycle Bool)(assert (= allows_lifecycle %s))\n' "$alc" >> "$d/facts.smt2"
}
for s in vuln fp fn wildcard; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/portscope.dl" -F "$d" -D "$d/out" 2>/dev/null
  reason=$(cut -f2 "$d/out/bad_port.csv" 2>/dev/null); reason=${reason%%$'\n'*}; reason=${reason:-NONE}
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-9s souffle=%-10s z3=%-5s\n' "$s" "$reason" "$z3v"
done
