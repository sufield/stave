#!/usr/bin/env bash
# MICROVM-022 — production MicroVM must have exec role + image build role.
#   vuln: prod, no exec role            -> no_exec_role  (FAIL)
#   fp  : prod, exec + build present    -> NONE          (PASS)
#   fn  : prod, image has no build role -> no_build_role (FAIL)
set -uo pipefail; cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"
  : > "$d/microvm.facts"; : > "$d/microvm_is_production.facts"; : > "$d/microvm_execution_role.facts"; : > "$d/microvm_build_role.facts"
  printf 'mvm\n' > "$d/microvm.facts"; printf 'mvm\n' > "$d/microvm_is_production.facts"
  local er=false br=false
  case "$(basename "$1")" in
    facts-vuln) printf 'mvm\tbuild-role\n' >> "$d/microvm_build_role.facts"; br=true ;;
    facts-fp)   printf 'mvm\texec-role\n' >> "$d/microvm_execution_role.facts"; printf 'mvm\tbuild-role\n' >> "$d/microvm_build_role.facts"; er=true; br=true ;;
    facts-fn)   printf 'mvm\texec-role\n' >> "$d/microvm_execution_role.facts"; er=true ;;
  esac
  printf '(declare-const is_production Bool)(assert is_production)\n(declare-const exec_role Bool)(assert (= exec_role %s))\n(declare-const build_role Bool)(assert (= build_role %s))\n' "$er" "$br" > "$d/facts.smt2"
}
for s in vuln fp fn; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/observability.dl" -F "$d" -D "$d/out" 2>/dev/null
  reason=$(cut -f2 "$d/out/bad_observability.csv" 2>/dev/null); reason=${reason%%$'\n'*}; reason=${reason:-NONE}
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-5s souffle=%-13s z3=%-5s\n' "$s" "$reason" "$z3v"
done
