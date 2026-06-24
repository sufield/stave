#!/usr/bin/env bash
# MICROVM-021 — production MicroVM with SHELL_INGRESS. Soufflé + Z3 must agree.
#   vuln: prod tag + SHELL_INGRESS                     -> FINDING (FAIL)
#   fp  : prod tag, no SHELL_INGRESS                   -> NONE    (PASS)
#   fn  : no tag, production ACCOUNT + SHELL_INGRESS   -> FINDING (FAIL)
set -uo pipefail; cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"
  : > "$d/microvm_shell_ingress.facts"; : > "$d/microvm_tag.facts"; : > "$d/microvm_account.facts"; : > "$d/production_account.facts"
  local si=false prod=false
  case "$(basename "$1")" in
    facts-vuln) printf 'mvm\n' >> "$d/microvm_shell_ingress.facts"; printf 'mvm\tenvironment\tproduction\n' >> "$d/microvm_tag.facts"; si=true; prod=true ;;
    facts-fp)   printf 'mvm\tenvironment\tproduction\n' >> "$d/microvm_tag.facts"; prod=true ;;
    facts-fn)   printf 'mvm\n' >> "$d/microvm_shell_ingress.facts"; printf 'mvm\tacct-prod\n' >> "$d/microvm_account.facts"; printf 'acct-prod\n' >> "$d/production_account.facts"; si=true; prod=true ;;
  esac
  printf '(declare-const shell_ingress Bool)(assert (= shell_ingress %s))\n(declare-const is_production Bool)(assert (= is_production %s))\n' "$si" "$prod" > "$d/facts.smt2"
}
for s in vuln fp fn; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/shellingress.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/production_shell_enabled.csv" ] && echo FINDING || echo NONE)
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-5s souffle=%-8s z3=%-5s\n' "$s" "$sou" "$z3v"
done
