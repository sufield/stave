#!/usr/bin/env bash
# MICROVM-023 — lambda:* silent blast radius. Soufflé gives severity, Z3 confirms.
#   vuln_cicd  : CI/CD role, lambda:* (inline)              -> CRITICAL (FAIL)
#   fp         : microvm-admin role, lambda:*               -> NONE     (PASS)
#   fn_managed : human role, lambda:* via managed policy    -> HIGH     (FAIL)
#   fn_agent   : agent, inline lambda:InvokeFunction + managed lambda:* -> CRITICAL (FAIL)
set -uo pipefail; cd "$(dirname "$0")"; HERE=$(pwd)
build() {
  local d="$1"; mkdir -p "$d"
  : > "$d/role_permission.facts"; : > "$d/role_microvm_admin.facts"; : > "$d/agent_role.facts"; : > "$d/cicd_role.facts"
  local wc=false admin=false
  case "$(basename "$1")" in
    facts-vuln_cicd)  printf 'GH\tlambda\t*\n' >> "$d/role_permission.facts"; printf 'GH\n' >> "$d/cicd_role.facts"; wc=true ;;
    facts-fp)         printf 'Admin\tlambda\t*\n' >> "$d/role_permission.facts"; printf 'Admin\n' >> "$d/role_microvm_admin.facts"; wc=true; admin=true ;;
    facts-fn_managed) printf 'Dev\tlambda\t*\n' >> "$d/role_permission.facts"; wc=true ;;  # wildcard from AWSLambda_FullAccess (resolved)
    facts-fn_agent)   printf 'Agent\tlambda\tInvokeFunction\nAgent\tlambda\t*\n' >> "$d/role_permission.facts"; printf 'Agent\n' >> "$d/agent_role.facts"; wc=true ;;  # inline scoped + managed wildcard
  esac
  printf '(declare-const has_wildcard Bool)(assert (= has_wildcard %s))\n(declare-const is_microvm_admin Bool)(assert (= is_microvm_admin %s))\n' "$wc" "$admin" > "$d/facts.smt2"
}
for s in vuln_cicd fp fn_managed fn_agent; do
  d="$HERE/facts-$s"; build "$d"; mkdir -p "$d/out"
  souffle "$HERE/wildcard.dl" -F "$d" -D "$d/out" 2>/dev/null
  sev=$(cut -f2 "$d/out/silent_blast_radius.csv" 2>/dev/null); sev=${sev%%$'\n'*}; sev=${sev:-NONE}
  z3o=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null); z3v=${z3o%%$'\n'*}
  printf '%-11s souffle=%-9s z3=%-5s\n' "$s" "$sev" "$z3v"
done
