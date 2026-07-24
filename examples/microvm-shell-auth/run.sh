#!/usr/bin/env bash
# MICROVM shell-auth reasoning spec — trap-triplet over both engines. Soufflé
# derives the finding + severity; Z3 independently confirms an unauthorized
# (non-break-glass) shell grant exists. They must agree on every scenario.
#
#   vuln    : developer role with lambda:* (wildcard)        -> HIGH     (FAIL)
#   fp      : break-glass role with the shell action                  -> NONE     (PASS)
#   fn_cicd : CI/CD role, lambda:* via managed policy        -> CRITICAL (FAIL)
#   fn_agent: bedrock agent role with explicit shell action           -> CRITICAL (FAIL)
set -uo pipefail
cd "$(dirname "$0")"; HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/role_permission.facts"; : > "$d/role_break_glass.facts"
  : > "$d/agent_role.facts"; : > "$d/cicd_role.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'DevTeam-LambdaRole\tlambda\t*\n'                 >> "$d/role_permission.facts" ;;
    facts-fp)
      printf 'Emergency-BreakGlass-Admin\tlambda\tCreateMicrovmShellAuthToken\n' >> "$d/role_permission.facts"
      printf 'Emergency-BreakGlass-Admin\n'                            >> "$d/role_break_glass.facts" ;;
    facts-fn_cicd)
      printf 'GitHubActions-DeployRole\tlambda\t*\n'          >> "$d/role_permission.facts"
      printf 'GitHubActions-DeployRole\n'                              >> "$d/cicd_role.facts" ;;
    facts-fn_agent)
      printf 'order-agent\tlambda\tCreateMicrovmShellAuthToken\n' >> "$d/role_permission.facts"
      printf 'order-agent\n'                                          >> "$d/agent_role.facts" ;;
  esac
  {
    echo "(define-fun role_permission ((r String)(s String)(a String)) Bool (or"
    awk -F'\t' '{printf "  (and (= r \"%s\")(= s \"%s\")(= a \"%s\"))\n",$1,$2,$3}' "$d/role_permission.facts"; echo "  false))"
    echo "(define-fun role_break_glass ((r String)) Bool (or"
    awk -F'\t' '{printf "  (= r \"%s\")\n",$1}' "$d/role_break_glass.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn_cicd fn_agent; do
  d="$HERE/facts-$s"; build_facts "$d"; mkdir -p "$d/out"
  souffle "$HERE/shellauth.dl" -F "$d" -D "$d/out" 2>/dev/null
  sev=$(cut -f2 "$d/out/unauthorized_shell_access.csv" 2>/dev/null || true); sev=${sev%%$'\n'*}; sev=${sev:-NONE}
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true); z3v=${z3out%%$'\n'*}
  printf '%-9s souffle=%-9s z3=%-5s\n' "$s" "$sev" "$z3v"
done
