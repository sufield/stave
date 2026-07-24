#!/usr/bin/env bash
#
# IAM-FOOTHOLD-001 reasoning spec — trap-triplet over both graph engines.
# For each scenario, build the facts, run Soufflé and Z3, and print whether a
# path from an internet-facing role to a sensitive resource exists. The two
# engines must agree on every scenario.
#
#   vuln : EC2 public IP -> role with direct secretsmanager access      -> PATH (FAIL)
#   fp   : EC2 private IP only -> same secrets access (not internet)     -> NONE (PASS)
#   fn   : EC2 public IP -> assume -> intermediate role -> secret (2-hop) -> PATH (FAIL)
set -uo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

# scenario => souffle .facts (TSV) + z3 facts.smt2 (closed-world define-fun)
build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/internet_facing_role.facts"; : > "$d/sensitive_resource.facts"
  : > "$d/can_assume.facts"; : > "$d/can_pass.facts"
  : > "$d/has_access.facts"; : > "$d/resource_policy_grants.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'web-ec2-role\n'                              >> "$d/internet_facing_role.facts"
      printf 'prod-secret\tsecretsmanager\n'               >> "$d/sensitive_resource.facts"
      printf 'web-ec2-role\tprod-secret\tGetSecretValue\n' >> "$d/has_access.facts" ;;
    facts-fp)
      # private IP -> NOT internet-facing (internet_facing_role empty)
      printf 'prod-secret\tsecretsmanager\n'                    >> "$d/sensitive_resource.facts"
      printf 'internal-ec2-role\tprod-secret\tGetSecretValue\n' >> "$d/has_access.facts" ;;
    facts-fn)
      printf 'web-ec2-role-twohop\n'                            >> "$d/internet_facing_role.facts"
      printf 'prod-secret\tsecretsmanager\n'                    >> "$d/sensitive_resource.facts"
      printf 'web-ec2-role-twohop\tintermediate-role\n'         >> "$d/can_assume.facts"
      printf 'intermediate-role\tprod-secret\tGetSecretValue\n' >> "$d/has_access.facts" ;;
  esac
  # z3 closed-world facts from the same edges
  {
    echo "(define-fun internet_facing_role ((r String)) Bool (or"
    awk '{printf "  (= r \"%s\")\n",$1}' "$d/internet_facing_role.facts"; echo "  false))"
    echo "(define-fun sensitive_resource ((r String)) Bool (or"
    awk -F'\t' '{printf "  (= r \"%s\")\n",$1}' "$d/sensitive_resource.facts"; echo "  false))"
    echo "(define-fun can_assume ((a String)(b String)) Bool (or"
    awk -F'\t' '{printf "  (and (= a \"%s\") (= b \"%s\"))\n",$1,$2}' "$d/can_assume.facts"; echo "  false))"
    echo "(define-fun can_pass ((a String)(b String)) Bool (or"
    awk -F'\t' '{printf "  (and (= a \"%s\") (= b \"%s\"))\n",$1,$2}' "$d/can_pass.facts"; echo "  false))"
    echo "(define-fun has_access ((r String)(s String)) Bool (or"
    awk -F'\t' '{printf "  (and (= r \"%s\") (= s \"%s\"))\n",$1,$2}' "$d/has_access.facts"; echo "  false))"
    echo "(define-fun resource_policy_grants ((s String)(p String)) Bool (or"
    awk -F'\t' '{printf "  (and (= s \"%s\") (= p \"%s\"))\n",$1,$2}' "$d/resource_policy_grants.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/reachable.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/reachable.csv" ] && echo PATH || echo NONE)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}   # first line (sat/unsat) without a SIGPIPE-prone head
  printf '%-5s  souffle=%-4s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
