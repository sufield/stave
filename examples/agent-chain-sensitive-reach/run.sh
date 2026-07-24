#!/usr/bin/env bash
#
# AGENT-CHAIN-001 reasoning spec — trap-triplet over both graph engines.
# For each scenario, build the facts, run Soufflé and Z3, and print whether a
# path from an agent role to a sensitive resource exists. The two engines must
# agree on every scenario.
#
#   vuln : agent -> assume -> pipeline-role -> secretsmanager            -> PATH (FAIL)
#   fp   : agent -> assume -> readonly-role -> public bucket (not sensitive) -> NONE (PASS)
#   fn   : sagemaker -> assume -> etl -passrole-> admin-lambda -> kms key -> PATH (FAIL)
set -uo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  : > "$d/agent_role.facts"; : > "$d/sensitive_resource.facts"
  : > "$d/can_assume.facts"; : > "$d/can_pass.facts"
  : > "$d/has_access.facts"; : > "$d/resource_policy_grants.facts"
  case "$(basename "$1")" in
    facts-vuln)
      printf 'bedrock-order-agent\n'                            >> "$d/agent_role.facts"
      printf 'prod-db-creds\tsecretsmanager\n'                  >> "$d/sensitive_resource.facts"
      printf 'bedrock-order-agent\tdata-pipeline-role\n'        >> "$d/can_assume.facts"
      printf 'data-pipeline-role\tprod-db-creds\tGetSecretValue\n' >> "$d/has_access.facts" ;;
    facts-fp)
      # destination bucket is NOT sensitive -> sensitive_resource empty
      printf 'bedrock-readonly-agent\n'                         >> "$d/agent_role.facts"
      printf 'bedrock-readonly-agent\treadonly-role\n'          >> "$d/can_assume.facts"
      printf 'readonly-role\tpublic-assets-bucket\tGetObject\n' >> "$d/has_access.facts" ;;
    facts-fn)
      printf 'sagemaker-notebook\n'                             >> "$d/agent_role.facts"
      printf 'cmk\tkms\n'                                       >> "$d/sensitive_resource.facts"
      printf 'sagemaker-notebook\tetl-role\n'                   >> "$d/can_assume.facts"
      printf 'etl-role\tadmin-lambda-role\n'                    >> "$d/can_pass.facts"
      printf 'admin-lambda-role\tcmk\tDecrypt\n'                >> "$d/has_access.facts" ;;
  esac
  {
    echo "(define-fun agent_role ((r String)) Bool (or"
    awk -F'\t' '{printf "  (= r \"%s\")\n",$1}' "$d/agent_role.facts"; echo "  false))"
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
  z3v=${z3out%%$'\n'*}
  printf '%-5s  souffle=%-4s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
