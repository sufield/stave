#!/usr/bin/env bash
#
# BATCH-003 / ECS-003 reasoning spec — trap-triplet over both graph engines.
# Build the chain graph per scenario, run Soufflé and Z3, print whether the
# four-condition escalation chain exists. The two engines must agree.
#
#   vuln        : EC2 CE + IMDS + job combo + instance role -> tenant data   -> CHAIN (FAIL)
#   fp          : Fargate CE (no EC2 env, no IMDS) + job combo               -> NONE  (PASS)
#   fn-ecs      : EC2 CE + IMDS + job combo + instance role has only ecs:*   -> CHAIN (FAIL)
#   fn-passrole : EC2 CE + IMDS + job combo + instance role has iam:PassRole -> CHAIN (FAIL)
set -euo pipefail
cd "$(dirname "$0")"
HERE=$(pwd)

build_facts() {
  local d="$1"; mkdir -p "$d"
  for r in batch_ec2_env imds_accessible job_role_can_create_jobs \
           instance_role_data_access instance_role_ecs_wildcard instance_role_passrole; do : > "$d/$r.facts"; done
  case "$(basename "$1")" in
    facts-vuln)
      printf 'batch-prod\tbatch-instance-role\n'   >> "$d/batch_ec2_env.facts"
      printf 'batch-prod\n'                          >> "$d/imds_accessible.facts"
      printf 'batch-prod\tbatch-job-role\n'          >> "$d/job_role_can_create_jobs.facts"
      printf 'batch-instance-role\ts3-tenant-data\n' >> "$d/instance_role_data_access.facts" ;;
    facts-fp)
      # Fargate: no batch_ec2_env, no imds_accessible. The combo exists (BATCH-002 fires) but the chain is broken.
      printf 'batch-staging\tbatch-job-role\n'       >> "$d/job_role_can_create_jobs.facts" ;;
    facts-fn-ecs)
      printf 'batch-analytics\tbatch-analytics-role\n' >> "$d/batch_ec2_env.facts"
      printf 'batch-analytics\n'                        >> "$d/imds_accessible.facts"
      printf 'batch-analytics\tbatch-job-role\n'        >> "$d/job_role_can_create_jobs.facts"
      printf 'batch-analytics-role\n'                   >> "$d/instance_role_ecs_wildcard.facts" ;;
    facts-fn-passrole)
      printf 'batch-pass\tbatch-pass-instrole\n'     >> "$d/batch_ec2_env.facts"
      printf 'batch-pass\n'                           >> "$d/imds_accessible.facts"
      printf 'batch-pass\tbatch-job-role\n'           >> "$d/job_role_can_create_jobs.facts"
      printf 'batch-pass-instrole\n'                  >> "$d/instance_role_passrole.facts" ;;
  esac
  {
    echo "(define-fun batch_ec2_env ((env String)(role String)) Bool (or"
    awk -F'\t' '{printf "  (and (= env \"%s\") (= role \"%s\"))\n",$1,$2}' "$d/batch_ec2_env.facts"; echo "  false))"
    echo "(define-fun imds_accessible ((env String)) Bool (or"
    awk -F'\t' '{printf "  (= env \"%s\")\n",$1}' "$d/imds_accessible.facts"; echo "  false))"
    echo "(define-fun job_role_can_create_jobs ((env String)(role String)) Bool (or"
    awk -F'\t' '{printf "  (and (= env \"%s\") (= role \"%s\"))\n",$1,$2}' "$d/job_role_can_create_jobs.facts"; echo "  false))"
    echo "(define-fun instance_role_data_access ((role String)(res String)) Bool (or"
    awk -F'\t' '{printf "  (and (= role \"%s\") (= res \"%s\"))\n",$1,$2}' "$d/instance_role_data_access.facts"; echo "  false))"
    echo "(define-fun instance_role_ecs_wildcard ((role String)) Bool (or"
    awk -F'\t' '{printf "  (= role \"%s\")\n",$1}' "$d/instance_role_ecs_wildcard.facts"; echo "  false))"
    echo "(define-fun instance_role_passrole ((role String)) Bool (or"
    awk -F'\t' '{printf "  (= role \"%s\")\n",$1}' "$d/instance_role_passrole.facts"; echo "  false))"
  } > "$d/facts.smt2"
}

for s in vuln fp fn-ecs fn-passrole; do
  d="$HERE/facts-$s"; build_facts "$d"
  mkdir -p "$d/out"
  souffle "$HERE/escalation.dl" -F "$d" -D "$d/out" 2>/dev/null
  sou=$([ -s "$d/out/escalation_chain.csv" ] && echo CHAIN || echo NONE)
  z3out=$(cat "$d/facts.smt2" "$HERE/query.smt2" | z3 -in 2>/dev/null || true)
  z3v=${z3out%%$'\n'*}
  printf '%-12s  souffle=%-5s  z3=%-5s\n' "$s" "$sou" "$z3v"
done
