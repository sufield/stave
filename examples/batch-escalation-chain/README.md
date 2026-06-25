# BATCH-003 / ECS-003 — escalation-chain reasoning spec

The full Doyensec chain (Batch and the identical ECS EC2-launch-type variant): a
principal that can author and run jobs/tasks on an **EC2-orchestration** compute
environment gets code execution in a container that shares the host network,
reaches the host **IMDS** (169.254.169.254), retrieves the EC2 **instance-role**
credentials, and those credentials reach a **sensitive resource**.

Four conditions, all required:
1. EC2 orchestration (`batch_ec2_env`)
2. IMDS accessible from job containers (`imds_accessible`)
3. job/task role can create+run jobs (`job_role_can_create_jobs` — the
   `batch:RegisterJobDefinition+SubmitJob` / `ecs:RegisterTaskDefinition+RunTask`
   + `PassRole` combo proven in `examples/iam-21-privesc-5-patterns`, reused)
4. instance role has sensitive access — direct data **or** `ecs:*` (lateral to
   ECS task roles) **or** `iam:PassRole` (chain extension)

Composes with the existing `chains/ec2_imds_container_escalation` (container →
IMDS → instance-role credential theft); this spec adds the Batch/ECS entry point
(condition 3) and the sensitive-reach exit (condition 4).

## Engines
- `escalation.dl` — Soufflé. `escalation_chain(env, job_role, instance_role, resource)`. Non-empty = FAIL.
- `query.smt2` — Z3, quantifier-free. `sat` = FAIL.

Collector signal: `batch.escalation_chain_present` / `container.escalation_chain_present`.

## Run
```bash
./run.sh
```
Expected (`expected/output.txt`):
```
vuln          souffle=CHAIN  z3=sat
fp            souffle=NONE   z3=unsat
fn-ecs        souffle=CHAIN  z3=sat
fn-passrole   souffle=CHAIN  z3=sat
```

- **vuln** — EC2 CE + IMDS + job combo + instance role → tenant data.
- **fp** — Fargate CE: no EC2 env, no IMDS. The combo exists (BATCH-002 fires
  independently) but the chain is broken — no IMDS to escalate through.
- **fn-ecs** — instance role looks minimal (`logs` + `ecs:*`) but `ecs:*` is a
  lateral escalation to ECS task roles; must count as sensitive.
- **fn-passrole** — instance role has `iam:PassRole`; extends the chain to a new
  resource; must count as sensitive.

Inspired by Doyensec CloudsecTidbits No. 3 — *Messing Around With AWS Batch For
Privilege Escalations*. Lab: github.com/doyensec/cloudsec-tidbits.
