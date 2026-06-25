# Batch / ECS-EC2 Escalation Signals

Derived observation properties for the AWS Batch (and ECS EC2-launch-type)
job-container → host-IMDS → instance-role privilege-escalation path. A collector
populates these; Stave core only reads them. The compound chain signal is
computed by `examples/batch-escalation-chain/` (Soufflé + Z3, which agree).

Inspired by Doyensec CloudsecTidbits No. 3 — *Messing Around With AWS Batch For
Privilege Escalations* (lab: github.com/doyensec/cloudsec-tidbits).

## `batch.*` — Batch compute environment (asset `aws_batch_compute_environment`)

| Field | Type | Meaning |
|-------|------|---------|
| `batch.kind` | string | `compute_environment` (gate). |
| `batch.orchestration_ec2` | bool | The CE uses EC2 or SPOT orchestration (host networking), not Fargate. |
| `batch.imds_accessible_from_jobs` | bool | Job containers can reach the host IMDS (169.254.169.254). Mirrors `CTL.EC2.IMDSV2.002`: true when hop limit > 1, the endpoint is enabled with host/bridge networking, **or** the launch template's metadata options are absent. **Fail-loud: unknown/missing metadata ⇒ true** (don't assume defaults are safe). IMDSv2-required without a hop-limit restriction is still `true`. |
| `batch.instance_role_arn` | string | The CE EC2 instance role (the escalation target). |
| `batch.escalation_chain_present` | bool | **Derived (graph)**. The full chain holds — see `CTL.BATCH.ESCALATION.CHAIN.001`. Computed by `examples/batch-escalation-chain/`. |
| `batch.escalation_path` | string | Hop-by-hop path behind `escalation_chain_present` (evidence). |

## `container.*` — ECS EC2-launch-type task (asset `aws_ecs_task_definition`)

Extends the existing ECS `container.*` namespace.

| Field | Type | Meaning |
|-------|------|---------|
| `container.launch_type` | string | `EC2` or `FARGATE`. Only `EC2` exposes the host IMDS. |
| `container.reaches_host_imds` | bool | An EC2-launch-type task can reach the host instance IMDS (169.254.169.254 → instance role) — host/bridge networking + hop limit > 1, fail-loud on unknown. Distinct from the task metadata endpoint (169.254.170.2) covered by `CTL.ECS.METADATA.CREDENTIAL.001`. |
| `container.escalation_chain_present` | bool | **Derived (graph)**. ECS variant of the chain — `CTL.ECS.ESCALATION.CHAIN.001`. Same reasoning spec. |
| `container.escalation_path` | string | Path evidence. |

## `identity.escalation.*` — dangerous combos (asset `aws_iam_user`/`aws_iam_role`)

New techniques in the existing escalation family (mirror
`identity.escalation.passrole_createjob`). The extractor folds the multi-action
combo into one `.present` boolean, resolving permissions across inline +
attached managed policies (`AWSBatchFullAccess`, `batch:*`, `ecs:*`).

| Field | Type | Meaning |
|-------|------|---------|
| `identity.escalation.passrole_submitjob.present` | bool | Principal has `iam:PassRole` (to a role whose effective perms exceed its own) + `batch:RegisterJobDefinition` + `batch:SubmitJob` (incl. via `batch:*`/`AWSBatchFullAccess`). Reused for `CTL.IAM.ESCALATE.PASSROLE.SUBMITJOB.001`. |
| `identity.escalation.passrole_runtask.present` | bool | Same for ECS: `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask` (incl. via `ecs:*`). `CTL.IAM.ESCALATE.PASSROLE.RUNTASK.001`. |

## Compound chain — `escalation_chain_present` inputs

The reasoning spec joins four conditions; the collector resolves each, treating
these as **sensitive instance-role access** (the FN traps), not just direct data
ARNs:

- direct data access (S3/EFS/Secrets Manager/KMS), **and**
- `ecs:*` on the instance role (lateral escalation to ECS task roles), **and**
- `iam:PassRole` on the instance role (extends the chain to a new resource).
