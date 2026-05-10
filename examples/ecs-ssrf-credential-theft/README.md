# ECS SSRF Credential Theft

Fixture-level demo of the existing
`chains/ecs_ssrf_credential_theft.yaml` compound chain. The
catalog already carries the chain (3 members, threshold=2,
severity=critical) and the 48 ECS controls; this example
contributes the writeup / remediated observation pair, the
runner, and a multi-engine analysis.

## What it shows

An attacker exploits an SSRF vulnerability in an ECS-hosted
application to reach the task metadata endpoint
(`169.254.170.2`), retrieves the task role's short-lived AWS
credentials, and exfiltrates them through the security group's
unrestricted egress.

The chain `ecs_ssrf_credential_theft` composes three findings:

| Member | Asset | Property checked |
|---|---|---|
| `CTL.ECS.TASKMETADATA.001` | task definition | `container.task_role.is_overprivileged` |
| `CTL.ECS.METADATA.CREDENTIAL.001` | task definition | `container.metadata.credential_scoping_enabled` |
| `CTL.VPC.SG.EGRESS.001` | security group | `network.egress.unrestricted_all_ports` |

Threshold 2 of 3 — the two ECS controls fire on the same
task-definition asset and meet the threshold; the SG control
adds the exfiltration leg of the attack story.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/ecs-ssrf-credential-theft/run.sh
```

Expected output:

```
writeup    → ECS+VPC controls: [METADATA.CREDENTIAL.001, TASKMETADATA.001, VPC.SG.EGRESS.001]
              chains: [ecs_ssrf_credential_theft]
remediated → 0 ECS/VPC findings, 0 chains
```

## Layout

```
examples/ecs-ssrf-credential-theft/
├── README.md                     — this file
├── run.sh                        — fmt-aware runner with interpretation
├── multi-engine-results.md       — Stave + external-engine analysis
└── fixtures/
    ├── writeup-config/
    │   └── observations/
    │       └── 2026-05-10T000000Z.json   — task def + SG with all 3 misconfigs
    └── remediated-config/
        └── observations/
            └── 2026-05-10T000000Z.json   — same shape, predicates flipped
```

## What this example does NOT do

Per the build spec's "What NOT to Do":

- **No core changes.** The 3 chain controls + the chain definition
  already exist in the catalog. This example contributes
  observation fixtures, a runner, and engine-result documentation.
- **No new controls authored.** The 48 ECS controls already cover
  the catalog space.
- **No new Clingo / Prolog / PySAT / Z3 rules.** External engines
  that don't yet have an `ecs_ssrf_credential_theft` shape produce
  empty cells in the multi-engine table — those are engine-rule
  expansion items, not this example's scope. See the backlog
  section in [`multi-engine-results.md`](./multi-engine-results.md).

## Why this matters

ECS task metadata credential theft is the container-equivalent of
the EC2 IMDSv1 attack that powered the Capital One breach — but
ECS task metadata has no IMDSv2-style token mechanism. The
mitigation is the chain-shape composition this control set
captures: scope the task role, restrict which containers reach
the metadata endpoint, lock down egress. Any one of the three
breaks the chain; the chain fires when ≥2 conditions are present.

## Related

- `chains/ec2_imds_container_escalation.yaml` — sibling chain for
  the EC2 IMDS variant of the same attack.
- `examples/iam-21-privesc-5-patterns/` — the broader IAM
  escalation surface that stolen credentials exploit.
