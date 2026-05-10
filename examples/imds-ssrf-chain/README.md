# EC2 IMDS SSRF Chain

Fixture-level demo of the existing
`chains/ec2_imds_container_escalation.yaml` compound chain (3
members, threshold=2, severity=high). The chain definition and
the EC2 IMDS controls already live in the catalog; this example
contributes the writeup / remediated observation pair, the
runner, and a multi-engine analysis.

## What it shows

An attacker exploits an SSRF vulnerability in an EC2-hosted
application to query the instance metadata service
(`169.254.169.254`). Because the instance still permits IMDSv1,
a single HTTP GET — no PUT-token round-trip — returns short-lived
AWS credentials for the instance's IAM role. The IMDS hop limit
above 1 means containers on the instance can also reach the
metadata service through the additional hop.

**This is the Capital One breach pattern** (2019, 100M+ records):
SSRF in a WAF → IMDSv1 → instance role credentials → S3.

## Chain composition

| Member | Asset | Property checked |
|---|---|---|
| `CTL.EC2.IMDSV2.001` | EC2 instance | `compute.network.imdsv2_required` |
| `CTL.EC2.IMDSV2.002` | EC2 instance | imdsv2_required AND container reaches IMDS via host or bridge+hop>1 |
| `CTL.EC2.IMDS.HOPLIMIT.001` | EC2 instance | `compute.ec2.imds_hop_limit_excessive` |

Threshold 2 of 3. `IMDSV2.001` and `IMDSV2.002` are mutually
exclusive on a single asset (`imdsv2_required` is `true` xor
`false`). The threshold is met by either pair:

- `{IMDSV2.001, HOPLIMIT.001}` — IMDSv1-still-allowed (this
  fixture; Capital One pattern)
- `{IMDSV2.002, HOPLIMIT.001}` — IMDSv2-but-containers-bypass
  (separate fixture; not shipped here — the IMDSv1 pattern is
  the one with historical weight)

## Run

```bash
cd <repo-root>/stave
make build
bash examples/imds-ssrf-chain/run.sh
```

Expected output:

```
writeup    → EC2 controls: [IMDS.HOPLIMIT.001, IMDSV2.001]
              chains: [ec2_imds_container_escalation] (high)
remediated → 0 EC2 findings, 0 chains
```

## Layout

```
examples/imds-ssrf-chain/
├── README.md                     — this file
├── run.sh                        — fmt-aware runner with interpretation
├── multi-engine-results.md       — Stave + external-engine analysis
└── fixtures/
    ├── writeup-config/
    │   └── observations/
    │       └── 2026-05-10T000000Z.json   — EC2 instance, IMDSv1 + hop>1
    └── remediated-config/
        └── observations/
            └── 2026-05-10T000000Z.json   — same shape, IMDSv2 + hop=1
```

## What this example does NOT do

Per the build spec's "What NOT to Do":

- **No core changes.** The chain definition and 3 EC2 IMDS
  controls already exist. This example contributes observation
  fixtures, a runner, and engine-result documentation.
- **No new controls authored.** The EC2 IMDS control set covers
  the catalog space.
- **No new Clingo / Prolog / PySAT / Z3 rules.** External engines
  that don't yet have an IMDS shape produce empty cells in the
  multi-engine table — those are engine-rule expansion items.
  See [`multi-engine-results.md`](./multi-engine-results.md)
  for the backlog.
- **Does not duplicate the ECS demo's IAM observation.** This
  fixture is EC2-instance-shaped (compute.kind=instance, ec2.*
  block, instance_profile_arn). The sibling
  `examples/ecs-ssrf-credential-theft/` uses ECS task-definition
  shape (container.kind=task_definition, task_role.is_overprivileged).

## Related

- `examples/ecs-ssrf-credential-theft/` — ECS variant (different
  metadata endpoint at `169.254.170.2`, different control set,
  same compound shape).
- `chains/ecs_ssrf_credential_theft.yaml` — sibling chain.
- `controls/iam/credential/CTL.IAM.CREDENTIAL.USERDATA.001.yaml` —
  the EC2-user-data leakage variant (NHI2 secret-leakage class).
- `examples/iam-21-privesc-5-patterns/` — broader IAM escalation
  surface that stolen credentials exploit.
