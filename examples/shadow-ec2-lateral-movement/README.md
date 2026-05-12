# Shadow EC2 Lateral Movement

Fixture-level demo of the new
`chains/shadow_ec2_lateral_movement.yaml` compound chain
(3 members, threshold=3, severity=critical). The catalog already
carries the underlying EC2 controls; this example contributes
the chain definition that joins three structural axes onto a
single EC2 instance, plus the writeup / remediated observation
pair, the runner, and the interpretation.

## What it shows

A dormant test instance that became the cheapest path into
production:

- Stopped for 180 days — outside monitoring scope
- IAM instance profile is overprivileged — broader than the
  original migration required
- ENIs span two subnets — staging *and* production

The chain `shadow_ec2_lateral_movement` composes three findings
on a single EC2 instance asset:

| Member | Property checked |
|---|---|
| `CTL.EC2.INSTANCE.STOPPED.AGED.001` | `compute.instance.stopped_age_exceeds_threshold` |
| `CTL.EC2.PROFILE.OVERBROAD.001` | `compute.instance_profile.is_overprivileged` |
| `CTL.EC2.NETWORK.DUALHOMED.001` | `compute.instance.spans_security_zones` |

All three predicates require `kind == instance`, so threshold-3
grouping by `asset.ID` works directly — no `scope_field` needed.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/shadow-ec2-lateral-movement/run.sh
```

## Why this matters

Single-resource scanners produce three separate tickets:

- The lifecycle scanner reports a stopped instance.
- The IAM scanner reports an overbroad role.
- The VPC scanner reports a dual-homed ENI.

None of them joins these onto the same instance asset and
reports the actual story — the dormant instance + the broad
role + the dual-homed network position together are a
production pivot. Stave's compound output surfaces the
composition as a single CRITICAL finding, with the three
individual controls visible as the supporting evidence.

The companion chain `ec2_network_pivot` also fires on the
writeup as a true co-finding (it shares the DUALHOMED member);
the runner shows both. Remediation drives all three predicates
to false and both chains go silent.
