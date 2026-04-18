# ECS awsvpc IMDS reachability — scope notes

This note records why the IMDSv2 container-bypass compound
(`CTL.EC2.IMDSV2.002`) does not cover ECS awsvpc network mode,
despite awsvpc tasks being able to reach the EC2 instance's IMDS
endpoint by default.

## Finding

ECS tasks running on EC2 with `awsvpc` network mode **can reach the
underlying EC2 instance's IMDS endpoint (169.254.169.254) by
default**. The task metadata endpoint (169.254.170.2) is separate
and always available.

**Evidence:**

- AWS ECS developer guide, *Task IAM roles*:
  <https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html>
  states verbatim: *"To prevent containers run by tasks that use the
  `awsvpc` network mode from accessing the credential information
  supplied to the Amazon EC2 instance profile, while still allowing
  the permissions that are provided by the task role, set the
  `ECS_AWSVPC_BLOCK_IMDS` agent configuration variable to `true`."*
  The same page warns that on EC2/External container instances,
  "containers can potentially access credentials for other tasks on
  the same container instance [and] permissions assigned to the ECS
  container instance role."
- amazon-ecs-agent source (`agent/config/config.go`,
  `agent/config/types.go`): `ECS_AWSVPC_BLOCK_IMDS` default is
  `false`. Default behavior = instance IMDS reachable from awsvpc.
- Prowler has **no** check for `ECS_AWSVPC_BLOCK_IMDS` or awsvpc IMDS
  reachability in its ECS service provider. This is a Prowler gap.

## Why `CTL.EC2.IMDSV2.002` does not cover it

The compound's bridge-network branch is gated on
`compute.network.imds_hop_limit > 1`. That gate reflects how the
IMDSv2 response-hop-limit feature defends against bridge-routed
containers: the bridge adds a hop, and hop limit 1 makes the IMDS
response TTL expire at the bridge.

awsvpc does not use the docker bridge. Each task gets a dedicated
ENI attached directly to the instance. AWS does not list hop limit
as a mitigation for awsvpc in any documented place; the documented
mitigation is the agent flag above. Encoding awsvpc into the
existing compound's bridge branch would produce false negatives:
operators with awsvpc tasks + hop limit 1 would see no finding, but
the attack path is still live.

## Shape a correct awsvpc control would need

Two viable designs, both expanding the compound beyond the
"mirror bridge-network logic" scope of the revised methodology
constraint:

1. **Conservative — treat awsvpc like host network.** Adds
   `compute.containers.has_awsvpc_network: bool`. Fires whenever
   awsvpc is present on an instance whose IMDS is enforced but not
   blocked, regardless of hop limit. Matches AWS's own guidance
   framing.

2. **Flag-aware — model the agent variable.** Adds both
   `compute.containers.has_awsvpc_network: bool` and
   `compute.containers.ecs_awsvpc_block_imds_enabled: bool`. Fires
   on awsvpc when the block flag is false. Tighter signal, but
   demands an extractor that reads ECS agent configuration.

Either is defensible. The choice hinges on whether extractors can
reliably observe the agent config variable. That determination
belongs in the iteration that implements awsvpc coverage; it is
not resolved here.

## Deferred

No code changes in this iteration. When a disclosed incident or
methodology source specifically grounds the awsvpc IMDS bypass
against a live workload — Prowler adding the check, an AWS security
bulletin, or a disclosed breach — pick one of the two designs above
and extend the compound. Until then the attack surface is documented
in AWS's own guide and in this note.

## Related

- `CTL.EC2.IMDSV2.001` — basic HttpTokens=required enforcement.
- `CTL.EC2.IMDSV2.002` — container-bypass compound for
  bridge-network and host-network cases on EC2.
- Contract fields: `compute.containers.*`,
  `compute.network.imds_hop_limit`.
