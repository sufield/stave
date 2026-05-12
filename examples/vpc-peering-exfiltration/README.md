# VPC Peering Exfiltration

Fixture-level demo of the existing
`chains/vpc_peering_exposure.yaml` compound chain. The catalog
already carries the chain (2 members, threshold=2,
severity=critical) and the underlying VPC peering / route table
controls; this example contributes the writeup / remediated
observation pair, the runner, and the interpretation.

## What it shows

A forgotten VPC peering connection — set up two years ago for a
vendor integration that has since ended — still bridges the
production VPC to an external AWS account. The production route
table still carries a route to the full peer VPC CIDR, so any
resource in prod has IP-layer reachability into the external
account's network. The external account's security posture is
outside organizational control. Data leaving via the peer looks
like a routine internal flow in the prod audit trail.

The chain `vpc_peering_exposure` composes two findings:

| Member | Asset | Property checked |
|---|---|---|
| `CTL.VPC.PEERING.CROSSACCOUNT.001` | peering connection | `network.peering.peer_account_in_org` |
| `CTL.VPC.PEERING.ROUTES.001` | route table | `network.peering_route.has_broad_destination` |

The two member predicates require **mutually exclusive `kind`
values** (`peering_connection` vs `route_table`), so the chain
sets `scope_field: properties.network.peering.id` — both
observations carry the peering connection ID at that path and
the chain engine groups them by the logical peering relationship
rather than by `asset.ID`. Threshold 2 of 2.

## Run

```bash
cd <repo-root>/stave
make build
bash examples/vpc-peering-exfiltration/run.sh
```

## Files

- `fixtures/writeup-config/observations/` — peer outside org +
  broad `/16` peering route ⇒ both controls fire, chain fires.
- `fixtures/remediated-config/observations/` — peer inside org +
  narrow `/24` peering route ⇒ both controls silent, chain
  silent.

## Why this matters

VPC peering is one of the few network primitives that lets a
compromise in an account outside your organization reach inside
your VPC at the IP layer. The peering connection itself is
explicit and reviewable; the *routing decision* that turns the
peering into a full network bridge often is not. The two-control
composition catches the configuration where both halves of that
decision are unsafe — a structural finding that single-resource
scanners miss because each property in isolation is normal.
