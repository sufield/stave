# VPC Peering Exfiltration — Multi-Engine Analysis

Detection runs through three reasoning layers. CEL evaluates
the YAML controls' predicates and produces findings. The chain
engine composes them. External engines then consume the same
fact export (`stave export-sir`) for additional reasoning
dimensions.

## Writeup fixture

`fixtures/writeup-config/observations/` — peering connection
`pcx-0abc...` terminates in an account outside the
organization (`peer_account_in_org == false`), DNS resolution
from the remote side is enabled, and the production route
table targets the full peer VPC CIDR (`has_broad_destination
== true`).

| Engine | Verdict | Detail |
|---|---|---|
| **CEL** (built-in) | 2 findings | `CTL.VPC.PEERING.CROSSACCOUNT.001`, `CTL.VPC.PEERING.ROUTES.001` |
| **Chain engine** | 1 CRITICAL | `vpc_peering_exposure` (threshold 2 of 2, scope_field=`properties.network.peering.id`) |
| **Clingo** | 2 violation kinds | external-peering with broad route, plus DNS-resolution-from-external |
| **Soufflé** | n/a | no `vpc-peering-reach.dl` authored yet — single-asset domain, no per-element array facts to enumerate |
| **Encoding verifier** | 4/4 verifiable facts match | every projected fact traceable to its observation property |

### CEL (the YAML predicate evaluator)

```
CTL.VPC.PEERING.CROSSACCOUNT.001   HIGH
CTL.VPC.PEERING.ROUTES.001         MEDIUM
```

The two predicates target mutually exclusive `kind` values
(`peering_connection` vs `route_table`), so the chain joins
them via `scope_field` on `properties.network.peering.id`
rather than on `asset.ID` — both observations carry the same
peering connection ID at that path.

### Chain engine

```
vpc_peering_exposure
  threshold:           2 of 2
  controls_failing:    CROSSACCOUNT, ROUTES
  scope_field:         properties.network.peering.id
  compound_severity:   CRITICAL
```

### Clingo (`examples/clingo-constraints/ai-delegation-shadow.lp`)

```
violation: cross_account_peering_broad_route  (1)
    arn:aws:ec2:us-east-1:111122223333:vpc-peering-connection/pcx-0abc123def456789
violation: peering_dns_from_external_account  (1)
    arn:aws:ec2:us-east-1:111122223333:vpc-peering-connection/pcx-0abc123def456789
```

The Clingo rule `cross_account_peering_broad_route` joins
`has_peering_peer_in_org(_, "false")` with
`has_peering_route_broad(_, "true")` — that join answers the
chain question independently of asset-ID grouping. The
`peering_dns_from_external_account` rule fires on the related
secondary defect (DNS resolution from a non-org peer
amplifies the surface).

### Soufflé

No `vpc-peering-reach.dl` exists. The peering domain ships
scalar booleans only — there are no per-element array
properties on these assets the way `unused_services[]` exists
on roles or `external_principals[]` on buckets. A reachability
program here would compute counts over a single asset, which
is what Clingo already enumerates.

## Remediated fixture

`fixtures/remediated-config/observations/` — peer account is
inside the organization, DNS resolution disabled, route table
narrowed to a `/24` application subnet instead of the full
`/16` peer CIDR.

| Engine | Verdict |
|---|---|
| CEL | 0 findings |
| Chain engine | 0 chains |
| Clingo | (clean) — every rule body returns false |
| Encoding verifier | 4/4 facts match |

## What each engine adds

- **CEL** is the primary detection: it evaluates the two
  control predicates against the peering and route-table
  observations.
- **The chain engine** composes them via `scope_field` on the
  peering connection ID — without that, the two findings live
  on different asset IDs and the chain could never fire.
- **Clingo** restates the same join in ASP form. Where CEL +
  chain rely on `scope_field` to group, Clingo joins via the
  predicate body itself (`has_peering_peer_in_org(_, "false"),
  has_peering_route_broad(_, "true")`). Two independent paths
  to the same verdict — the kind of cross-check that catches
  a regression in either the predicate definitions or the
  chain wiring.

## Reproduce

```bash
cd <repo-root>/stave
make build

./stave export-sir --format jsonl \
    --observations examples/vpc-peering-exfiltration/fixtures/writeup-config/observations \
    --now 2027-01-01T00:00:00Z > /tmp/vpc.jsonl

.tools-venv/bin/python3 examples/clingo-constraints/run.py \
    "vpc-peering" /tmp/vpc.jsonl \
    examples/clingo-constraints/constraints.lp \
    examples/clingo-constraints/ai-delegation-shadow.lp
```
