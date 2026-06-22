# Cognito Iteration 9 — Lifecycle and Orphaned Resources

End-to-end fixtures for the Iteration 9 dormant-resource /
orphan-reference controls. Spans four asset types with one
control per type (mostly). No compound chain.

```
6 individual controls   (writeup → all fire ; remediated → 0)
0 compound chains
```

## Controls covered

| Control | Asset type | Predicate signal |
|---|---|---|
| `CTL.COGNITO.ORPHAN.NOCLIENTS.001` | `aws_cognito_user_pool` (`kind: user_pool`) | `has_app_clients == false` |
| `CTL.COGNITO.ORPHAN.NOUSERS.001`   | `aws_cognito_user_pool` (`kind: user_pool`) | `is_user_pool_dormant == true` (90+ days no logins) |
| `CTL.COGNITO.ORPHAN.TRIGGERS.001`  | `aws_cognito_user_pool` (`kind: user_pool`) | `has_orphan_triggers == true` (Lambda triggers on dormant pool) |
| `CTL.COGNITO.ORPHAN.CLIENT.001`    | `aws_cognito_user_pool_client` (`kind: cognito_app_client`) | `is_app_client_dormant == true` |
| `CTL.COGNITO.ORPHAN.IDPOOL.001`    | `aws_cognito_identity_pool` (`kind: cognito_identity_pool`) | `has_identity_providers == false` |
| `CTL.COGNITO.ORPHAN.RESOURCESRV.001` | `aws_cognito_resource_server` (`kind: cognito_resource_server`) | `is_resource_server_orphan == true` |

## Run

```bash
cd <repo-root>/stave
make build

./stave apply \
    --observations examples/cognito-iteration9-orphans/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.ORPHAN."))] | map(.control_id) | sort | unique), chains: (.chain_findings // [] | map(.chain))}'

./stave apply \
    --observations examples/cognito-iteration9-orphans/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --format json \
  | jq '{ctls: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.ORPHAN."))] | length), chains: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → 6 ctls, 0 chains
remediated  → 0, 0
```

## Architecture observation: new asset types

Iteration 9 introduces two asset types not seen in earlier
iterations:

- `aws_cognito_user_pool_client` — first appeared in Iteration
  4 for OAuth-flow / token / callback-URL controls; reused
  here for the dormant-client check.
- `aws_cognito_resource_server` — **new**. The catalog adds
  this for the orphan-resource-server check (a resource
  server is orphan when no app client references its
  scopes). The collector enumerates resource servers from
  `aws_cognito_resource_server` (or its API equivalent) and
  cross-checks against app clients' `allowed_o_auth_scopes`,
  stamping `is_resource_server_orphan` on the resource-server
  asset. Same denormalisation pattern as previous iterations.

The fixture writeup uses 4 distinct asset entries because
the 6 controls split across 4 asset types. The
account-aggregation pattern from Iteration 8 doesn't apply
here — these are per-resource lifecycle states, not
account-wide posture.

## Why no compound chain

The plan listed 0 compound chains for Iteration 9 and the
catalog ships none. Each orphan / dormant condition is
independently actionable; "dormant pool AND orphan client"
doesn't escalate severity. A future "lifecycle decay"
compound (similar to existing `cf_lifecycle_debris` /
`config_lifecycle_decay` chains in the broader catalog)
could compose Iteration 9 findings with broader
account-posture orphans, but that's a cross-iteration
concern.

## What this iteration shipped

- **6 individual controls** for dormant resources / orphan
  references fire end-to-end across 4 Cognito asset types.
- **One new asset type** (`aws_cognito_resource_server`)
  enters the catalog vocabulary.
- **No compound chain** — by design.

No Stave engine changes required. Same trajectory as
Iterations 3-8.
