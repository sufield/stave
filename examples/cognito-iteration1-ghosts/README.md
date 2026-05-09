# Cognito Iteration 1 — All 14 Ghost Controls + Compound Invariants

End-to-end fixtures for the full Iteration 1 ghost-control set
plus the two compound chain invariants. Composes with
`examples/cognito-presignup-ghost/` (the original PRESIGNUP
de-risk).

```
14 individual controls   (writeup → all fire ; remediated → none fire)
 1 compound invariant    (IDCHAIN → fires correctly on writeup)
 1 compound invariant    (AUTHFLOW → architectural gap, see below)
```

## Controls covered

### 9 Lambda-trigger ghosts

Same observation shape; `trigger_type` is the discriminator.

| Control | trigger_type |
|---|---|
| `CTL.COGNITO.GHOST.PREAUTH.001` | `pre_authentication` |
| `CTL.COGNITO.GHOST.POSTAUTH.001` | `post_authentication` |
| `CTL.COGNITO.GHOST.CUSTOMMSG.001` | `custom_message` |
| `CTL.COGNITO.GHOST.POSTCONFIRM.001` | `post_confirmation` |
| `CTL.COGNITO.GHOST.DEFINEAUTH.001` | `define_auth_challenge` |
| `CTL.COGNITO.GHOST.CREATEAUTH.001` | `create_auth_challenge` |
| `CTL.COGNITO.GHOST.VERIFYAUTH.001` | `verify_auth_challenge_response` |
| `CTL.COGNITO.GHOST.PRETOKEN.001` | `pre_token_generation` |
| `CTL.COGNITO.GHOST.USERMIGRATE.001` | `user_migration` |

(`CTL.COGNITO.GHOST.PRESIGNUP.001` lives in the sibling
`cognito-presignup-ghost/` example — same shape.)

### 5 non-Lambda ghosts

| Control | Boolean |
|---|---|
| `CTL.COGNITO.GHOST.IDPOOL.001` | `properties.identity.cognito.has_ghost_user_pool` (kind: `cognito_identity_pool`) |
| `CTL.COGNITO.GHOST.SAMLMETA.001` | `properties.identity.cognito.has_ghost_saml_metadata` |
| `CTL.COGNITO.GHOST.DOMAINCERT.001` | `properties.identity.cognito.has_ghost_domain_cert` |
| `CTL.COGNITO.GHOST.DOMAINDNS.001` | `properties.identity.cognito.has_ghost_domain_dns` |
| `CTL.COGNITO.GHOST.RESOURCESRV.001` | `properties.identity.cognito.has_ghost_resource_server` (kind: `cognito_user_pool_client`) |

### 2 compound chains

Both chains use the new `scope_field:
properties.identity.cognito.user_pool_id` directive (see "Chain
scope_field" below).

| Chain | Members | Threshold | Fires? |
|---|---|---|---|
| `cognito_ghost_idchain` | IDPOOL, SAMLMETA, DOMAINCERT, DOMAINDNS | 2 | **YES** — SAML/cert/DNS ghosts on the user pool trip 3-of-4 |
| `cognito_ghost_authflow` | PREAUTH, DEFINEAUTH, CREATEAUTH, VERIFYAUTH | 2 | **YES** — 4 trigger ghosts on a shared `user_pool_id` reunite via scope_field |

## Run

```bash
cd <repo-root>/stave
make build

# Writeup: 14 individual ghost findings + 1 compound (IDCHAIN)
./stave apply \
    --observations examples/cognito-iteration1-ghosts/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ghosts: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.GHOST."))] | map(.control_id) | sort | unique), compounds: (.chain_findings // [] | map(.chain))}'

# Remediated: zero findings, zero chains
./stave apply \
    --observations examples/cognito-iteration1-ghosts/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ghost_count: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.GHOST."))] | length), chain_count: (.chain_findings // [] | length)}'

# AUTHFLOW gap demo: same user_pool_id, 4 trigger ghosts, 0 chain firings
./stave apply \
    --observations examples/cognito-iteration1-ghosts/fixtures/authflow-gap-config/observations \
    --now 2026-05-09T12:00:00Z --allow-unknown-input --format json \
  | jq '{ghost_count: ([.findings[] | select(.control_id | startswith("CTL.COGNITO.GHOST."))] | length), chain_count: (.chain_findings // [] | length)}'
```

Expected:

```
writeup     → ghosts: 14 distinct, compounds: ["cognito_ghost_idchain"]
remediated  → ghost_count: 0,  chain_count: 0
authflow    → ghost_count: 4,  chains: ["cognito_ghost_authflow"]
```

## Chain scope_field

Both chains declare:

```yaml
scope_field: properties.identity.cognito.user_pool_id
```

Why this is needed: each Lambda-trigger ghost predicate filters
on `properties.identity.cognito.trigger_type` (a single string
field), so one logical user pool with N broken triggers must
surface as N distinct Stave assets — one per trigger. Without
`scope_field`, the chain engine groups failing controls by
`asset.ID` and never sees ≥2 of these controls firing on a
single asset. The chain `cognito_ghost_authflow` would never
fire on any input.

`scope_field` reroutes the grouping. When set, the chain engine
asks the per-snapshot `risk.ScopeResolver` to read the
property at that path on each failing asset. Failing controls
that resolve to the same scope value bucket together. The
resulting `CompoundFinding` carries:

- `scope_id` — the resolved scope value (e.g. `"authflow-pool"`)
- `scope_field` — the path that produced it
- `contributing_assets` — every `asset.ID` that fed the chain

When the resolver returns false for a failing asset (e.g. the
identity pool's `user_pool_id` field is named `linked_user_pool_id`,
not `user_pool_id`, in the current property contract), that
failing control falls back to `asset.ID` grouping for the chain.
This is the case for `cognito_ghost_idchain.IDPOOL.001` in the
writeup fixture: it fires on the identity-pool asset, falls back
to its asset.ID, and ends up in a bucket of 1 (threshold not
met). The user pool's 3 ghost flags (SAML/cert/DNS) resolve to
`user_pool_id` "us-east-1_acmeApp_idchain" and trip the chain
threshold from that bucket.

A future collector contract can populate
`properties.identity.cognito.user_pool_id` on identity-pool
assets too (with the linked pool's ID), making the IDPOOL
finding a contributor rather than a missing safeguard. No chain
or control YAML change needed at that point.

## What this de-risked

- The `chain_engine.go:DetectChains` per-asset.ID grouping was
  too tight for any chain whose member predicates surface one
  logical resource as multiple Stave assets.
- Adding `scope_field` to `ChainDefinition` and threading a
  snapshot-backed `ScopeResolver` through the workflow lets
  chain authors declare the right grouping in YAML — without
  touching control YAMLs or the collector contract.
- AUTHFLOW now fires on the gap fixture
  (`fixtures/authflow-gap-config/`) — confirmed empirically.

## What this de-risks

- **All 14 ghost YAMLs evaluate correctly** under `stave apply`
  with realistic obs.json. No control YAML edits needed for the
  remaining 14 controls; the existing inline tests carried over
  to full pipeline behavior.
- **The IDCHAIN compound fires** on the multi-flag user-pool
  asset, validating that the chain engine handles the same-asset
  case correctly.
- **The AUTHFLOW compound is the one architectural gap**,
  surfaced empirically with a focused fixture and a documented
  fix path. Iteration 1 can ship the 14 individual controls
  without blocking on the chain fix; the chain ships once
  option 1 above lands.
