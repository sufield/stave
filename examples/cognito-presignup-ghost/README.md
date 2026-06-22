# Cognito Pre-Sign-Up Ghost Lambda — End-to-End

Demonstrates the full pipeline for `CTL.COGNITO.GHOST.PRESIGNUP.001`:

```
obs.json (collector-populated trigger booleans)
  -> stave apply  -> finding (writeup) | no finding (remediated)
  -> stave export-sir --format smt2  -> has_ghost_trigger / has_trigger_type / has_trigger_lambda_exists
```

This is the de-risk for Iteration 1 of the Cognito gap closure
plan: it confirms the existing per-asset CEL evaluation +
SIR-projector pattern works for ghost references, and that the
SMT-LIB surface carries enough fact vocabulary for downstream
Z3 / Datalog reasoning.

## Observation contract

The collector that reads from `aws_cognito_user_pool` populates
the following derived booleans on each user pool asset:

| Property path | Type | Meaning |
|---|---|---|
| `properties.identity.kind` | `"cognito_user_pool"` | Asset shape discriminator |
| `properties.identity.cognito.trigger_type` | string | `pre_sign_up`, `pre_authentication`, ... — one of the 10 trigger names |
| `properties.identity.cognito.trigger_lambda_arn` | string | The ARN configured in `lambda_config.<trigger_type>` |
| `properties.identity.cognito.trigger_lambda_exists` | bool | Whether the Lambda asset exists in the same observation |
| `properties.identity.cognito.has_ghost_trigger` | bool | `trigger_lambda_exists == false` AND `lambda_config.<trigger_type>` is set |

The collector does the cross-asset existence check; Stave
evaluates the booleans. Same pattern as
`CTL.CLOUDFRONT.GHOST.LOGBUCKET.001` (uses
`cdn.cloudfront.has_ghost_log_bucket`) and
`CTL.S3.BUCKET.TAKEOVER.001` (uses `s3_ref.bucket_exists`).

## Per-trigger-type generic check

The 10 Lambda triggers (`pre_sign_up`, `pre_authentication`,
`post_authentication`, `custom_message`, `post_confirmation`,
`define_auth_challenge`, `create_auth_challenge`,
`verify_auth_response`, `pre_token_generation`, `user_migration`)
all share the same observation shape — a single
`trigger_type` discriminator selects which trigger the asset
represents. Each YAML control matches on:

```yaml
- field: properties.identity.cognito.trigger_type
  op: eq
  value: <trigger_name>
- field: properties.identity.cognito.has_ghost_trigger
  op: eq
  value: true
```

The SIR projector emits one binary `has_trigger_type` predicate
that carries the trigger name as the second argument, so a
single SMT-LIB declaration covers all 10 controls. Compound
queries like `cognito_ghost_authflow` (pre-auth + custom-auth
challenges all dead) follow naturally from the per-asset facts.

## Run

```bash
cd <repo-root>/stave
make build

# Writeup: pre-sign-up Lambda has been deleted
./stave apply \
    --observations examples/cognito-presignup-ghost/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z \
    --format json | jq '.findings[] | select(.control_id == "CTL.COGNITO.GHOST.PRESIGNUP.001")'

# Remediated: same pool, but the Lambda asset is in the observation
./stave apply \
    --observations examples/cognito-presignup-ghost/fixtures/remediated-config/observations \
    --now 2026-05-09T12:00:00Z \
    --format json | jq '.findings | map(select(.control_id == "CTL.COGNITO.GHOST.PRESIGNUP.001")) | length'
# 0

# SMT-LIB surface — feeds Z3 / Datalog
./stave export-sir \
    --observations examples/cognito-presignup-ghost/fixtures/writeup-config/observations \
    --now 2026-05-09T12:00:00Z \
    --format smt2 | grep -E 'has_ghost_trigger|has_trigger_'
```

## Why this de-risks Iteration 1

1. **Pattern fits.** All 15 cognito ghost controls already pass
   inline tests; this fixture confirms the same booleans flow
   through `stave apply` (full pipeline, not just CEL eval).
2. **SMT contract is stable.** The new `has_ghost_trigger`,
   `has_trigger_type`, `has_trigger_lambda_exists` predicates
   join the baseline-declared set, so downstream queries can
   reference them portably.
3. **Generic-checker plan is sound.** One SMT predicate covers
   all 10 trigger variants because `trigger_type` is the
   discriminator. The 15 control YAMLs in `controls/cognito/ghost/`
   reuse the same predicate shape — no per-trigger Stave
   plumbing needed.

## Open question for the rest of Iteration 1

The current convention assumes the **collector** populates
`trigger_lambda_exists` and `has_ghost_trigger` by checking
the Lambda asset list. If a user authors observations by hand
or runs Stave against a feed that doesn't pre-compute these
booleans, ghost detection silently passes. A future Stave-side
enricher could re-derive the booleans from raw `lambda_config`
ARNs cross-referenced with `aws_lambda_function` assets in the
same snapshot — same semantics, but collector-independent. Out
of scope for this de-risk; flag for the broader collector
contract review.
