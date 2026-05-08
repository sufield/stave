# z3-cognito-unauth-chain — first multi-fact chain query

The first SMT query against Stave's facts export that reasons
**across services** instead of one-asset-at-a-time. Z3
composes four facts to determine whether an unauthenticated
visitor can reach IAM-granted S3 access through Cognito; CEL
evaluates each fact independently and never asks the
composition. This is the result no per-control evaluator
produces from a static snapshot.

## The chain

```
anonymous visitor
 → Cognito identity pool (allows_unauthenticated = true)
 → Cognito pool maps to (maps_unauth_to → IAM role)
 → IAM role grants (has_action s3:* / s3:Get* …)
 → on S3 resource (has_resource arn:aws:s3:…)
```

Four facts. Four different SIR-extracted predicates. One
quantified composition.

## What the query asks

Find `(pool, role, action, resource)` such that:

1. `pool` is an `aws_cognito_identity_pool` with
 `allows_unauthenticated = true`
2. `pool` `maps_unauth_to role`
3. `role` is an `aws_iam_role` with at least one `has_action` in
 `{s3:*, s3:GetObject, s3:ListBucket, s3:GetObjectVersion}`
4. `role` `has_resource` whose ARN starts with `arn:aws:s3:::`

If such a tuple exists in the snapshot, Z3 returns `sat` and
names it.

## Verdicts

| Fixture | Stave verdict | Expected | Z3 | cvc5 | Witness shape |
|---|---|---|---|---|---|
| `writeup-config` (allow_unauth=true, unauth role has s3:GetObject + s3:ListBucket on app-public-assets) | `CTL.COGNITO.SELFREG.001` fires on the *user pool* (self-registration), but no individual control fires on the unauth chain | **sat** | sat | sat | `pool=identitypool/abc, role=Cognito_appUnauth_Role, action=s3:GetObject, resource=arn:aws:s3:::app-public-assets` |
| `remediated-config` (allow_unauth=false, no unauth role mapping) | clean for this chain | **unsat** | unsat | unsat | n/a |

(The exact Z3 vs cvc5 witnesses differ — the formula has
multiple satisfying assignments; both solvers pick a valid
one. Verdict equality is what matters.)

## Why CEL doesn't say this

`CTL.COGNITO.SELFREG.001` fires on the writeup user pool
because self-registration is unrestricted. That's a per-asset
property check on the pool. It does NOT trace the chain
`pool → role → S3`.

`CTL.IAM.POLICY.RESOURCE.WILDCARD.001` would fire on
`Cognito_appAuth_Role` (the auth role with `s3:*` on `*`) but
NOT on `Cognito_appUnauth_Role` (whose policy is
narrowly-scoped: `s3:GetObject` + `s3:ListBucket` on a public
asset bucket). Per-asset, the unauth role's policy looks fine.

The composition — *that the unauth role is reachable without
authentication* — is the security property the chain query
exposes. The `app-public-assets` bucket is intentionally
public for CDN traffic, so the finding here is informational
("this is the reachability surface"), not necessarily a
violation. But the query's whole point is making the
reachability surface MECHANICALLY ENUMERABLE so security
review can compare it to intent — which CEL can't do.

The same query, run against a fixture where the unauth role
has access to `arn:aws:s3:::sensitive-data` (no public-read
intent, no wildcard policy), would return `sat` with the
sensitive bucket as the witness. That's the exposure no
per-control check catches today and what motivates the
SMT-LIB layer.

## Run

```bash
cd stave
make build
bash examples/z3-cognito-unauth-chain/run.sh
```

Expected (also captured in `expected/output.txt`):

```
writeup-config expected=sat z3=sat cvc5=sat OK
remediated-config expected=unsat z3=unsat cvc5=unsat OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (optional cross-check)

## What this is not

- **Not a complete reachability checker.** The chain stops at
 "role has S3 grant." A full reachability would also walk
 the `can_assume` graph (multi-hop role assumption); that
 needs the SIR's role-chain resolver to populate
 `IdentityFact.RoleChains` for Cognito principals, which it
 doesn't today. Worth the next iteration.

- **Not the full Cognito self-register chain.** The
 the article describes the full attack:
 `self-register → app client → identity pool → AUTH role →
 s3:*`. This query covers only the unauth half. A second
 query that uses `maps_auth_to` plus the user pool's
 `governance.self_registration_restricted` flag would cover
 the auth half — but that flag isn't in the projection yet
 either; another extension.

- **Not solver-specific.** Both Z3 and cvc5 produce the same
 verdict (with different but equally valid witnesses).
 Adding cvc5 to the cross-check this turn caught no
 encoding bugs — agreement validates the SMT-LIB is
 solver-portable for chain queries, not just leaf
 predicates.
