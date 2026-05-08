# z3-cognito-auth-chain

Two queries in one example. Together they isolate the
registration gate as the choke point in the Cognito
self-register-to-AWS-creds chain — and reveal that the
remediation didn't actually fix the auth role's permissions.

## The two queries

| Query | Question | What it isolates |
|---|---|---|
| `query-auth-chain.smt2` | Can someone authenticated against the Cognito identity pool reach broad S3? | The auth role's S3 grant — independent of how the visitor became authenticated |
| `query-self-register-chain.smt2` | Can an *anonymous* internet visitor reach broad S3 by registering at the user pool? | The full chain, gated on `self_registration_unrestricted` |

The auth chain assumes someone is authenticated by ANY means
(legitimate onboarding, SSO, IdP federation, self-
registration). The self-register chain adds the predicate
that an anonymous attacker can become authenticated without
admin approval.

## Verdict matrix

```
=== auth-chain (anyone authenticated reaches S3) ===
 writeup-config expected=sat z3=sat cvc5=sat OK
 remediated-config expected=sat z3=sat cvc5=sat OK

=== self-register-chain (anonymous reaches S3 by registering) ===
 writeup-config expected=sat z3=sat cvc5=sat OK
 remediated-config expected=unsat z3=unsat cvc5=unsat OK
```

## The pedagogical reveal — auth-chain stays SAT on remediated

The auth-chain is SAT on BOTH fixtures. Z3's witnesses show why:

**writeup-config** (the unsafe state):
```
identity_pool = arn:aws:cognito-identity:us-east-1:111122223333:identitypool/us-east-1:abc-app-pool
auth_role = arn:aws:iam::111122223333:role/Cognito_appAuth_Role
action = s3:*
resource = *
```

The auth role grants every S3 action on every bucket.

**remediated-config** (the supposedly fixed state):
```
identity_pool = arn:aws:cognito-identity:us-east-1:111122223333:identitypool/us-east-1:abc-app-pool
auth_role = arn:aws:iam::111122223333:role/Cognito_appAuth_Role
action = s3:GetObject
resource = arn:aws:s3:::app-user-data/${cognito-identity.amazonaws.com:sub}/*
```

The auth role STILL grants S3 access — narrowed to per-user
prefix scoping (the `${cognito-identity.amazonaws.com:sub}/*`
template), but still SAT against the auth-chain query. The
remediation didn't eliminate the role's S3 grant; it scoped
it.

The witness is the answer. The query asks "auth user reaches
some S3 resource"; the witness names *which* S3 access the
auth role currently holds. In the remediated config, that's
"per-user prefix" — legitimate use. In writeup, it's "all
buckets" — broken.

## What the self-register chain isolates

The auth chain alone doesn't distinguish writeup from
remediated. The self-register chain does: it adds one
conjunct gating on the user pool's
`self_registration_unrestricted` predicate. That predicate
fires only when `governance.self_registration_restricted =
false` — i.e. anyone-can-sign-up.

- writeup-config: pool admits self-registration → SAT
- remediated-config: pool restricts self-registration → UNSAT

The self-register chain is what the article calls the
exploitable case: **anonymous → register → authenticated →
auth role → S3**. Closing the registration gate breaks the
chain at step 2; the auth role's permissions can stay broken
without the chain being reachable from the internet.

This is the article's central beat: the choke point is the
registration gate, not the role's permissions. The
remediation flipped one boolean; the role is still a footgun
if any other onboarding path admits an attacker.

## Run

```bash
cd stave
make build
bash examples/z3-cognito-auth-chain/run.sh
```

Expected output (also captured in `expected/output.txt`):

```
=== auth-chain (anyone authenticated reaches S3) ===
 writeup-config expected=sat z3=sat cvc5=sat OK
 remediated-config expected=sat z3=sat cvc5=sat OK

=== self-register-chain (anonymous reaches S3 by registering) ===
 writeup-config expected=sat z3=sat cvc5=sat OK
 remediated-config expected=unsat z3=unsat cvc5=unsat OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (cross-check; decisive on this fixture)

cvc5 decides both queries on both fixtures because the
Cognito fact set is small (~30 assertions). The
`--finite-model-find` strategy that times out on the larger
Rhino fixture works fine here.

## Three Cognito chains, one attack surface

Together with `z3-cognito-unauth-chain`, this example covers
the full Cognito attack surface from the article:

| Chain | Visitor enters via | Step-1 predicate |
|---|---|---|
| `z3-cognito-unauth-chain` | anonymous | `allows_unauthenticated` |
| `z3-cognito-auth-chain` (auth-chain query) | authenticated by any means | (no gate) |
| `z3-cognito-auth-chain` (self-register query) | self-registered user | `self_registration_unrestricted` |

The remediated config closes the unauth chain
(`allow_unauthenticated_identities=false`) and the
self-register chain (`governance.self_registration_restricted=true`).
It does NOT close the auth chain — anyone authenticated
through any other onboarding path still reaches S3 via
the (narrowed) auth role.

## What this is not

- **Not a full attack-path validator.** SAT means the chain
 shape exists in the snapshot; not that an attacker
 necessarily executed it. The application code that wires
 the user pool to the identity pool, and the social-
 engineering or phishing path that gets the attacker to
 the sign-up page, are out of scope.

- **Not a replacement for the example's Z3 prover.**
 That prover (via `aclements/go-z3`) does the choke-point
 analysis the article describes — toggling each candidate
 fix, finding which ones break the chain. This SMT-LIB
 pair makes the same composition expressible through
 file-as-language-boundary so any solver consumes it; the
 iterative choke-point flow stays in the per-example
 go-z3 prover.

- **Not a determinism issue.** The auth-chain witnesses
 differ across fixtures (`s3:* / *` vs `s3:GetObject /
 per-user-prefix`) because the FIXTURES differ, not because
 the solver is non-deterministic. Same input, same output.
