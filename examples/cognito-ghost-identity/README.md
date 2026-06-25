# COGNITO-SSO-005 — ghost-identity-with-privileges reasoning spec

Three conditions on a Cognito User Pool create the worst case: an external IdP is
registered, there is no PreSignUp Lambda gate before user creation, and a
security-sensitive attribute is mapped from IdP claims. An attacker controlling
the IdP federates → a ghost identity is auto-created with the sensitive attribute
set from an attacker-controlled claim, with nothing gating it.

The finding is **per-IdP** — it names the specific IdP carrying the sensitive
mapping (the FN trap puts one safe and one risky IdP on the same pool).

## Engines
- `ghost_identity.dl` — Soufflé. `ghost_identity(pool, idp, attr, claim)`. Non-empty = FAIL.
- `query.smt2` — Z3, quantifier-free. `sat` = FAIL.

Collector signal: `identity.cognito.ghost_identity_chain_present` (read by
`CTL.COGNITO.FEDERATION.GHOST.IDENTITY.001`); composes SSO-001 (missing PreSignUp)
and SSO-002 (sensitive mapping).

## Run
```bash
./run.sh
```
Expected (`expected/output.txt`):
```
vuln   souffle=GHOST  z3=sat
fp     souffle=NONE   z3=unsat
fn     souffle=GHOST  z3=sat
```

- **vuln** — external IdPs, no PreSignUp, `PartnerIdP` maps `custom:role ← groups`.
- **fp** — PreSignUp gate present → chain broken (SSO-002 still fires on its own).
- **fn** — two IdPs, only `PartnerIdP` has a sensitive mapping (`custom:accessLevel`);
  the chain fires for `PartnerIdP` only, named in the output.

Inspired by Doyensec CloudsecTidbits No. 4 — *The Danger of Multi-SSO AWS Cognito
User Pools*.
