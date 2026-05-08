# Example — Cognito MFA + Advanced Security

Demonstrates the `cognito-no-mfa-advanced-security`
pattern using Stave's library API, grounded in **HackerOne report
[bomma](https://hackerone.com/reports/bomma)** (a Cognito
account-takeover via email-alias trust + no MFA).

The bug: a Cognito user pool authenticates customer-facing
sessions but has `MfaConfiguration: OFF` and
`AdvancedSecurityMode: OFF`. The sole authentication
factor is the user's password. Credential stuffing,
password spraying, and phishing-recovered passwords all
land directly in authenticated sessions; Cognito's
risk-based response (which would otherwise add MFA
challenges or block suspicious sign-ins) is disabled.

## Prerequisites

This example's `z3prove/` binary links against libz3 via CGO.
Install the development headers before running:

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y libz3-dev pkg-config` |
| macOS (Homebrew) | `brew install z3 pkg-config` |

Then build with `CGO_ENABLED=1 go run .` from inside `z3prove/`.
The Stave binary itself has no libz3 dependency; only the
per-example Z3 prover does. See [`../PREREQUISITES.md`](../PREREQUISITES.md)
for other platforms (Fedora, Arch, nix, Debian) and for the
prerequisites of the SMT CLI / Soufflé / Prolog / Python-venv
examples.

## What it does

Loads two fixture snapshot directories — fixtures/before
(MFA off + Advanced Security off) and fixtures/after
(both on) — and asserts that `CTL.COGNITO.MFA.001` fires
on the first and is silent on the second.

The example is scoped to `CTL.COGNITO.MFA.001` for the
cleanest narrative; the fixture also flips
`advanced_security.enabled` so the article can frame the
*pair* of weakening defaults (MFA + adaptive risk) as a
single configuration drift. Stave's separate
`CTL.COGNITO.ADVANCED.SECURITY.001` control would fire
on the same fixture if the example pulled it in.

## Run

From `stave/`:

```bash
go run ./examples/cognito-no-mfa-advanced-security # both phases
go run ./examples/cognito-no-mfa-advanced-security before # MFA-off only
go run ./examples/cognito-no-mfa-advanced-security after # remediated only
```

## Expected output

```
=== before (MFA off, advanced security off) ===
 status: NON_COMPLIANT total_assets=1 violations=1
 CTL.COGNITO.MFA.001 fired on 1 asset(s):
 - arn:aws:cognito-idp:us-east-1:111122223333:userpool/us-east-1_acmeApp severity=high exposure_score=76.64
 assertion: fires=true (expected) ✓

=== after (MFA enforced, advanced security on) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.COGNITO.MFA.001: no findings
 assertion: fires=false (expected) ✓
```

## The Predicate

```yaml
unsafe_predicate:
 all:
 - field: properties.identity.kind
 op: eq
 value: user_pool
 - field: properties.identity.auth.mfa_enforced
 op: eq
 value: false
```

Two leaf clauses: the asset is a user pool, and MFA is
not enforced. Severity is `high` — single-factor auth on
a customer-facing pool is a credential-stuffing target,
but the unsafe state is *one factor away* from
multi-factor; the control fires on the capability gap,
not on a confirmed compromise.

## Why Z3 doesn't help

Same answer as the other presence-check iterations
(this example, this example, this example, this example): the collector observes
two booleans (`mfa_enforced`, `advanced_security.enabled`)
and emits them. CEL's predicate is a leaf check. There's
no logical search space, no quantification.

A different question — "given this user pool's
auth-factor configuration plus its app client list and
their `ExplicitAuthFlows`, can a session bypass MFA via a
non-MFA flow?" — *would* be reachability-shaped. That's
the territory of `CTL.COGNITO.MFA.ENFORCE.001` (which
checks app-client flow configuration); not in scope here.

## Layout

```
examples/cognito-no-mfa-advanced-security/
├── README.md
├── main.go
├── controls/
│ └── CTL.COGNITO.MFA.001.yaml
├── fixtures/
│ ├── before/observations/{T1,T2}.json # mfa_enforced=false × 2 weeks
│ └── after/observations/{T1,T2}.json # mfa_enforced=true × 2 weeks
└── expected/
 ├── before-output.txt
 └── after-output.txt
```

## Where this fits

No new `pkg/stave` API was needed. Phase C is the
article in `channels/devto/`, framing Cognito as the
identity perimeter and MFA + Advanced Security as the
two settings whose default-off posture turns
account-takeover from "hard" into "credential-stuffing
target."
