# Cognito Self-Register → Self-Promote → AWS Credentials

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

## What this demonstrates

Serj Novoselov's 2023 Medium writeup ("Attacking AWS |
Common Cognito Misconfigurations") describes a four-stage
attack against a Cognito-protected application using
nothing but the AWS CLI:

```
Stage 1: aws cognito-idp sign-up (self-register)
Stage 2: aws cognito-idp update-user-attributes (self-promote)
Stage 3: aws cognito-identity get-credentials-for-identity (creds)
Stage 4: AWS API call with the temporary credentials (resource access)
```

Four CLI commands. Zero starting credentials. On the
writeup's configuration the chain ends with `s3:*` on
every bucket in the account.

## Five Z3 verdicts on the writeup config

| Finding | Verdict | Witness |
|---|---|---|
| 1 — self-registration possible | **SAT** | `allow_admin_create_user_only=false`, public client, no pre-signup Lambda |
| 2 — sensitive attribute writable | **SAT** | `custom:role`, `email`, `custom:is_premium`, no pre-token Lambda |
| 3 — credentials reach sensitive resources | **SAT** | both Path A (unauth) and Path B (auth) — `s3:*` on `*` |
| 4 — compound chain | **SAT** | F1 ∧ F2 ∧ F3 |
| 5 — choke-point analysis | **3 of 5** candidate fixes break the chain individually |

## On the remediated config

All four primary findings flip to UNSAT.

## The choke-point analysis (this iteration's distinguishing feature)

For each candidate single-change fix, the prover toggles
the fix on the writeup config and re-runs the chain.
Fixes that flip the chain from SAT to UNSAT are choke
points.

```
[CLOSED] set allow_admin_create_user_only=true
 stage 1 closed — no self-registration
[CLOSED] remove sensitive attrs from app client write_attributes
 stage 2 closed — no self-promotion
[CLOSED] configure pre-token-generation Lambda validator
 stage 2 closed — attribute changes validated
[OPEN ] set allow_unauthenticated_identities=false
 path A of stage 3 closed (path B remains)
[OPEN ] scope authenticated role to non-sensitive resources
 path B of stage 3 closed
```

Three of five collapse the chain individually. The
remaining two are partial fixes — stage 3 has two
independent paths (unauth and auth-via-self-register);
closing either alone leaves the other open.

The cheapest fix is row 1: one boolean flip in the
user-pool config. One Terraform attribute change. No
IAM rework, no Lambda authoring, no role rescoping.
**One setting. Chain collapses.** That is the
iteration's central teaching beat.

## CEL side — `main.go`

Scoped to `CTL.COGNITO.SELFREG.001`. Reads
`identity.governance.self_registration_restricted`. On
writeup: false → fires. On remediated: true → silent.

```bash
go run ./examples/cognito-self-register-to-aws-creds
```

## Z3 prover — `z3prove/`

Five queries × two configs plus the choke-point
analysis. Prerequisites: `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/cognito-self-register-to-aws-creds/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

## Sensitive-attribute registry

The Z3 program ships a static registry of Cognito user
attributes that imply privilege escalation or account
takeover when writable:

```go
"custom:role": "privilege_escalation",
"custom:admin": "privilege_escalation",
"custom:is_admin": "privilege_escalation",
"custom:is_premium": "privilege_escalation",
"custom:debug_mode": "privilege_escalation",
"custom:permissions": "privilege_escalation",
"custom:access_level": "privilege_escalation",
"email": "account_takeover",
"email_verified": "verification_bypass",
"phone_number": "mfa_bypass",
"phone_number_verified": "mfa_bypass",
```

When an organisation adds custom attributes, they add
them to this registry. Z3 immediately checks the new
attribute against every fixture.

## Layout

```
examples/cognito-self-register-to-aws-creds/
├── README.md
├── main.go # CEL foil
├── controls/
│ └── CTL.COGNITO.SELFREG.001.yaml
├── fixtures/
│ ├── writeup-config/observations/{T1,T2}.json
│ └── remediated-config/observations/{T1,T2}.json
├── z3prove/
│ ├── go.mod
│ └── main.go # 5 queries × 2 configs + choke point
└── expected/
 ├── cel-output.txt
 └── z3-output.txt
```

## Source

"Attacking AWS | Common Cognito Misconfigurations" —
Medium, June 2023, by Serj Novoselov.

## Where this fits

Three notable structural beats: compound chain across
four Cognito boundaries, choke-point analysis as a
new query pattern, and the sensitive-attribute
registry.
