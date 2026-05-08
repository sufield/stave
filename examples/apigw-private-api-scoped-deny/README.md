# API Gateway Private API: Scoped Deny Gap Proof

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

A 2023 Medium tutorial walks through securing a private
API Gateway with VPC endpoints. The configuration works
for the intended use case — an EC2 host in
`vpc-0b52ca08e7db8531f` invokes the API; the EC2 has the
right security-group rules; the resource policy
restricts to that VPC. As an infrastructure tutorial, it
delivers what it promises.

As a security artefact, three policy choices in the
published walkthrough merit formal scrutiny:

1. The Deny condition uses `aws:sourceVpc` instead of
 `aws:sourceVpce` — restricting by entire VPC instead
 of by specific endpoint.
2. The Allow and Deny statements share an identical
 `Resource: "execute-api:/prod/GET/*"` pattern. Today,
 that's safe (every Allow is also covered by a Deny).
 Any independent broadening of either pattern silently
 opens the API.
3. The API method has `authorization_type: NONE`. The
 resource policy is the only access control; if the
 resource policy has a gap, no second layer catches it.

Z3 runs four queries against three fixtures (the writeup
config, a broadened-allow variant that demonstrates risk
2's latent fragility, and a remediated config) and
returns:

| Query | writeup | broadened | remediated |
|---|---|---|---|
| F1: Allow/Deny pattern alignment | UNSAT (currently safe) | **SAT** (developer change opens it) | UNSAT (aligned at `:/*`) |
| F2: aws:sourceVpc vs aws:sourceVpce | **SAT** (any endpoint in VPC) | **SAT** | UNSAT (`aws:sourceVpce`) |
| F3: no auth + VPC-wide compound | **SAT** | **SAT** | UNSAT (IAM auth) |

The intellectual-honesty beat parallels this example in
reverse: where this example refuted a suspicion that turned
out wrong (KMS Resource:* in a key policy), this example
demonstrates that an UNSAT today (Finding 1a) becomes
SAT under a single common developer change (Finding 1b).
Both cases are statements about the configuration's
*structural fragility*, not just its current
satisfiability.

## CEL foil — `main.go`

The CEL side scopes to
`CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001`, the
catalogue's existing private-API control. It fires only
when the resource policy has *no VPC restriction at all*
(`resource_policy_restricts_vpc: false`). The writeup
config has a VPC restriction (it just uses the wrong
condition key — `aws:sourceVpc` instead of
`aws:sourceVpce`), so the boolean is `true` and the
control is silent.

Run from `stave/`:

```bash
go run ./examples/apigw-private-api-scoped-deny
```

Captured output (`expected/cel-output.txt`):

```
=== writeup-config (sourceVpc + identical Resource patterns) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001: no findings

=== broadened-allow (developer widens Allow) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001: no findings

=== remediated-config (sourceVpce + aligned + IAM auth) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001: no findings
```

All three configurations report `COMPLIANT/0` against
the existing CEL control. The catalogue's private-API
posture check passes because the writeup *has* a VPC
restriction; it does not check *which* VPC dimension is
restricted nor whether the Deny pattern matches the
Allow pattern.

## Z3 prover — `z3prove/`

Four queries with verbose verdicts. Prerequisites
(Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/apigw-private-api-scoped-deny/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

The Z3 prover runs against all three fixtures
sequentially and prints the full verdict trail. Excerpt
from the writeup-config block:

```
========== writeup-config (sourceVpc + identical Resource patterns) ==========
--- Finding 1a: Allow/Deny resource pattern alignment ---
 Allow Resource: [execute-api:/prod/GET/*]
 Deny Resource: [execute-api:/prod/GET/*]
 verdict: UNSAT — every witness the Allow admits is also blocked by the Deny
 (patterns are currently aligned; becomes SAT the moment either
 pattern is changed independently — see the broadened-allow
 variant below)

--- Finding 2: aws:sourceVpc vs aws:sourceVpce ---
 endpoints not blocked by Deny: 4 / 4
 verdict: SAT — witness: vpce-0999888777666555 (in vpc-0b52ca08e7db8531f, NOT vpce-0abc123def456789)
 (Deny condition uses aws:sourceVpc which matches every
 endpoint in the VPC, not just the intended one)

--- Finding 3: no authorization + VPC-wide access (compound) ---
 authorization_type: NONE
 verdict: SAT — witness: vpce-0999888777666555 reaches the API with auth=NONE
 (no IAM/Lambda authorizer to catch the resource-policy gap)
```

The broadened-allow block flips Finding 1a's UNSAT to a
SAT:

```
========== broadened-allow (developer widens Allow) ==========
--- Finding 1b: Allow/Deny resource pattern alignment ---
 Allow Resource: [execute-api:/*]
 Deny Resource: [execute-api:/prod/GET/*]
 admitted by Allow: 5 / 5 blocked by Deny: 1 / 5
 verdict: SAT — witness: stage=prod method=POST resource=execute-api:/prod/POST/users
 (Allow widened to execute-api:/* — Deny still scoped to /prod/GET/*,
 so this resource is allowed without any VPC restriction)
```

The remediated-config block returns UNSAT on all four
queries: patterns aligned at `execute-api:/*`, condition
key `aws:sourceVpce`, authorization type `AWS_IAM`.

## Layout

```
examples/apigw-private-api-scoped-deny/
├── README.md
├── main.go # CEL foil
├── controls/
│ └── CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001.yaml
├── fixtures/
│ ├── writeup-config/observations/{T1,T2}.json
│ ├── broadened-allow/observations/{T1,T2}.json
│ └── remediated-config/observations/{T1,T2}.json
├── z3prove/
│ ├── go.mod # separate module
│ └── main.go # 4 queries × 3 fixtures = 12 verdicts
└── expected/
 ├── cel-output.txt
 └── z3-output.txt
```

## Source

"Securing Private APIs in API Gateway Using VPC
Endpoints" — Medium, June 2023. Resource policy
documents in the writeup-config fixture are exact
transcriptions from the article. The broadened-allow
fixture is a one-line change a developer could make
when adding a new method or stage.

## Where this fits

Same
foil pattern as this example (CEL passes, Z3 finds): four
queries × three fixtures × three verdict polarities,
plus a structural-fragility demonstration that doesn't
appear in any prior iteration. The matcher template now
covers IAM identity policies (this example / this example), bucket
policies with wildcard or account-root principals
(this example / this example / this example), KMS key policies with
key-scoped Resource:*, and API Gateway
resource policies with VPC-condition semantics (this
iteration).
