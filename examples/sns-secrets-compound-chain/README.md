# SNS Secrets: Cross-Service Compound Chain Proof

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

A CloudGoat scenario (sns_secrets, July 2025
walkthrough by VirajMathpati) in which a low-privileged
IAM user with **zero** direct permissions on Secrets
Manager retrieves a secret through a four-service
credential-flow chain:

```
 IAM user (cg-sns-user)
 │
 ├─ sns:Subscribe to public-topic-cgidxi93qpes3g
 │ (no topic policy → IAM-only gate; subscription succeeds)
 │
 ▼
 SNS topic publishes message containing API key
 │
 │ (the credential value flows here, not a permission)
 ▼
 API Gateway accepts API key, no IAM auth
 │
 ▼
 Lambda integration reads Secrets Manager
 │
 ▼
 secret value returned to user
```

This is the first iteration where the bug lives in the
**data** flowing between services (an API key published
as an SNS message), not in the **permissions** on any
individual service. Every policy on the path is
"reasonable" by per-service checklist criteria. The
compound chain is what Z3 proves.

## Four Z3 verdicts on the writeup config

| Finding | Verdict | Witness / data |
|---|---|---|
| 1 — SNS topic subscribable + publishes credential | **SAT** | `public-topic-cgidxi93qpes3g`, `publishes_credential_type=api_key` |
| 2 — `apigateway:GET` Deny coverage gap | **SAT** | 21 of 24 known management paths reachable |
| 3 — 5-hop credential-flow chain | **SAT** | all five hops `true` |
| 4 — Compound path | **SAT** | F1 ∧ F2 ∧ F3 |

## Four Z3 verdicts on the remediated config

| Finding | Verdict | Reason |
|---|---|---|
| 1 | **UNSAT** | `sns:Subscribe` scoped to `ops-alerts-*`, plus topic now has a policy |
| 2 | **UNSAT** | `apigateway:GET` removed from the user's policy entirely |
| 3 | **UNSAT** | Chain broken at hop 1 (subscribe denied) |
| 4 | **UNSAT** | At least one precondition fails |

## CEL side — `main.go`

Scoped to `CTL.SNS.POLICY.SUBSCRIBE.BROAD.001`,
Stave's existing per-topic broad-subscribe control. The
control reads
`properties.messaging.sns.subscribe_broadly_granted`
from the *topic* — not from the IAM identity policy.
The writeup config has *no topic policy* at all (the
boolean is `false`); the per-service control is silent
on both fixtures.

Run from `stave/`:

```bash
go run ./examples/sns-secrets-compound-chain
```

Captured output:

```
=== writeup-config (cg-sns-user policy + bare topic + key-only API) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.SNS.POLICY.SUBSCRIBE.BROAD.001: no findings

=== remediated-config (sns:Subscribe scoped + topic policy + IAM auth) ===
 status: COMPLIANT total_assets=1 violations=0
 CTL.SNS.POLICY.SUBSCRIBE.BROAD.001: no findings
```

The catalogue's existing controls each check a single
service. None of them looks at the cross-service data
flow. This is structural; the compound finding requires
multi-service reasoning that no per-service predicate
can express.

## Z3 prover — `z3prove/`

Four queries plus a per-path API Gateway deny coverage
table. Prerequisites (Ubuntu): `sudo apt install
libz3-dev pkg-config`.

```bash
cd stave/examples/sns-secrets-compound-chain/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

The deny coverage table on the writeup config is the
article's centrepiece evidence:

```
--- API Gateway Deny coverage analysis ---
 OPEN : /restapis
 OPEN : /restapis/{id}
 OPEN : /restapis/{id}/resources
 OPEN : /restapis/{id}/resources/{resource_id}
 OPEN : /restapis/{id}/resources/{resource_id}/methods/{method}
 BLOCKED : /restapis/{id}/resources/{resource_id}/methods/{method}/integration
 OPEN : /restapis/{id}/stages
 OPEN : /restapis/{id}/stages/{stage}
 OPEN : /restapis/{id}/deployments
 OPEN : /restapis/{id}/deployments/{deployment_id}
 OPEN : /restapis/{id}/models
 OPEN : /restapis/{id}/authorizers
 OPEN : /restapis/{id}/gatewayresponses
 OPEN : /restapis/{id}/requestvalidators
 OPEN : /restapis/{id}/documentation
 BLOCKED : /apikeys
 BLOCKED : /apikeys/{key_id}
 OPEN : /usageplans
 OPEN : /usageplans/{plan_id}
 OPEN : /usageplans/{plan_id}/keys
 OPEN : /domainnames
 OPEN : /vpclinks
 OPEN : /clientcertificates
 OPEN : /account
```

The writeup's deny lists 7 patterns. They cover 3 of 24
known paths. The other 21 remain reachable.

## What each finding proves

### Finding 1: SNS topic subscribable + sensitive content

The user's IAM policy admits `sns:Subscribe` on
`Resource:*`. The topic has no resource policy. In AWS,
when a topic has no resource policy, the *only* gate is
the caller's IAM identity policy. The user wins.

The fixture also annotates the topic with
`publishes_credential_type=api_key`. This is a
*data-flow fact* — it captures what the topic publishes,
not what permissions it grants. Stave's standard
observation schema would carry this from a content-type
collector that inspects message templates or
historically-published payloads; in the fixture it's
hand-set to model the writeup's scenario.

### Finding 2: API Gateway Deny coverage gap

The user's policy:

```json
{
 "Allow": "apigateway:GET",
 "Resource": "*"
},
{
 "Deny": "apigateway:GET",
 "Resource": [
 "/apikeys",
 "/apikeys/*",
 "/restapis/*/resources/*/methods/GET",
 "/restapis/*/methods/GET",
 "/restapis/*/resources/*/integration",
 "/restapis/*/integration",
 "/restapis/*/resources/*/methods/*/integration"
 ]
}
```

The author thought of seven path patterns. The Z3
prover walks 24 known management paths from
`apigwManagementPaths` (a static registry sourced from
the AWS API Gateway management API reference). The
prover finds 21 paths reachable — `/restapis/{id}`,
`/restapis/{id}/stages`, `/restapis/{id}/resources`,
`/restapis/{id}/deployments`, `/restapis/{id}/models`,
and many more.

These paths are individually innocuous-looking but
together let the principal enumerate every API in the
account, every stage, every resource path. Combined
with the API key from Finding 1, that's enough to
construct the invocation URL.

### Finding 3: 5-hop credential-flow chain

This is the iteration's distinguishing feature. The Z3
program computes five booleans from the fixture:

```
hop 1: principal can subscribe to topic (true)
hop 2: topic publishes credential (true)
hop 3: API Gateway accepts credential
 (auth_type=API_KEY_ONLY, no IAM) (true)
hop 4: API Gateway integrates with function (true)
hop 5: function reads Secrets Manager (true)
```

All five must be true for the chain to be reachable.
Z3 conjuncts them and checks satisfiability. On the
writeup config: SAT — every hop holds. On the
remediated config: hops 1, 2, and 3 are false, the
chain breaks at the first one.

What Z3 contributes here is the *modeling shape*: the
data-flow chain is a logical conjunction over facts
that come from different services' observation
documents. CEL evaluates per-asset predicates; it has
no native way to compose facts across four asset types
into a single "is this reachable?" verdict. The Z3
program does it as a one-line `And` of five booleans.

### Finding 4: Compound path

The conjunction of Findings 1, 2, and 3. SAT on the
writeup config means: a low-privileged user can reach
the secret in seven API calls without holding a single
permission on Secrets Manager.

## Layout

```
examples/sns-secrets-compound-chain/
├── README.md
├── main.go # CEL foil
├── controls/
│ └── CTL.SNS.POLICY.SUBSCRIBE.BROAD.001.yaml
├── fixtures/
│ ├── writeup-config/observations/{T1,T2}.json
│ └── remediated-config/observations/{T1,T2}.json
├── z3prove/
│ ├── go.mod
│ ├── apigw_paths.go # 24 known management API paths
│ └── main.go # 4 queries × 2 configs + coverage table
└── expected/
 ├── cel-output.txt
 └── z3-output.txt
```

## Source

"AWS SNS Secrets: From Misconfiguration to Exploitation
— A CloudGoat Walkthrough" — Medium, July 2025,
VirajMathpati. The IAM policy and the four-service
chain in the fixtures are paraphrased from the
walkthrough with synthetic identifiers.

## Where this fits

Three notable beats:

- The CEL foil pattern from this example/12/13 is reused —
 the existing per-service control is silent on both
 fixtures because it checks the wrong layer.
- The deny-coverage matrix from this example returns,
 scaled up: the writeup's deny list covers 3 of 24
 known paths.
- **Cross-service data-flow modeling.** The
 iteration's distinguishing feature is reasoning
 about credential value flowing through SNS, not
 permission edges. This is the first example where
 the answer is "permission analysis says no access;
 data analysis says yes access."

The cumulative encoder template now spans IAM
identity policies (this example family), bucket policies
(this example, 2, 11), KMS key policies, API
Gateway resource policies, Allow-and-Deny
effective-permission resolution, and now
**cross-service data-flow conjunctions**.
