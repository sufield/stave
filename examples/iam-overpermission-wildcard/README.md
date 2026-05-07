# Example — IAM Over-Permission (Lambda Role with `s3:*` on `*`)

Demonstrates the `iam-overpermission-wildcard` pattern using
both **CEL** (`pkg/stave`) and **Z3** (the
`aclements/go-z3` binding). Pattern P12 (added at iter-7a)
in [`examples-plan.md`](../../../examples-plan.md), grounded
in the Capital One breach pattern and several
overprivileged-Lambda-role disclosures across HackerOne.

The bug: a Lambda execution role's attached policy grants
`s3:*` on `Resource: "*"` when the function only calls
`s3:GetObject` on one bucket prefix. The wildcard admits 40+
S3 actions on every bucket in the account — including
`s3:PutBucketPolicy` (any bucket public),
`s3:DeleteObject` (data destruction),
`s3:PutBucketAcl` (access-control rewrite). The Lambda
function never calls those; an attacker who reaches the
Lambda's execution context (SSRF, dependency confusion,
dependency takeover) inherits all of them.

## Two binaries, two questions

```
examples/iam-overpermission-wildcard/
├── README.md
├── main.go              # CEL: does the unsafe predicate hold?
├── controls/
│   └── CTL.IAM.POLICY.RESOURCE.WILDCARD.001.yaml
├── fixtures/
│   ├── before/observations/{T1,T2}.json   # s3:* on *
│   └── after/observations/{T1,T2}.json    # scoped actions on scoped ARNs
├── z3prove/
│   ├── go.mod           # separate module — CGO/libz3 stays out of stave/
│   └── main.go          # Z3: which dangerous (action, resource) does the policy admit?
└── expected/
    ├── before-output.txt
    ├── after-output.txt
    ├── z3-before-output.txt
    └── z3-after-output.txt
```

`z3prove/` is a separate Go module (mirrors iter-4 and
iter-5) so its libz3 link does not infect Stave's vendored
tree.

## CEL side

From `stave/`:

```bash
go run ./examples/iam-overpermission-wildcard           # both phases
go run ./examples/iam-overpermission-wildcard before    # vulnerable only
go run ./examples/iam-overpermission-wildcard after     # remediated only
```

Captured output:

```
=== before (s3:* on *) ===
  status: NON_COMPLIANT   total_assets=1   violations=1
  CTL.IAM.POLICY.RESOURCE.WILDCARD.001 fired on 1 asset(s):
    - arn:aws:iam::111122223333:role/DataProcessorLambdaRole   severity=high   exposure_score=76.64
  assertion: fires=true (expected) ✓

=== after  (scoped actions + ARNs) ===
  status: COMPLIANT   total_assets=1   violations=0
  CTL.IAM.POLICY.RESOURCE.WILDCARD.001: no findings
  assertion: fires=false (expected) ✓
```

The control reads
`properties.identity.policies.has_resource_wildcard_on_sensitive`
— a boolean the engine pre-computes by walking the
attached-policy statements. `true` if any sensitive action
is paired with `Resource: "*"`; `false` otherwise.

## Z3 side

Prerequisites (Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/iam-overpermission-wildcard/z3prove
go mod tidy
CGO_ENABLED=1 go run . before
CGO_ENABLED=1 go run . after
```

Captured output for `before`:

```
=== before (s3:* on *) ===
  policy statements: 2
    [0] Effect=Allow Action=s3:* Resource=*
    [1] Effect=Allow Action=[logs:CreateLogGroup logs:CreateLogStream logs:PutLogEvents] Resource=arn:aws:logs:us-east-1:111122223333:*
  admitted requests: 5 / 5
  intended scope:    [s3:GetObject → app-data-production/input/file.csv s3:PutObject → app-data-production/output/result.json]
  dangerous set:     [s3:PutBucketPolicy → customer-pii-bucket s3:DeleteObject → billing-archives/jan-2026.csv s3:PutBucketAcl → audit-logs-bucket]
  verdict: SAT — witness: s3:PutBucketPolicy on customer-pii-bucket
```

Z3 returns SAT with a concrete witness — the role can call
`s3:PutBucketPolicy` on `customer-pii-bucket`. That is the
specific exploitation path: an attacker who reaches the
Lambda's execution context can make any bucket in the
account public with one API call.

For `after`:

```
=== after  (scoped actions + ARNs) ===
  policy statements: 3
    [0] Effect=Allow Action=s3:GetObject Resource=arn:aws:s3:::app-data-production/input/*
    [1] Effect=Allow Action=s3:PutObject Resource=arn:aws:s3:::app-data-production/output/*
    ...
  admitted requests: 2 / 5
  ...
  verdict: UNSAT — no dangerous action admitted outside intended scope
```

UNSAT — the scoped policy admits exactly the two intended
requests (read from `input/`, write to `output/`); no
dangerous action remains reachable.

## What the Z3 program does

The fixture observation carries the raw policy statements
under `properties.identity.policies.attached_policies`. The
Z3 program:

1. Reads each statement's `Action` and `Resource` fields.
2. Walks a hard-coded set of named witness `(action, resource)`
   pairs:
   ```
   0: (s3:GetObject,       app-data-production/input/file.csv)   intended
   1: (s3:PutObject,       app-data-production/output/result.json) intended
   2: (s3:PutBucketPolicy, customer-pii-bucket)                  DANGEROUS
   3: (s3:DeleteObject,    billing-archives/jan-2026.csv)        DANGEROUS
   4: (s3:PutBucketAcl,    audit-logs-bucket)                    DANGEROUS
   ```
3. For each witness, checks whether *any* `Allow` statement
   admits it:
   - Action match: `*`, `s3:*`, or exact name.
   - Resource match: `*`, `arn:.../*` prefix, or exact ARN.
4. Encodes the question into Z3:
   ```
   admitted    = req ∈ admitted_set
   dangerous   = req ∈ {2, 3, 4}
   intended    = req ∈ {0, 1}
   unsafe      = admitted ∧ dangerous ∧ ¬intended
   ```
5. Asks the solver to find a satisfying `req`. SAT returns
   the witness index; UNSAT proves no dangerous request is
   admitted.

This is structurally the same model as iter-4 and iter-5,
adapted to the IAM action+resource domain. The action /
resource matching is done in Go (string-prefix and
service-wildcard rules) and the *boolean* admittedness is
fed to Z3; the solver does the existence search across the
finite witness set.

## Modelling note: what's faithful and what isn't

This fixture works because every relevant question is
finite-domain and discrete:

- The sensitive action set is finite and known.
- The "intended scope" is enumerable.
- The witness ARNs are concrete.

A production IAM analyser must additionally handle:

- **SCP overlays** at the organization level (could DENY
  what the role's policy ALLOWS).
- **Permissions boundaries** that further restrict.
- **Resource policies** on the target bucket (could DENY
  cross-account or DENY by source-IP).
- **NotAction / NotResource** clauses, condition keys
  (`aws:RequestTag`, `aws:SourceIp`, `kms:ViaService`).

This example does not model those layers — by design, to
keep the Z3 mechanics legible. The CEL control
(`CTL.IAM.POLICY.RESOURCE.WILDCARD.001`) is the right tool
for "is the boolean unsafe?"; the Z3 demo answers "what
specific dangerous action does the wildcard admit?" Neither
question requires modelling the full IAM policy-evaluation
algorithm.

## What this iteration adds

Iter-7a is the first iteration where the Z3 model walks a
**real policy structure** rather than parameterising a
hard-coded admitted set. The `admittedByStatements` walker
implements a small subset of IAM Action/Resource matching;
the Z3 step uses its boolean output. This pattern scales to
the iter-7 (`iam-attach-user-policy-self`) and other IAM
examples: walk the statements with Go, feed the boolean
results to Z3, let the solver enumerate witnesses.

No new `pkg/stave` API was needed for iter-7a. The CEL side
reuses `FindingsForControl` from iter-1 unchanged. The Z3
side does not depend on Stave at all.

## Where this fits

This is **Iteration 7a, Phase B** of the examples roadmap.
Phase C is the article in `channels/devto/`, framed around
the empathetic teaching point: the same developer who wrote
this policy also scoped the CloudWatch Logs statement
correctly. They know how to scope. The fix is three lines.
