# S3 Cross-Account Replication: Over-Permission Proof

## What this demonstrates

A 2023 Medium tutorial walks through cross-account, cross-
region S3 replication of encrypted objects. The author's
intent is correct; the configuration replicates objects as
expected. Three policy choices in the published walkthrough
suggest excess permission, though:

1. The destination bucket policy uses
   `Principal: "arn:aws:iam::SOURCE_ACCOUNT:root"` —
   account-root delegates to the source account's IAM
   layer, which means *any* IAM principal in the source
   account can perform the bucket policy's actions if its
   own IAM grants them.
2. The destination bucket policy grants `s3:Get*` and
   `s3:List*` — wildcard action sets that admit dozens
   of actions replication never calls.
3. The destination KMS key policy grants `kms:Encrypt`
   on `Resource: "*"` — visually alarming, but **KMS key
   policies scope `*` to the key itself**, not to all keys.

Z3 runs three queries — one per claim — against the exact
policy documents from the walkthrough and a remediated
version. Two of the suspicions are confirmed; one is
refuted. All three are proven mathematically against the
actual configuration data, not pattern-matched.

## The intellectual-honesty beat

A pattern-matching scanner that flags "every `Resource: "*"`
is over-permission" would mark Finding 3 as a critical
issue. Z3 says no: in a KMS key policy, `Resource: "*"` is
correctly scoped to the key the policy is attached to.

Formal verification is right when you expect it to be
right *and* right when you expect it to be wrong. That's
the one thing pattern-matching tools can't claim.

## CEL foil — `main.go`

The CEL side of this iteration is a **foil**, not a CEL
demonstration. The example scopes to
`CTL.S3.POLICY.SCOPING.001` — the closest existing
control to the writeup's anti-pattern (it catches
`Principal: "*"` and `Principal: {"AWS": "*"}`). The
writeup uses `Principal: "arn:aws:iam::ACCOUNT:root"` —
narrower than `"*"`, so the control stays silent.

Run from `stave/`:

```bash
go run ./examples/s3-cross-account-replication-overperm
```

Captured output (`expected/cel-output.txt`):

```
=== writeup-config (account-root principal, s3:Get*/s3:List* wildcards) ===
  status: COMPLIANT   total_assets=4   violations=0
  no findings — Stave's built-in catalogue reports clean

=== remediated-config (scoped Principal, AllowRead removed) ===
  status: COMPLIANT   total_assets=4   violations=0
  no findings — Stave's built-in catalogue reports clean

note: this CEL run is a foil — the over-permissions live
      in shapes Stave's built-in catalogue does not catch.
      Run z3prove/ for the formal proofs.
```

Both fixtures report `COMPLIANT/0` against
`CTL.S3.POLICY.SCOPING.001`. The control was specifically
written to catch wildcard-principal anti-patterns; the
writeup uses an account-root principal which is technically
narrower than `"*"`, so the predicate doesn't fire — the
foil this iteration is built around.

## Z3 prover — `z3prove/`

Three queries with verbose verdicts. Prerequisites
(Ubuntu): `sudo apt install libz3-dev pkg-config`.

```bash
cd stave/examples/s3-cross-account-replication-overperm/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

Captured output for both fixtures (`expected/z3-output.txt`).
Excerpt for the writeup config:

```
========== writeup-config ==========
--- Finding 1: non-replication principal access ---
  ...
  verdict:  SAT — witness: arn:aws:iam::111122223333:user/intern-developer

--- Finding 2: excess actions via s3:Get* wildcard ---
  ...
  verdict:  SAT — witness: s3:GetObjectVersionTagging

--- Finding 3: KMS Resource:* scope check ---
  ...
  verdict:  UNSAT — KMS Resource:* scopes to the key itself only
            (suspicion REFUTED; author got this right)
```

For the remediated config: all three queries return
`UNSAT` — Findings 1 and 2 because the policy is scoped,
Finding 3 unchanged (was correct in the original).

## What each query proves

### Finding 1: non-replication principal access

**Query:** is there a principal in account 111122223333
that is NOT the replication role, but the destination
bucket policy admits a `s3:ReplicateObject` request from?

**Encoding:** four witness principals — the replication
role plus three other principals in the same account
(intern user, admin role, data analyst). The bucket
policy's `Principal: "arn:aws:iam::111122223333:root"`
matches every principal whose ARN starts with
`arn:aws:iam::111122223333:` — the matcher's
`matchesAccountRoot` rule encodes the AWS resource-policy
account-root semantic. Z3 looks for a witness in
`admitted ∧ ¬intended`.

**Writeup:** SAT, witness
`arn:aws:iam::111122223333:user/intern-developer`.

**Remediated:** UNSAT — the policy's Principal is scoped
to the role ARN; only the replication role is in the
admitted set.

### Finding 2: excess actions via s3:Get* wildcard

**Query:** among the ~30 `s3:Get*` actions, is any one
both (a) outside replication's required set and (b)
admitted by the bucket policy?

**Encoding:** witnesses are the
`s3:Get*` action names *minus* the small replication-
required set (just `s3:GetBucketVersioning`). The matcher
expands `s3:Get*` glob-style, so every witness matches.
Z3 looks for any admitted witness.

**Writeup:** SAT, witness `s3:GetObjectVersionTagging`
(or any of the other 29 excess actions).

**Remediated:** UNSAT — the `AllowRead` statement was
removed entirely; the only Allow that remains carries
exact-action enumeration.

### Finding 3: KMS Resource:* scope check

**Query:** does the destination KMS key policy admit
`kms:Encrypt` on any key *other than* the destination key
itself?

**Encoding:** witnesses are three KMS key ARNs — the
destination key plus two unrelated keys (a customer-data
key, a billing key). The matcher's `kmsResourceMatches`
rule encodes the KMS-specific semantic: `Resource: "*"`
in a key policy admits *only the key the policy is
attached to*. Z3 looks for a witness key that's *not* the
destination key but is still admitted.

**Both configs:** UNSAT. The two unrelated keys are not
admitted; the destination key is the only one in the
admitted set, but the query excludes it. The suspicion
that `Resource: "*"` is over-broad is *refuted*.

## What the matcher needed beyond iter-7a

Iter-7a / iter-7's IAM matcher handled action wildcards
(`*`, `s3:*`) and resource ARNs with trailing-`/*`. This
iteration adds three rules:

1. **Account-root principal** — `matchesAccountRoot` —
   recognises that `arn:aws:iam::ACCOUNT:root` in a
   resource policy admits every principal in that
   account.
2. **Mid-name action wildcard** — `s3:Get*` glob expansion
   so `s3:GetBucketPolicy` matches even though the
   wildcard isn't at the end of the service name.
3. **KMS key-policy resource semantic** —
   `kmsResourceMatches` recognises that `Resource: "*"`
   in a KMS key policy means "this key" not "all keys."
   Without this rule, the matcher would falsely report
   Finding 3 as SAT.

Each rule lives in a single function with a comment
documenting the AWS semantic it encodes. The rules are
copy-paste candidates for any future cross-account /
KMS / bucket-policy iteration.

## Layout

```
examples/s3-cross-account-replication-overperm/
├── README.md
├── main.go                     # CEL foil
├── controls/
│   └── CTL.S3.POLICY.SCOPING.001.yaml   # closest existing control
├── fixtures/
│   ├── writeup-config/observations/{T1,T2}.json
│   └── remediated-config/observations/{T1,T2}.json
├── z3prove/
│   ├── go.mod                  # separate module — CGO/libz3 stays out of stave/
│   ├── main.go                 # three queries, two configs, six verdicts
│   └── actions.go              # static S3 Get* action registry
└── expected/
    ├── cel-output.txt
    └── z3-output.txt
```

The fixture's `policy_json` and `key_policy_json` strings
are paraphrased from the original Medium tutorial with
synthetic account IDs (`111122223333`, `444455556666`).
The structural shape — account-root principal, `s3:Get*`
+ `s3:List*` wildcard actions, KMS Resource `*` — is
faithful to the published walkthrough.

## Source

"Seamless Cross-Account, Cross-Region Replication of
Encrypted Objects in AWS S3" — Medium, June 2023. Policy
documents in the writeup-config fixture are exact
transcriptions from the article with synthetic account
IDs substituted. The article is intentionally not a
vulnerability disclosure; this iteration treats it as a
configuration source and runs formal queries against it.

## Where this fits

This is **Iteration 11** of the examples roadmap. Closes
the prefix-quantification arc (iter-4, iter-5) by adding
a third bucket-policy reachability example with two new
twists: cross-account principals (account-root in
resource policies) and KMS-specific resource semantics.
The matcher template now covers IAM identity policies
(iter-7a, iter-7), bucket policies with wildcard
principals (iter-1, iter-2), and resource policies with
account-root principals (this iteration).
