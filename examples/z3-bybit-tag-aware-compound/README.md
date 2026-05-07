# z3-bybit-tag-aware-compound

The fifth distinct SMT query shape: **permission + resource
classification**. Asks whether any developer's wildcard
resource pattern prefix-matches a production-tagged bucket —
the configuration that enabled the March 2025
Bybit / Safe{WALLET} $1.5B ETH heist.

## What this proves

A developer's IAM policy used a prefix wildcard
`arn:aws:s3:::company-frontend-*` for their dev-bucket
access. The wildcard incidentally matched the production
frontend bucket. Compromised dev creds → modify `app.js` in
production → CloudFront serves backdoored JavaScript to
every user → $1.5B redirected.

CEL flags the broad policy on the developer (one finding)
and the production tag on the bucket (separate metadata).
CEL never asks whether the developer's wildcard pattern
ACTUALLY prefix-matches a production-tagged bucket. The
conjunction is the security property; the witness names
the specific (developer, wildcard, bucket) triple.

## The compound

```
Fact 1: developer is an IAM user with PutObject capability
        has_action(developer, "s3:PutObject")
Fact 2: developer has a resource pattern ending in "*"
        has_resource(developer, wildcard_pattern)
        str.suffixof("*", wildcard_pattern)
Fact 3: a production-tagged S3 bucket exists
        has_type(prod_bucket, "aws_s3_bucket")
        has_tag(prod_bucket, "environment=production")
Fact 4: the wildcard pattern's stripped prefix is a prefix
        of the production bucket's ARN
        wildcard_pattern = prefix_part ++ "*"
        str.prefixof(prefix_part, prod_bucket)

Conjunction → bybit shape: developer can write to a
              production-tagged bucket they shouldn't access.
```

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `bybit-pattern-before` | **sat** | **sat** | (see below) |
| `bybit-pattern-after`  | **unsat** | **unsat** | n/a |

Z3 + cvc5 witness on `bybit-pattern-before`:

```
developer        = arn:aws:iam::111122223333:user/developer-frontend
wildcard_pattern = arn:aws:s3:::company-frontend-*
prod_bucket      = arn:aws:s3:::company-frontend-prod
prefix_part      = arn:aws:s3:::company-frontend-
```

The four-element witness is the actual bybit attack chain:
the developer ARN, the wildcard pattern from the IAM policy,
the production bucket the wildcard accidentally matches, and
the common prefix that bridges them. That's the entire $1.5B
configuration anomaly, named by Z3.

## Why CEL doesn't say this

CEL evaluates per-asset, per-control:

- A wildcard-policy control fires on the developer for using
  prefix `*` (one finding)
- A production-bucket-tag control might exist for
  governance — separate finding

What CEL can't ask: "does the developer's specific wildcard
pattern, given its specific prefix, prefix-match a bucket
tagged production?" That requires:

1. String-level prefix matching (SMT-LIB string theory)
2. Cross-asset reasoning (developer's policy ↔ bucket's tag)
3. Closed-world enumeration of resource patterns

All three are first-class operations in the SMT pipeline.
CEL would need bespoke per-control plumbing to recover the
same composition; the SMT query is 30 lines of standard
SMT-LIB.

## Run

```bash
cd stave
make build
bash examples/z3-bybit-tag-aware-compound/run.sh
```

Expected output (also captured in `expected/output.txt`):

```
bybit-pattern-before    expected=sat    z3=sat    cvc5=sat        OK
bybit-pattern-after     expected=unsat  z3=unsat  cvc5=unsat      OK
```

Requires:
- `z3` 4.x on PATH (required)
- `cvc5` 1.3+ on PATH (decisive on this fixture; the bybit
  fact set is small enough that `--finite-model-find` doesn't
  need timeout fallback)

## What this commit added to the projection

One new fact extractor:

| Predicate | Source SIR field | Encoding |
|---|---|---|
| `has_tag` | Any depth-2 `tags` block under `properties.<svc>.tags.<key>` (walks `bucket`, `storage`, `identity`, `api`, `cdn`, …) | Binary `(subject, "key=value")`. Each (key, value) pair becomes one fact with `key=value` concatenated as the object string. |

The extractor scans every top-level property block for a
`tags` sub-map rather than enumerating per-service paths,
so it catches the bybit convention (`properties.bucket.tags`)
and the older S3 convention (`properties.storage.tags`) and
any new asset type that follows the same shape — no
per-service plumbing.

Determinism: tag map iteration order is randomised in Go;
the extractor sorts block names and tag keys before emission
so the same SIR yields byte-identical output across runs.

`has_tag` added to the SMT-LIB baseline so queries reference
it portably across fixtures.

## Why binary `has_tag(s, "k=v")` instead of ternary `has_tag(s, k, v)`

The current SMT-LIB serializer assumes binary predicates
throughout — `(declare-fun X (String String) Bool)` and the
closed-world axiom both use two quantifiers. Ternary support
would require:

1. Per-predicate arity tracking in the serializer
2. Variable-arity `declare-fun` emission
3. Variable-arity `forall` quantifiers in the closed-world axiom

That's a serializer refactor across every existing predicate
for one query's ergonomics. The binary `key=value`
concatenation preserves the semantic — the asserted tuple
uniquely identifies the (asset, key, value) triple — at a
small cost in query verbosity:

```smt2
; Binary (this commit)
(has_tag bucket "environment=production")

; Ternary (would need serializer refactor)
(has_tag bucket "environment" "production")
```

If a future query needs to range over tag keys (e.g.,
"find all assets with ANY environment tag"), ternary becomes
necessary. None of the InfoSec writeup queries needs that;
the binary form ships every fixed-key compound the article
roadmap describes. Ternary is a separate-session refactor
when a consumer demonstrates need.

## What this is not

- **Not a complete bybit detector.** SAT means "the developer
  has a wildcard that prefix-matches a production bucket."
  That's the configuration anomaly; whether it constitutes
  an active threat depends on whether the developer's
  credentials are compromised, which is out of scope. The
  query produces the configuration list to triage.

- **Not a replacement for the iter-7a bybit go-z3 prover.**
  That prover (via `aclements/go-z3`) does the full attack
  reconstruction the article describes — modeling the
  CloudFront integration, the user count, the supply chain
  amplification. This SMT-LIB query is the existential
  reachability check that grounds the broader analysis.

- **Not action↔resource bound.** The current `has_action` /
  `has_resource` projection emits actions and resources as
  separate predicates per principal. The bybit query gets
  away with this because the defect is the WILDCARD PATTERN
  ITSELF, not the action↔resource pairing. Other patterns
  (e.g., "does developer have PutObject specifically on the
  prod bucket?") would need a ternary `statement_grants`
  predicate; that's a follow-up serializer extension.
