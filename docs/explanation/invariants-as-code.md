# Invariants as Code

Why "invariant" rather than "rule", "policy", or "check" — and why this distinction matters.

---

## What an Invariant Is

An invariant is a property that must always be true. Not "should be true", not "is recommended to be true", not "was true when last checked." Always true, in every account, in every region, at every point in time.

"S3 buckets must block public access" is an invariant. It is not conditional on the bucket's purpose, the team that owns it, or whether an exception was filed three months ago. The property either holds or it does not.

This is fundamentally different from a compliance check, which asks "does this resource satisfy requirement 4.3.2 of standard X?" A compliance check is contextual — it depends on which standard applies, which version, and which organizational interpretation. An invariant is universal.

## Why Not "Rule" or "Policy"

A rule implies a decision point: evaluate the rule, apply the consequence. Rules have exceptions. Rules are negotiated. Rules change based on who is asking.

A policy implies organizational intent: "our policy is to encrypt all data at rest." Policies are aspirational. A policy document that says "all data must be encrypted" while 40% of databases are unencrypted is not wrong — the policy is correct, the implementation is not.

An invariant has no gap between intent and reality. If the invariant does not hold, the system is in a violated state. The invariant does not care about intent.

## How Invariants Differ from Vulnerability Findings

A vulnerability scanner finds a specific weakness in a specific version of a specific software package. "CVE-2024-1234 affects OpenSSL 3.0.2 on host X." This is an observation about a running system at a moment in time.

An invariant is a property of a configuration. "The encryption key must have rotation enabled." This can be evaluated against a static snapshot without connecting to the running system. The invariant does not care whether the key is currently being used — it cares whether rotation is enabled.

This distinction matters because invariants can be evaluated offline, against historical snapshots, in air-gapped environments, and without the privileges required to scan running systems.

## The Predicate Expresses What Must Be True

A Stave control's `unsafe_predicate` field does not describe a test that detects a problem. It describes the condition under which the asset is unsafe. The predicate is the negation of the invariant.

```yaml
# The invariant: "S3 buckets must block public ACLs"
# The predicate: "the bucket is unsafe when public ACLs are not blocked"
unsafe_predicate:
  all:
    - field: properties.storage.controls.block_public_acls
      op: eq
      value: false
```

When the predicate evaluates to true, the invariant is violated. When it evaluates to false, the invariant holds. This inversion — expressing the unsafe condition rather than the safe condition — ensures that missing data produces INCONCLUSIVE rather than a false PASS.
