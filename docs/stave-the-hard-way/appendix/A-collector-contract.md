# Appendix A — Collector Contract

The collector contract is the interface between the Physical Domain
(the collector that captures AWS state) and the Functional Domain
(the evaluation engine that checks properties).

## The Contract File

```bash
head -25 data/collector-contract.yaml
```

```yaml
# Collector Contract
#
# Axiom 1 boundary between the collector (Physical Domain) and the
# evaluation engine (Functional Domain). Each entry specifies the
# semantic postcondition a collector MUST satisfy when producing a
# boolean field.

version: "1.0"
contracts:
  ...
```

392 fields across 4,113 lines. Each entry defines:

- **field** — dotted path into the properties bag
- **type** — data type (usually boolean)
- **postcondition** — prose contract the collector must satisfy
- **consumers** — which controls depend on this field

## Example: The MFA Condition Field

```bash
grep -A 12 "has_mfa_condition" data/collector-contract.yaml | head -13
```

```yaml
  - field: identity.trust_policy.has_mfa_condition
    type: boolean
    postcondition: >
      True if the IAM role trust policy includes a Condition
      block requiring aws:MultiFactorAuthPresent. The
      collector MUST parse the trust policy's Condition for
      Bool: {"aws:MultiFactorAuthPresent": "true"} — both
      StringEquals and Bool operators count.
    consumers:
      - CTL.IAM.TRUST.MFA.001
```

The postcondition tells the collector exactly what to compute. The
consumer list connects the field to the controls that depend on it.

## Null Semantics

A missing or null field means "the collector did not evaluate this."
It does NOT mean false. A predicate `op: eq, value: false` will not
match null. Missing data is an unknown, not a safe state.

## CLI Commands

- `stave contract` — inspect per-asset-type input contracts
- `stave gaps` — report which fields are missing and what they unlock
- `stave readiness` — what Stave can and cannot evaluate given your observations
- `stave coverage` — field coverage analysis against control predicates
