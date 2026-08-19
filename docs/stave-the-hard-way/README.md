# Stave the Hard Way

Security is a set of verifiable configuration properties, not an empirical
search for vulnerabilities. This tutorial teaches that idea by making you
verify each property yourself, from raw observation to compound chain finding
to remediation proof.

## What You Will Learn

Ten labs, each building on the last:

1. **Prerequisites** — install Stave, verify your environment
2. **Observations** — how raw AWS API output becomes structured data
3. **Security Properties** — what makes a configuration "good," expressed as YAML
4. **Predicates** — how the evaluation engine checks a property
5. **Red-Green Loop** — testing security properties the way you test code
6. **Findings** — what Stave produces when a property fails
7. **Chains** — individual properties compose into compound findings
8. **Remediation** — from finding to fix to verification
9. **Drift Detection** — catching properties that change after verification
10. **Continuous Verification** — the operational workflow

## The Narrative Thread: MFA Theater

A pen tester discovered that an IAM role required MFA — but the MFA was
security theater. The trust policy used `aws:MultiFactorAuthPresent`
(a boolean, checked once at session start) without `aws:MultiFactorAuthAge`
(a time-bound check). A single TOTP code granted a 12-hour session. The MFA
gate existed but provided no ongoing assurance.

This is exactly the kind of compound property that manual testing catches
once and Stave verifies continuously. Every lab in this tutorial follows
that thread.

## What This Is Not

This is not a getting-started guide. It is not documentation. It is designed
to teach the concepts by making you do everything the hard way. You will read
YAML, run commands, interpret output, and fix misconfigurations by hand.

## Prerequisites

No AWS credentials required. All exercises use pre-built fixtures included
in the Stave repository.

## Table of Contents

| Lab | Title |
|-----|-------|
| [01](01-prerequisites.md) | Prerequisites |
| [02](02-observations.md) | Observations |
| [03](03-security-properties.md) | Security Properties |
| [04](04-predicates.md) | Predicates |
| [05](05-red-green-loop.md) | Red-Green Loop |
| [06](06-findings.md) | Findings |
| [07](07-chains.md) | Chains |
| [08](08-remediation.md) | Remediation |
| [09](09-drift-detection.md) | Drift Detection |
| [10](10-continuous-verification.md) | Continuous Verification |

Appendix:

- [A — Collector Contract](appendix/A-collector-contract.md)
- [B — Sensitive Action Classification](appendix/B-sensitive-actions.md)
- [C — Asset Types](appendix/C-asset-types.md)

## Target Audience

Cloud security practitioners, pen testers, and platform engineers who want
to understand how configuration verification works at the property level.

## Estimated Time

2–3 hours.
