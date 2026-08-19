# Lab 03 — Security Properties

A security property is a statement about configuration state that must hold
for an asset to be considered safe. Stave expresses properties as YAML
controls.

## The Simplest Control

```bash
cat internal/controls/elb/resilience/CTL.ELB.DELETION.PROTECT.001.yaml
```

```yaml
id: CTL.ELB.DELETION.PROTECT.001
name: Load Balancer Must Have Deletion Protection Enabled
applicable_asset_types: [aws_elb]
unsafe_predicate:
  all:
  - field: properties.loadbalancer.deletion_protection
    op: eq
    value: false
remediation:
  description: LB lacks deletion protection.
  action: Enable deletion protection.
```

One field, one operator, one value. If `deletion_protection` equals `false`,
the state is unsafe.

## The MFA Control

Now look at the control for our narrative thread:

```bash
stave explain CTL.IAM.TRUST.MFA.001 --controls internal/controls
```

```
Control: CTL.IAM.TRUST.MFA.001
Name: Cross-Account Trust Policy Must Require MFA

Matched fields:
  - properties.identity.kind
  - properties.identity.trust_policy.has_cross_account_trust
  - properties.identity.trust_policy.has_mfa_condition

Rules:
  - properties.identity.kind eq role (all[0])
  - properties.identity.trust_policy.has_cross_account_trust present <nil> (all[1])
  - properties.identity.trust_policy.has_cross_account_trust eq true (all[2])
  - properties.identity.trust_policy.has_mfa_condition ne true (all[3])
```

Three fields, four rules. The control fires when: the asset is a role, it
has cross-account trust, and MFA is not required. Every field is a property
path into the observation's `properties` bag.

## Scale

```bash
find internal/controls/ -name "*.yaml" | wc -l
ls internal/controls/ | wc -l
```

4,761 controls across 132 services. Each is a YAML file, version-controlled,
auditable.

## Verify

Run `stave explain CTL.IAM.TRUST.MFA.001 --controls internal/controls` and
identify which rule checks for the MFA condition.

Next: [Lab 04 — Predicates](04-predicates.md)
