# Vendor Trust Leash

Vendor trust leash analysis answers: "Which external companies can
physically read your sensitive data, and should they still have
access?"

Companies grant access to SaaS vendors (Datadog, Wiz, Vanta) using
cross-account roles. Over time, these vendors accumulate ghost
access — roles that persist after contracts end, or permissions
that exceed the vendor's current needs.

## The vendor access model

```
Vendor Account → AssumeRole → Your Account → Sensitive Resources
     ↓
  Dormant role (unused 180 days) + PHI access (12 buckets)
```

Each dormant vendor role is an unmonitored ingress path. If the
vendor is compromised, the attacker gains direct access to your
sensitive data through the trust relationship.

## How it works

The extractor identifies cross-account roles, maps them to vendor
names, and checks usage patterns:

```yaml
properties:
  identity:
    kind: role
    vendor_trust:
      is_external_vendor: true
      vendor_name: datadog
      last_used_days_ago: 180
      is_dormant: true
      reachable_sensitive_count: 12
      has_external_id: true
```

## Controls

### CTL.IAM.VENDOR.DORMANT.001 — Vendor role unused > 90 days

```
Fires when: is_external_vendor == true
        AND is_dormant == true
Severity: high
```

Ghost access persists after the business need has ended.

**Remediation:** Review the vendor relationship. Delete unused
cross-account roles. Re-verify trust policies for active vendors.

### CTL.IAM.VENDOR.OVERPRIVILEGED.001 — Vendor reaches > 10 sensitive resources

```
Fires when: is_external_vendor == true
        AND reachable_sensitive_count > 10
Severity: critical
```

Vendor compromise exposes a disproportionate data surface.

**Remediation:** Scope vendor permissions to minimum required
resources. Create per-function roles.

## Safety chain: third_party_exposure_path

```yaml
id: third_party_exposure_path
controls:
  - CTL.IAM.VENDOR.DORMANT.001
  - CTL.IAM.VENDOR.OVERPRIVILEGED.001
  - CTL.IAM.TRUST.EXTERNALID.001
escalation_threshold: 2
compound_severity: critical
```

## Key files

| File | Purpose |
|---|---|
| `controls/iam/vendor/CTL.IAM.VENDOR.DORMANT.001.yaml` | Dormant vendor detection |
| `controls/iam/vendor/CTL.IAM.VENDOR.OVERPRIVILEGED.001.yaml` | Overprivileged vendor detection |
| `chains/third_party_exposure_path.yaml` | Compound chain definition |
