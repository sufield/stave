# KMS Concentration Risk

KMS concentration risk answers: "If this one encryption key is
compromised or deleted, how much of your business shuts down?"

Organizations often use a single KMS key to encrypt hundreds of
S3 buckets and RDS instances. If that key is deleted, disabled, or
its policy misconfigured, every dependent resource becomes
inaccessible. This is a cryptographic single point of failure.

## The concentration model

```
KMS Key (1) → encrypts → S3 (200 buckets) + RDS (50 instances) + EBS (100 volumes)
                          ↓
                Key deletion = 350 resources inaccessible
```

Scanners check if encryption is ON. Stave checks if the encryption
dependency is concentrated in a single point of failure.

## How it works

The extractor counts the resources encrypted with each KMS key:

```yaml
properties:
  cryptography:
    kind: key
    key_concentration:
      resource_count: 450
      service_count: 5
      has_deletion_protection: false
      has_multi_region_replica: false
```

## Controls

### CTL.KMS.CONCENTRATION.001 — Key encrypts > 50 resources

```
Fires when: resource_count > 50
Severity: high
```

A single key encrypts too many resources. Key misconfiguration
has a disproportionate blast radius.

**Remediation:** Create per-service or per-application KMS keys.

### CTL.KMS.CONCENTRATION.002 — High-density key lacks deletion protection

```
Fires when: resource_count > 50
        AND has_deletion_protection == false
Severity: critical
```

A high-density key can be deleted with a single API call. The
7-day minimum waiting period is the only grace period.

**Remediation:** Enable key deletion protection. Deny
`kms:ScheduleKeyDeletion` via SCP.

## Safety chain: crypto_concentration_failure

```yaml
id: crypto_concentration_failure
controls:
  - CTL.KMS.CONCENTRATION.001
  - CTL.KMS.CONCENTRATION.002
  - CTL.KMS.ROTATION.001
escalation_threshold: 2
compound_severity: critical
```

## Key files

| File | Purpose |
|---|---|
| `controls/kms/concentration/CTL.KMS.CONCENTRATION.001-002.yaml` | 2 concentration controls |
| `controls/kms/isolation/CTL.KMS.ISOLATION.001.yaml` | Key domain isolation control |
| `chains/crypto_concentration_failure.yaml` | Concentration compound chain |
| `chains/cryptographic_boundary_collapse.yaml` | Isolation + cross-env compound chain |

## Related: Cryptographic isolation

Concentration checks how many resources depend on one key.
Isolation checks whether a key is shared across sensitivity domains.
See CTL.KMS.ISOLATION.001 — a PHI key shared with a dev bucket
collapses the cryptographic boundary even if concentration is low.
