# Secret Blast Radius

Secret blast radius answers: "If this secret is compromised, how
much sensitive data is exposed?"

Standard scanners check if a secret is rotated. Stave checks if
that secret is a master key to sensitive data — and how many
principals have access to it.

## The secret-to-data path

```
Principal → secretsmanager:GetSecretValue → DB Credentials → RDS (PHI)
```

A secret in Secrets Manager is a direct path to the data it
unlocks. The number of principals who can read the secret
determines the blast radius — each reader is a potential
credential compromise path that bypasses IAM least privilege
on the data resource itself.

## How it works

The extractor identifies secrets, maps them to target resources,
and counts the principals with `secretsmanager:GetSecretValue`:

```yaml
properties:
  secret:
    kind: secret
    blast_radius:
      target_resource_id: "arn:aws:rds:us-east-1:123:db/prod"
      target_sensitivity: phi
      privileged_reader_count: 7
      access_vector: cross_account
      is_rotated: false
```

## Controls

### CTL.SECRET.BLAST.001 — Multiple readers targeting sensitive resource

```
Fires when: privileged_reader_count > 3
        AND target_sensitivity in [phi, pii, confidential]
Severity: critical
```

Too many principals can read a secret that unlocks sensitive data.
Each reader is an independent credential compromise vector.

**Remediation:** Reduce readers to minimum required. Use
resource-based policies on the secret. Enable automatic rotation.

### CTL.SECRET.BLAST.002 — Cross-account access to sensitive secret

```
Fires when: access_vector == "cross_account"
        AND target_sensitivity in [phi, pii, confidential]
Severity: critical
```

A secret targeting sensitive data is readable from another AWS
account, doubling the blast radius.

**Remediation:** Remove cross-account access. If required, restrict
to specific role ARNs with external ID conditions.

## Safety chain: compromised_secret_path

```yaml
id: compromised_secret_path
controls:
  - CTL.SECRET.BLAST.001
  - CTL.SECRET.BLAST.002
  - CTL.SECRETSMANAGER.ACCESS.001
escalation_threshold: 2
compound_severity: critical
```

## Key files

| File | Purpose |
|---|---|
| `controls/secretsmanager/blast/CTL.SECRET.BLAST.001-002.yaml` | 2 blast radius controls |
| `chains/compromised_secret_path.yaml` | Compound chain definition |
