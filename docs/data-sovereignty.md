# Data Sovereignty

Data sovereignty analysis answers: "Is your data physically in the
right jurisdiction AND logically inaccessible from outside it?"

Checking that a bucket is in `eu-west-1` is half the story. The
other half: can a principal in `us-east-1` read it? Data residency
is physically correct but logically violated when cross-jurisdiction
access exists.

## The sovereignty model

```
Resource (eu-west-1, PII) ← s3:GetObject ← Principal (us-east-1)
```

The data is in the EU. The access power is in the US. GDPR Article
44 prohibits this transfer. The extractor maps resource jurisdictions
to accessor jurisdictions and flags edges that cross sovereignty
boundaries.

## How it works

```yaml
properties:
  reachability:
    kind: cross_border
    sovereignty:
      cross_border_access_detected: true
      resource_jurisdiction: eu
      accessor_jurisdiction: us
      target_sensitivity: pii
```

Jurisdiction codes are generalized to support GDPR (EU), CCPA (US-CA),
FedRAMP (US-GOV), and custom boundaries.

## Controls

### CTL.EXPOSURE.SOVEREIGNTY.001 — Cross-border access to sensitive data

```
Fires when: cross_border_access_detected == true
        AND target_sensitivity in [phi, pii, confidential]
Severity: high
```

A sensitive resource in one jurisdiction is accessible from a
principal in a different jurisdiction.

**Remediation:** Use IAM condition keys to restrict access by
source VPC or IP range within the jurisdiction. Apply SCPs to
deny cross-jurisdiction access at the organization level.

## Safety chain: sovereignty_violation

```yaml
id: sovereignty_violation
controls:
  - CTL.EXPOSURE.SOVEREIGNTY.001
  - CTL.S3.REGION.001
escalation_threshold: 2
compound_severity: high
```

Data residency control exists (S3 region approved) but is
structurally violated by cross-border access paths.

## Key files

| File | Purpose |
|---|---|
| `controls/exposure/sovereignty/CTL.EXPOSURE.SOVEREIGNTY.001.yaml` | Sovereignty control |
| `chains/sovereignty_violation.yaml` | Compound chain definition |
