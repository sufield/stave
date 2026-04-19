# Data Exfiltration Path

Data exfiltration path analysis answers: "How can data get out?"
This is the reverse of unauthenticated reachability — instead of
tracing inbound from anonymous, it traces outbound from sensitive
data to the internet.

## The exfiltration model

A resource may be private with proper access controls, yet attached
to a compute instance that has both read access to the data and an
outbound internet path. A compromised instance can copy sensitive
data to an external destination.

```
Sensitive Resource → Compute (read access) → Internet (egress)
     S3 bucket         EC2 instance           IGW / NAT
     DynamoDB          Lambda function         VPC peering
     RDS               ECS task
```

The extractor traces this reverse path:
1. Start at the sensitive resource
2. Find compute instances that can read it
3. Check if those instances have outbound internet connectivity
4. Check if those instances have wildcard write permissions

## How it works

### Extractor computes, Stave evaluates

The extractor performs reverse reachability analysis and stores
results as observation properties:

```
Extractor                              Stave
────────                              ─────
Find compute with data read access →  Check sensitive_data_readable == true
Check for internet egress path     →  Check path_to_internet_exists == true
Check for wildcard write perms     →  Check has_wildcard_write == true
Store on each target resource      →  Evaluate as standard predicates
```

### Observation properties

```yaml
properties:
  reachability:
    kind: exfiltration_path
    exfiltration:
      path_to_internet_exists: true
      vector: "compute_with_igw_plus_wildcard_write"
      egress_type: "internet_gateway"
      compute_id: "arn:aws:ec2::.../i-abc123"
      has_wildcard_write: true
      sensitive_data_readable: true
      target_data_classification: "phi"
```

## Controls

### CTL.EXPOSURE.EXFIL.001 — Sensitive data readable by compute with internet egress

```
Fires when: path_to_internet_exists == true
        AND sensitive_data_readable == true
Severity: critical
```

A compute instance can read the sensitive resource AND has an
unmonitored path to the internet. Credential compromise on that
instance enables direct data exfiltration.

**Remediation:** Place sensitive-data-accessing instances in private
subnets with VPC endpoints only. Remove internet gateways from the
instance's route table. Scope the instance role to minimum required
resources.

### CTL.EXPOSURE.EXFIL.002 — Compute with wildcard write and internet egress

```
Fires when: path_to_internet_exists == true
        AND has_wildcard_write == true
Severity: high
```

An instance with s3:PutObject on Resource "*" and outbound internet
can write data to any S3 bucket — including attacker-controlled
external buckets.

**Remediation:** Scope write permissions to specific resource ARNs.
Use VPC endpoints with bucket-scoped policies to restrict write
targets.

## Safety chain: data_exfiltration_path

The exfiltration controls participate in a compound chain with
monitoring controls:

```yaml
id: data_exfiltration_path
controls:
  - CTL.EXPOSURE.EXFIL.001
  - CTL.EXPOSURE.EXFIL.002
  - CTL.VPC.FLOWLOG.001
  - CTL.CLOUDTRAIL.DATAREAD.001
escalation_threshold: 2
compound_severity: critical
```

When sensitive data is exfiltrable AND there is no audit trail
(VPC flow logs or CloudTrail data events), the compound finding
fires: data can leave with minimal detection risk.

## Relationship to other features

| Feature | Direction | Question it answers |
|---|---|---|
| Unauthenticated reachability | Inbound | Can anonymous get to sensitive data? |
| Data exfiltration | Outbound | Can sensitive data reach the internet? |
| Identity blast radius | Lateral | How far can a compromised credential reach? |
| Cross-env pivot | Lateral | Can non-prod reach prod? |

## Key files

| File | Purpose |
|---|---|
| `controls/exposure/exfil/CTL.EXPOSURE.EXFIL.001-002.yaml` | 2 exfiltration controls |
| `chains/data_exfiltration_path.yaml` | Compound chain definition |
| `docs/contract/README.md` | `reachability.exfiltration.*` namespace |
| `docs/extractor-exfiltration.md` | Extractor implementation guide |
