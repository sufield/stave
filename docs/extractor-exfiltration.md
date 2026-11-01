# Exfiltration Extractor

Traces reverse reachability: starting at sensitive resources, finding
compute instances that can both read the data and reach the internet.

## Implementation

**Source:** `iam-explainer/Stave/Extract/Exfiltration.lean`
(`Extract.Exfiltration` namespace)

Pure function over already-collected data. No live API calls.

### Types

```lean
inductive EgressType where
  | internetGateway | natGateway | vpcPeering | none

structure SensitiveResource where
  arn : String
  assetType : String
  classification : String  -- "phi" | "pii" | "confidential"

structure ComputeReader where
  computeArn : String
  roleArn : String
  egress : EgressType
  hasWildcardWrite : Bool

structure ExfilPath where
  resource : SensitiveResource
  reader : ComputeReader
```

### Pipeline

1. **`identifySensitive`** — Scans asset tags for `data-classification`
   or `data_classification` keys with values `phi`, `pii`, or
   `confidential` (case-insensitive).

2. **`classifyEgress`** — Determines egress type from route table
   routes by checking `GatewayId` (igw-*), `NatGatewayId`, and
   `VpcPeeringConnectionId` fields.

3. **`transformExfiltration`** — Orchestrator. Takes `List ExfilPath`,
   filters to paths with internet egress, outputs `List ObsAsset`.
   Paths without internet egress are silently dropped (no finding).

### Building ExfilPath inputs

Assemble `ExfilPath` values by joining three data sources:

- **Sensitive resources:** Tag-based classification from
  `identifySensitive` or a manual list.
- **Compute readers:** For each sensitive resource, find compute
  instances whose IAM role grants read access (`s3:GetObject`,
  `dynamodb:GetItem`, etc.).
- **Egress classification:** For each compute instance's subnet,
  pass route table routes through `classifyEgress`.

### Egress types

| Type | Meaning |
|---|---|
| `internet_gateway` | Direct internet access via IGW |
| `nat_gateway` | Outbound via NAT (can still exfiltrate) |
| `vpc_peering` | To a VPC with internet access |
| `none` | No internet path (filtered from output) |

## Output (obs.v0.1)

```json
{
  "id": "arn:aws:s3:::phi-records",
  "type": "aws_s3_bucket",
  "vendor": "aws",
  "properties": {
    "reachability": {
      "kind": "exfiltration_path",
      "exfiltration": {
        "path_to_internet_exists": true,
        "vector": "compute_with_igw_plus_wildcard_write",
        "egress_type": "internet_gateway",
        "compute_id": "arn:aws:ec2:us-east-1:123456789:instance/i-abc123",
        "has_wildcard_write": true,
        "sensitive_data_readable": true,
        "target_data_classification": "phi"
      }
    }
  }
}
```

## Verified properties

- IGW route classified as `internetGateway` (`#guard`)
- NAT route classified as `natGateway` (`#guard`)
- Local-only route classified as `none` (`#guard`)
- PHI resource with IGW egress produces finding (`#guard`)
- No internet egress produces empty output (`#guard`)

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.EXPOSURE.EXFIL.001 | Sensitive data + internet egress | critical |
| CTL.EXPOSURE.EXFIL.002 | Wildcard write + internet egress | high |
| CTL.EXPOSURE.EXFIL.INCOMPLETE.001 | Missing egress data | low |
