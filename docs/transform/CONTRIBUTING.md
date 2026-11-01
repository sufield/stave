# Adding an Extractor

Extractor logic lives in the **Lean 4** project at
`iam-explainer/Stave/Extract/`. Each module converts raw AWS CLI JSON into
Stave's `obs.v0.1` observation format with formal verification.

## Module map

| Module | Coverage |
|---|---|
| `S3.lean` | Buckets, encryption, public access block, tags |
| `IAM.lean` | Roles, users, groups, password policy, inline policies, attached policies, tags |
| `EC2.lean` | Instances, security groups, volumes |
| `CloudTrail.lean` | Trails |
| `KMS.lean` | Keys, rotation, key policy |
| `Misc.lean` | Config recorders, OpenSearch, CloudWatch, Lambda |

## Analysis extractors

| Module | Purpose |
|---|---|
| `CrossEnv.lean` | BFS trust chain analysis across environments |
| `Escalation.lean` | 10-vector privilege escalation pattern matching |
| `Exfiltration.lean` | Reverse reachability for data exfiltration paths |
| `Reachability.lean` | Anonymous BFS for unauthenticated access |
| `SupplyChain.lean` | OIDC supply chain analysis |

## Capture reference

See [capture.md](capture.md) for the exact AWS CLI calls per resource type.
