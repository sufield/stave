# Reachability Domain

Cross-cutting reachability analysis. The `reachability.*` namespace
overlays any asset type — an S3 bucket, DynamoDB table, Secrets Manager
secret, etc., may carry `reachability.*` fields populated by post-
collection graph traversal.

Part of the [observation contract](README.md).

## Unauthenticated reachability namespace

The `reachability.*` namespace is a cross-cutting concern overlaid on any
asset type (S3 bucket, DynamoDB table, Secrets Manager secret, etc.). The
extractor performs BFS from an anonymous principal node through access
grants (IAM policies, bucket policies, role assumptions, VPC endpoint
policies, security group rules) and annotates each reachable target
resource with path metadata.

### Core properties

| Property | Type | Description |
|---|---|---|
| `reachability.kind` | string | Discriminator: `anonymous_path` |
| `reachability.anonymous_path.reachable` | bool | Resource is reachable from anonymous |
| `reachability.anonymous_path.path_hop_count` | int | Edges in shortest path from anonymous |
| `reachability.anonymous_path.target_data_classification` | string | `phi`, `pii`, `confidential`, `public`, `none` |
| `reachability.anonymous_path.entry_point_type` | string/null | First externally-facing service (`apigateway`, `elb`, etc.) |

### Boundary properties

Authentication and inspection are distinct concepts. An authentication
boundary verifies **identity** (who are you?). An inspection boundary
verifies **request safety** (is your request malicious?). A path with
WAF but no authorizer is inspected but still unauthenticated.

| Property | Type | Description |
|---|---|---|
| `reachability.anonymous_path.has_auth_boundary` | bool | Path has at least one identity verification point |
| `reachability.anonymous_path.auth_boundary_types` | string[] | `cognito`, `lambda_authorizer`, `iam`, `mtls` |
| `reachability.anonymous_path.has_inspection_boundary` | bool | Path has at least one request filtering point |
| `reachability.anonymous_path.inspection_boundary_types` | string[] | `waf`, `api_gateway_request_validation` |

### Graph completeness

When the extractor cannot fully resolve all nodes in a path (e.g.,
access denied on an IAM policy lookup), the path is partially resolved.
Safety cannot be proven for unresolved segments.

| Property | Type | Description |
|---|---|---|
| `reachability.anonymous_path.is_fully_resolved` | bool | All intermediate nodes were inspected |
| `reachability.anonymous_path.unresolved_reason` | string/null | `access_denied_on_iam_policy_lookup`, `missing_lambda_config`, etc. |

### Path summary (structured)

Each node in the path is an object with type, identifier, and optional
remediation hint. This enables CLI deep links and fix-efficiency ranking.

| Property | Type | Description |
|---|---|---|
| `reachability.anonymous_path.path_summary` | object[] | Ordered nodes in the shortest path |
| `path_summary[].node_type` | string | `entry_point`, `compute`, `identity`, `storage`, `network` |
| `path_summary[].id` | string | Resource identifier (ARN, name) |
| `path_summary[].fix_hint` | string/null | CLI command or remediation action for this node |

### Negative assurance (proof of obstruction)

When `reachable == false`, the `blocked_at` field records where the
path was terminated. This provides formal proof of safety for auditors.

| Property | Type | Description |
|---|---|---|
| `reachability.anonymous_path.blocked_at` | object/null | Where the path was blocked (null if reachable) |
| `blocked_at.node_type` | string | Type of the blocking node |
| `blocked_at.id` | string | Identifier of the blocking resource |
| `blocked_at.reason` | string | `iam_authorization`, `cognito_authorizer`, `no_route`, etc. |

### Example: unsafe path (reachable, no auth boundary)

```json
{
  "id": "arn:aws:s3:::my-phi-bucket",
  "type": "aws_s3_bucket",
  "vendor": "aws",
  "properties": {
    "reachability": {
      "kind": "anonymous_path",
      "anonymous_path": {
        "reachable": true,
        "path_hop_count": 4,
        "path_summary": [
          {"node_type": "entry_point", "id": "apigateway:my-api/GET/*", "fix_hint": "aws apigateway update-method --authorization-type COGNITO_USER_POOLS"},
          {"node_type": "compute", "id": "lambda:my-function", "fix_hint": null},
          {"node_type": "identity", "id": "iam_role:my-lambda-role", "fix_hint": null},
          {"node_type": "storage", "id": "s3:my-phi-bucket", "fix_hint": "Restrict s3:GetObject to VPC endpoint"}
        ],
        "target_data_classification": "phi",
        "has_auth_boundary": false,
        "auth_boundary_types": [],
        "has_inspection_boundary": true,
        "inspection_boundary_types": ["waf"],
        "is_fully_resolved": true,
        "entry_point_type": "apigateway",
        "blocked_at": null
      }
    }
  }
}
```

### Example: safe path (blocked by authorizer)

```json
{
  "id": "arn:aws:s3:::my-protected-bucket",
  "type": "aws_s3_bucket",
  "vendor": "aws",
  "properties": {
    "reachability": {
      "kind": "anonymous_path",
      "anonymous_path": {
        "reachable": false,
        "path_hop_count": 0,
        "path_summary": [],
        "target_data_classification": "phi",
        "has_auth_boundary": true,
        "auth_boundary_types": ["cognito"],
        "has_inspection_boundary": true,
        "inspection_boundary_types": ["waf"],
        "is_fully_resolved": true,
        "entry_point_type": null,
        "blocked_at": {
          "node_type": "entry_point",
          "id": "apigateway:my-api/GET/*",
          "reason": "cognito_authorizer"
        }
      }
    }
  }
}
```

**Controls:** CTL.EXPOSURE.ANON.001 (sensitive reachable), .002 (deep chain),
.003 (no auth boundary), .004 (no inspection boundary), .PARTIAL.001
(unresolved path). See [Extractor Guide: Reachability](../extractor-reachability.md).

---

## Data exfiltration namespace

The `reachability.exfiltration.*` namespace tracks whether sensitive data
can reach the internet through compute instances with outbound connectivity.
The extractor traces from the sensitive resource to compute instances that
can read it, then checks for internet egress paths.

| Property | Type | Description |
|---|---|---|
| `reachability.kind` | string | Discriminator: `exfiltration_path` |
| `reachability.exfiltration.path_to_internet_exists` | bool | Compute has outbound internet path (IGW, NAT) |
| `reachability.exfiltration.vector` | string | `compute_with_igw_plus_wildcard_write`, etc. |
| `reachability.exfiltration.egress_type` | string | `internet_gateway`, `nat_gateway`, `vpc_peering` |
| `reachability.exfiltration.compute_id` | string | ARN of the compute instance with egress |
| `reachability.exfiltration.has_wildcard_write` | bool | Instance role has s3:PutObject on Resource "*" |
| `reachability.exfiltration.sensitive_data_readable` | bool | Compute can read the sensitive resource |
| `reachability.exfiltration.target_data_classification` | string | `phi`, `pii`, `confidential`, `public`, `none` |

**Controls:** CTL.EXPOSURE.EXFIL.001 (sensitive data + egress),
.002 (wildcard write + egress).

---


## Sovereignty namespace

The `reachability.sovereignty.*` namespace tracks cross-border
access patterns for jurisdictional compliance.

| Property | Type | Description |
|---|---|---|
| `reachability.kind` | string | Discriminator: `cross_border` |
| `reachability.sovereignty.cross_border_access_detected` | bool | Resource accessible from outside jurisdiction |
| `reachability.sovereignty.resource_jurisdiction` | string | `eu`, `us`, `apac`, etc. |
| `reachability.sovereignty.accessor_jurisdiction` | string | Jurisdiction of the accessing principal |
| `reachability.sovereignty.target_sensitivity` | string | `phi`, `pii`, `confidential`, `public`, `none` |

**Controls:** CTL.EXPOSURE.SOVEREIGNTY.001 (cross-border access to
sensitive data).

---

