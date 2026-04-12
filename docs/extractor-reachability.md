# Building a Reachability Extractor

This guide describes how to build an extractor that computes
unauthenticated reachability paths and produces `obs.v0.1` JSON
for evaluation by Stave's `CTL.EXPOSURE.ANON.*` controls.

Stave does not traverse graphs. Your extractor performs BFS from
the anonymous principal node, annotates each reachable target
resource, and outputs the results as observation properties.

## Overview

```
Your Extractor                        Stave
────────────────                      ─────
Build directed graph from config  →   Check reachable == true
BFS from anonymous principal      →   Check target_data_classification in [phi, pii, confidential]
Count hops in shortest path       →   Check path_hop_count > 3
Detect auth/inspection boundaries →   Check has_auth_boundary == false
Track graph completeness          →   Check is_fully_resolved == false
Record blocking points            →   Display proof of obstruction
Output obs.v0.1 JSON              →   Evaluate as standard predicates
```

## Step 1: Build the access graph

### Nodes

| Node type | AWS source | How to enumerate |
|---|---|---|
| `anonymous` | Synthetic | Create one node representing the public internet |
| `entry_point` | API Gateway, ALB, CloudFront | `apigateway:GetRestApis`, `elbv2:DescribeLoadBalancers` |
| `compute` | Lambda, ECS, EC2 | `lambda:ListFunctions`, `ecs:ListTasks` |
| `identity` | IAM roles | `iam:ListRoles`, `iam:GetRole` |
| `storage` | S3, DynamoDB, RDS, Secrets Manager | `s3:ListBuckets`, `dynamodb:ListTables` |
| `network` | VPC endpoints, security groups | `ec2:DescribeVpcEndpoints`, `ec2:DescribeSecurityGroups` |

### Edges (access grants)

| Edge type | Source → Target | How to discover |
|---|---|---|
| API Gateway integration | entry_point → compute | `apigateway:GetIntegration` (Lambda URI) |
| Lambda execution role | compute → identity | `lambda:GetFunction` → `Configuration.Role` |
| IAM policy grant | identity → storage | `iam:ListAttachedRolePolicies` + `iam:GetPolicyVersion` |
| Role assumption | identity → identity | `sts:AssumeRole` in policy statements |
| Bucket policy | anonymous/identity → storage | `s3:GetBucketPolicy` → Principal analysis |
| VPC endpoint policy | network → storage | `ec2:DescribeVpcEndpoints` → PolicyDocument |
| Security group rule | network → compute | `ec2:DescribeSecurityGroups` → IpPermissions |

### Edge direction

Edges point from **accessor to resource** (who can reach what).
The anonymous node connects to all public entry points.

## Step 2: BFS from anonymous

```python
from collections import deque

def bfs_from_anonymous(graph):
    """Returns {resource_id: path} for all reachable resources."""
    queue = deque([("anonymous", ["anonymous"])])
    visited = {"anonymous"}
    reachable = {}

    while queue:
        node, path = queue.popleft()
        for neighbor in graph.neighbors(node):
            if neighbor not in visited:
                visited.add(neighbor)
                new_path = path + [neighbor]
                if graph.is_resource(neighbor):
                    reachable[neighbor] = new_path
                queue.append((neighbor, new_path))

    return reachable
```

Record the **shortest path** (BFS guarantees this). The path
becomes the `path_summary` property.

## Step 3: Detect boundaries

For each edge in the path, check if it passes through an
authentication or inspection boundary.

### Authentication boundaries (identity verification)

| Type | How to detect |
|---|---|
| `cognito` | API Gateway method has `authorizationType: COGNITO_USER_POOLS` |
| `lambda_authorizer` | API Gateway method has `authorizationType: CUSTOM` |
| `iam` | API Gateway method has `authorizationType: AWS_IAM` |
| `mtls` | API Gateway stage has mutual TLS configured |

### Inspection boundaries (request filtering)

| Type | How to detect |
|---|---|
| `waf` | `wafv2:GetWebACLForResource` returns a WebACL for the stage/ALB |
| `api_gateway_request_validation` | API Gateway method has `requestValidatorId` set |

Set `has_auth_boundary = true` if any authentication type is found.
Set `has_inspection_boundary = true` if any inspection type is found.
Populate the `auth_boundary_types` and `inspection_boundary_types`
arrays with all detected types.

**Important:** WAF is inspection, not authentication. A path with
WAF but no authorizer is inspected but still unauthenticated.

## Step 4: Track graph completeness

During BFS, when you encounter an access-denied error or missing
configuration, mark the path as partially resolved:

```python
try:
    policy_doc = iam.get_role_policy(role_name, policy_name)
except iam.exceptions.AccessDeniedException:
    path.is_fully_resolved = False
    path.unresolved_reason = "access_denied_on_iam_policy_lookup"
```

Controls that fire on partially-resolved paths:
- `CTL.EXPOSURE.ANON.PARTIAL.001` (severity: medium)

This is the "unknown" state — the extractor cannot prove safety
beyond the unresolved node. The auditor decides whether to grant
additional permissions or accept the risk.

## Step 5: Read data classification tags

For each reachable resource, read its tags to determine sensitivity:

```python
def classify_resource(arn):
    tags = resourcegroupstaggingapi.get_resources(
        ResourceARNList=[arn]
    )["ResourceTagMappingList"][0]["Tags"]

    for tag in tags:
        if tag["Key"].lower() in ("data-classification", "data_classification"):
            return tag["Value"].lower()  # phi, pii, confidential, public
    return "none"
```

The `target_data_classification` field drives the core control
`CTL.EXPOSURE.ANON.001` — only `phi`, `pii`, and `confidential`
trigger the critical finding.

## Step 6: Record negative assurance

When BFS cannot reach a resource (because a boundary blocks the
path), record **where** the path was blocked:

```python
if not reachable:
    observation["blocked_at"] = {
        "node_type": "entry_point",
        "id": "apigateway:my-api/GET/*",
        "reason": "cognito_authorizer"
    }
```

This provides formal proof of safety for auditors. The `blocked_at`
field shows the exact resource and boundary type that terminated
the path.

Possible `reason` values:
- `cognito_authorizer` — Cognito user pool blocks unauthenticated
- `iam_authorization` — IAM auth required on API Gateway
- `lambda_authorizer` — Custom Lambda authorizer blocks
- `no_route` — No network path exists (security group/NACL)
- `resource_policy_deny` — Explicit deny in resource-based policy
- `vpc_endpoint_policy` — VPC endpoint policy restricts access

## Step 7: Encode path summary as objects

Each node in `path_summary` is an object with type, identifier,
and optional remediation hint:

```json
{
  "path_summary": [
    {
      "node_type": "entry_point",
      "id": "apigateway:my-api/GET/*",
      "fix_hint": "aws apigateway update-method --authorization-type COGNITO_USER_POOLS"
    },
    {
      "node_type": "compute",
      "id": "lambda:my-function",
      "fix_hint": null
    },
    {
      "node_type": "identity",
      "id": "iam_role:my-lambda-role",
      "fix_hint": null
    },
    {
      "node_type": "storage",
      "id": "s3:my-phi-bucket",
      "fix_hint": "Restrict s3:GetObject to VPC endpoint"
    }
  ]
}
```

### Fix efficiency

When providing `fix_hint`, prefer fixes at the **ingress** (entry
point) over fixes at the **egress** (target resource). An
authorizer at the API Gateway protects every resource behind that
API, while a bucket policy fix only protects one bucket.

Priority order:
1. **Entry point fix** (highest efficiency) — blocks all paths
2. **Identity fix** — scopes the role's reach
3. **Target fix** (defense-in-depth) — protects one resource

### Node types

| `node_type` | Description | Examples |
|---|---|---|
| `entry_point` | First externally-facing service | API Gateway, ALB, CloudFront |
| `compute` | Execution environment | Lambda, ECS task, EC2 instance |
| `identity` | IAM principal | IAM role, service account |
| `storage` | Data store (target resource) | S3 bucket, DynamoDB table, RDS |
| `network` | Network boundary | VPC endpoint, security group |

## Step 8: Output obs.v0.1 JSON

Assemble the full observation. Each reachable (or proven-safe)
resource gets a `reachability` property:

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-04-12T00:00:00Z",
  "assets": [
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
              {"node_type": "entry_point", "id": "apigateway:my-api/GET/*", "fix_hint": "Enable Cognito authorizer"},
              {"node_type": "compute", "id": "lambda:my-function", "fix_hint": null},
              {"node_type": "identity", "id": "iam_role:my-lambda-role", "fix_hint": null},
              {"node_type": "storage", "id": "s3:my-phi-bucket", "fix_hint": "Restrict to VPC endpoint"}
            ],
            "target_data_classification": "phi",
            "has_auth_boundary": false,
            "auth_boundary_types": [],
            "has_inspection_boundary": true,
            "inspection_boundary_types": ["waf"],
            "is_fully_resolved": true,
            "unresolved_reason": null,
            "entry_point_type": "apigateway",
            "blocked_at": null
          }
        }
      }
    }
  ]
}
```

## Required AWS permissions

The extractor needs read-only access to enumerate the graph:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": [
      "apigateway:GET",
      "lambda:GetFunction",
      "lambda:GetPolicy",
      "iam:ListRoles",
      "iam:ListAttachedRolePolicies",
      "iam:GetRolePolicy",
      "iam:GetPolicyVersion",
      "s3:GetBucketPolicy",
      "s3:GetBucketTagging",
      "elasticloadbalancing:DescribeLoadBalancers",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeRules",
      "ec2:DescribeSecurityGroups",
      "ec2:DescribeVpcEndpoints",
      "wafv2:GetWebACLForResource",
      "tag:GetResources"
    ],
    "Resource": "*"
  }]
}
```

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.EXPOSURE.ANON.001 | Sensitive resource reachable from anonymous | critical |
| CTL.EXPOSURE.ANON.002 | Path exceeds 3 hops | high |
| CTL.EXPOSURE.ANON.003 | No authentication boundary | high |
| CTL.EXPOSURE.ANON.004 | No inspection boundary | medium |
| CTL.EXPOSURE.ANON.PARTIAL.001 | Path not fully resolved | medium |
| CTL.EXPOSURE.ANON.INCOMPLETE.001 | Missing reachable field | low |
