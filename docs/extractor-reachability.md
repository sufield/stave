# Reachability Extractor

BFS from the anonymous principal through an access graph. Detects
unauthenticated paths to storage resources, with authentication and
inspection boundary detection.

## Implementation

**Source:** `iam-explainer/Stave/Extract/Reachability.lean`
(`Extract.Reachability` namespace)

Pure function over already-collected data. No live API calls.

Stave does not traverse graphs. This extractor performs BFS, annotates
each reachable target resource, and outputs the results as observation
properties for Stave's CEL predicates to evaluate.

### Types

```lean
inductive NodeType where
  | anonymous | entryPoint | compute | identity | storage | network

structure GraphNode where
  nodeId : String
  nodeType : NodeType
  dataClassification : Option String := none
  fixHint : Option String := none

structure GraphEdge where
  source : String    -- accessor
  target : String    -- resource

inductive AuthBoundary where
  | cognito | lambdaAuthorizer | iam | mtls

inductive InspectionBoundary where
  | waf | requestValidation

structure ReachablePath where
  target : GraphNode
  path : List GraphNode
  hopCount : Nat
  authBoundaries : List AuthBoundary
  inspectionBoundaries : List InspectionBoundary
  isFullyResolved : Bool
  unresolvedReason : Option String
  entryPointType : Option String

structure BlockedPath where
  target : GraphNode
  blockedAtId : String
  blockedAtType : NodeType
  reason : String
```

### Pipeline

1. **`bfsFromAnonymous`** — BFS from the synthetic anonymous node.
   Returns all reachable storage nodes with their shortest paths.
   Fuel-bounded (default 100 iterations).

2. **`annotateBoundaries`** — Post-BFS pass. Takes auth and inspection
   boundary maps (`nodeId → boundary type`) and annotates each path
   with the boundaries it crosses.

3. **`transformReachability`** — Converts `List ReachablePath` into
   obs.v0.1 assets with full path summaries and boundary annotations.

4. **`transformBlocked`** — Converts `List BlockedPath` into
   negative-assurance assets showing where the path was blocked.

### Building the access graph

Edges point from **accessor to resource** (who can reach what).
The anonymous node connects to all public entry points.

| Node type | AWS source |
|---|---|
| `anonymous` | Synthetic — one node representing the public internet |
| `entry_point` | API Gateway, ALB, CloudFront |
| `compute` | Lambda, ECS, EC2 |
| `identity` | IAM roles |
| `storage` | S3, DynamoDB, RDS, Secrets Manager |
| `network` | VPC endpoints, security groups |

| Edge type | Source → Target |
|---|---|
| API Gateway integration | entry_point → compute |
| Lambda execution role | compute → identity |
| IAM policy grant | identity → storage |
| Role assumption | identity → identity |
| Bucket policy | anonymous/identity → storage |
| VPC endpoint policy | network → storage |
| Security group rule | network → compute |

### Authentication vs inspection boundaries

WAF is inspection, not authentication. A path with WAF but no
authorizer is inspected but still unauthenticated.

| Authentication | Inspection |
|---|---|
| `cognito` — Cognito user pool | `waf` — WAF WebACL |
| `lambda_authorizer` — Custom authorizer | `requestValidation` — API Gateway request validator |
| `iam` — IAM authorization | |
| `mtls` — Mutual TLS | |

### Negative assurance

When BFS cannot reach a resource, `transformBlocked` records where the
path was blocked — providing formal proof of safety for auditors.

Possible `reason` values: `cognito_authorizer`, `iam_authorization`,
`lambda_authorizer`, `no_route`, `resource_policy_deny`,
`vpc_endpoint_policy`.

### Fix efficiency

Path summaries include `fix_hint` per node. Prefer fixes at ingress
over egress:

1. **Entry point fix** (highest efficiency) — blocks all paths
2. **Identity fix** — scopes the role's reach
3. **Target fix** (defense-in-depth) — protects one resource

## Output (obs.v0.1)

### Reachable resource

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
        "entry_point_type": "apigateway:my-api/GET/*",
        "blocked_at": null
      }
    }
  }
}
```

### Blocked resource (negative assurance)

```json
{
  "id": "arn:aws:s3:::protected-bucket",
  "type": "aws_s3_bucket",
  "vendor": "aws",
  "properties": {
    "reachability": {
      "kind": "anonymous_path",
      "anonymous_path": {
        "reachable": false,
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

## Verified properties

- 3-hop path (anonymous → API GW → Lambda → S3) produces hop count 3 (`#guard`)
- No path to storage produces empty results (`#guard`)
- Boundary annotation correctly attaches auth and inspection types (`#guard`)

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.EXPOSURE.ANON.001 | Sensitive resource reachable from anonymous | critical |
| CTL.EXPOSURE.ANON.002 | Path exceeds 3 hops | high |
| CTL.EXPOSURE.ANON.003 | No authentication boundary | high |
| CTL.EXPOSURE.ANON.004 | No inspection boundary | medium |
| CTL.EXPOSURE.ANON.PARTIAL.001 | Path not fully resolved | medium |
| CTL.EXPOSURE.ANON.INCOMPLETE.001 | Missing reachable field | low |
