# Unauthenticated Reachability

Unauthenticated reachability answers: "Can an anonymous principal
reach this sensitive resource through any composition of access
grants?"

This is a system-level composition check. Individual resources may
pass every check in isolation, but the
composition of API Gateway → Lambda → IAM Role → S3 Bucket creates
an unauthenticated path to data. Stave detects this by evaluating
pre-computed reachability metadata from the extractor.

## How it works

### Extractor computes, Stave evaluates

The extractor performs BFS from the anonymous principal node and
stores the results as observation properties. Stave evaluates them:

```
Extractor                              Stave
────────                              ─────
Build directed graph from config →    Check reachable == true
BFS from anonymous principal    →    Check target_data_classification in [phi, pii, confidential]
Count hops in shortest path     →    Check path_hop_count > 3
Detect auth boundaries          →    Check has_auth_boundary == false
Detect inspection boundaries    →    Check has_inspection_boundary == false
Track graph completeness        →    Check is_fully_resolved == false
Record blocking points          →    Display proof of obstruction
Store on each target resource   →    Evaluate as standard predicates
```

This preserves Stave's core promise: deterministic evaluation of
YAML controls against observation properties.

### Graph model

The extractor builds a directed graph where:

**Nodes:** Principals (IAM users, roles, service principals,
anonymous) and resources (S3 buckets, DynamoDB tables, Lambda
functions, API Gateways).

**Edges:** Access grants — IAM policies, bucket policies, role
assumptions (`sts:AssumeRole`), VPC endpoint policies, Lambda
resource-based policies, security group rules.

**Traversal:** BFS from the anonymous node. Every resource reached
is annotated with path metadata.

### Observation properties

The extractor populates these fields on each reachable target
resource:

```yaml
properties:
  reachability:
    kind: anonymous_path
    anonymous_path:
      reachable: true
      path_hop_count: 4
      path_summary:
        - node_type: entry_point
          id: "apigateway:my-api/GET/*"
          fix_hint: "aws apigateway update-method --authorization-type COGNITO_USER_POOLS"
        - node_type: compute
          id: "lambda:my-function"
        - node_type: identity
          id: "iam_role:my-lambda-role"
        - node_type: storage
          id: "s3:my-phi-bucket"
          fix_hint: "Restrict s3:GetObject to VPC endpoint"
      target_data_classification: phi
      has_auth_boundary: false
      auth_boundary_types: []
      has_inspection_boundary: true
      inspection_boundary_types: ["waf"]
      is_fully_resolved: true
      entry_point_type: apigateway
      blocked_at: null
```

**Boundary types** — authentication and inspection are distinct:

| Category | Verifies | Types |
|---|---|---|
| Authentication | Identity (who are you?) | `cognito`, `lambda_authorizer`, `iam`, `mtls` |
| Inspection | Request safety (is it malicious?) | `waf`, `api_gateway_request_validation` |

A path with WAF but no authorizer is inspected but still
unauthenticated. Both are needed for defense-in-depth.

**Graph completeness** — when the extractor cannot resolve all nodes:

- `is_fully_resolved: false` — safety cannot be proven
- `unresolved_reason: "access_denied_on_iam_policy_lookup"` — why

**Negative assurance** — when `reachable == false`, the `blocked_at`
field records where the path was terminated, providing formal proof
of safety:

```yaml
blocked_at:
  node_type: entry_point
  id: "apigateway:my-api/GET/*"
  reason: cognito_authorizer
```

### Extractor analysis steps

1. Enumerate all API Gateway stages, ALB listeners, and other
   public entry points
2. For each entry point, follow Lambda integrations and backend
   targets
3. For each Lambda function, resolve its execution role
4. For each IAM role, parse attached and inline policies for
   resource access grants
5. For each accessible resource, read its data classification tags
6. Detect **authentication** boundaries (Cognito, Lambda authorizer,
   IAM, mTLS) — these verify identity
7. Detect **inspection** boundaries (WAF, API Gateway request
   validation) — these filter malicious requests
8. Track **graph completeness** — if any node cannot be resolved
   (access denied, missing config), mark `is_fully_resolved: false`
9. For unreachable resources, record **where** the path was blocked
   in `blocked_at` (proof of obstruction)
10. Encode each path node as an object with `node_type`, `id`, and
    `fix_hint` — prefer ingress fixes over egress for efficiency
11. Store results as `reachability.*` properties on the target asset

See [Reachability Extractor Guide](extractor-reachability.md) for
the complete implementation reference with code examples and IAM
permissions.

## Controls

### CTL.EXPOSURE.ANON.001 — Sensitive resource reachable from anonymous

```
Fires when: reachable == true
        AND target_data_classification in [phi, pii, confidential]
Severity: critical
```

A resource tagged with sensitive data is reachable from the public
internet through a composition of access grants. This is the core
Prompt 11 finding — the composition attack that individual resource
checks cannot detect.

**Remediation:** Add an authorization layer to the path. Configure
an API Gateway authorizer (Cognito, Lambda, or IAM), attach a WAF
with managed rule groups, or revoke the intermediate role's access
to the sensitive resource.

### CTL.EXPOSURE.ANON.002 — Deep unauthenticated chain

```
Fires when: reachable == true
        AND path_hop_count > 3
Severity: high
```

Deep access chains (4+ hops) indicate unintended transitive access.
Each hop is an access grant that widens the blast radius beyond
what was intended. Shorter paths are more likely intentional.

**Remediation:** Flatten the chain. Remove unnecessary intermediate
services. Scope Lambda execution role permissions to minimum
required resources. Replace broad role assumption chains with direct
service-linked roles.

### CTL.EXPOSURE.ANON.003 — No auth boundary in path

```
Fires when: reachable == true
        AND has_auth_boundary == false
Severity: high
```

The path from anonymous to the resource has no authentication
boundary — no identity verification point (Cognito, Lambda
authorizer, IAM, mTLS). An inspection boundary (WAF) may exist
but does not establish identity. The path is still unauthenticated.

**Remediation:** Add an authentication boundary. Configure a
Cognito user pool or Lambda authorizer on API Gateway routes.
Enable IAM authorization. For service-to-service, enable mTLS.

### CTL.EXPOSURE.ANON.004 — No inspection boundary in path

```
Fires when: reachable == true
        AND has_inspection_boundary == false
Severity: medium
```

The path has no request filtering — no WAF managed rules, no
API Gateway request validation. Even if authenticated, malicious
payloads are not inspected. Both boundaries needed for
defense-in-depth.

**Remediation:** Attach a WAF web ACL with managed rule groups to
the API Gateway stage or ALB. Enable API Gateway request validation.

### CTL.EXPOSURE.ANON.PARTIAL.001 — Partially resolved path

```
Fires when: reachable == true
        AND is_fully_resolved == false
Severity: medium
```

The extractor found a path from anonymous but could not resolve all
intermediate nodes. Safety cannot be proven for the unresolved
segment. This is the "unknown" state — the extractor needs
additional permissions.

**Remediation:** Grant the extractor read access to unresolved
resources (iam:GetRolePolicy, lambda:GetFunction, etc.).

## Safety chain: unauthenticated_data_path

The reachability controls participate in a compound chain together
with entry point protection controls:

```yaml
id: unauthenticated_data_path
controls:
  - CTL.EXPOSURE.ANON.001  # sensitive data reachable
  - CTL.EXPOSURE.ANON.003  # no auth boundary
  - CTL.APIGATEWAY.AUTH.001 # API Gateway without authorization
  - CTL.WAF.RULES.001       # WAF without managed rules
escalation_threshold: 2
compound_severity: critical
```

When a sensitive resource is reachable AND there is no auth boundary,
the compound finding fires: "anonymous principal can reach sensitive
data through a composition of access grants with zero friction."

## Example output

### Unsafe path (JSON)

```json
{
  "chain_findings": [{
    "chain": "unauthenticated_data_path",
    "controls_failing": [
      "CTL.EXPOSURE.ANON.001",
      "CTL.EXPOSURE.ANON.003"
    ],
    "missing_safeguards": [
      "CTL.APIGATEWAY.AUTH.001",
      "CTL.WAF.RULES.001"
    ],
    "compound_score": 62.5,
    "severity": "CRITICAL",
    "narrative": "Sensitive resource reachable from anonymous with no auth boundary..."
  }],
  "top_exposures": [{
    "control_id": "CTL.EXPOSURE.ANON.001",
    "asset_id": "arn:aws:s3:::my-phi-bucket",
    "exposure_score": 2000.0,
    "breakdown": {
      "base_score": 100,
      "duration_factor": 5.0,
      "blast_multiplier": 2.0,
      "exposure_multiplier": 2.0,
      "days_blind": 1826.0
    },
    "silent_killer": true
  }]
}
```

### Unsafe path (text)

```
Compound Risk Chains
--------------------

  [CRITICAL] Chain: unauthenticated_data_path
  Sensitive resource reachable from anonymous with no auth boundary.
  Failing:    CTL.EXPOSURE.ANON.001, CTL.EXPOSURE.ANON.003
  Fix any of: CTL.APIGATEWAY.AUTH.001, CTL.WAF.RULES.001
  Score:      62.5
  Stages:     initial_access

Top Exposures
-------------
   1  2000.0   1826d  CTL.EXPOSURE.ANON.001      s3:my-phi-bucket
      SILENT KILLER  base=100 x duration=5.0 x blast=2.0 x exposure=2.0
```

"Fix any of" shows the cheapest remediation: adding an API Gateway
authorizer or enabling WAF rules would break the chain below its
escalation threshold.

### Safe path (proof of obstruction)

When `reachable == false`, the `blocked_at` field proves where
the path was terminated:

```json
{
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
```

Reading: "Anonymous node explored. Path blocked at API Gateway
'my-api' by mandatory Cognito authorization." This is the formal
proof of safety that auditors need: "here is where and why the
path was stopped."

### Partially resolved path

When the extractor cannot see the full graph:

```json
{
  "reachability": {
    "kind": "anonymous_path",
    "anonymous_path": {
      "reachable": true,
      "is_fully_resolved": false,
      "unresolved_reason": "access_denied_on_iam_policy_lookup"
    }
  }
}
```

Reading: "We found a path from anonymous to Lambda, but cannot
prove safety beyond that point due to missing metadata." The
CTL.EXPOSURE.ANON.PARTIAL.001 control fires at medium severity.

### Fix efficiency in path_summary

Each node carries a `fix_hint` with the recommended remediation.
Fixes at the ingress (entry point) are more efficient than fixes
at the egress (target resource):

```json
{
  "path_summary": [
    {"node_type": "entry_point", "id": "apigateway:my-api/GET/*",
     "fix_hint": "Enable Cognito authorizer (blocks ALL paths through this API)"},
    {"node_type": "compute", "id": "lambda:my-function", "fix_hint": null},
    {"node_type": "identity", "id": "iam_role:my-lambda-role", "fix_hint": null},
    {"node_type": "storage", "id": "s3:my-phi-bucket",
     "fix_hint": "Restrict s3:GetObject to VPC endpoint (protects this bucket only)"}
  ]
}
```

The entry point fix protects every resource behind that API. The
target fix protects only one bucket. Both are valid — the entry
point is higher efficiency, the target is defense-in-depth.

## The composition problem

Individual resource checks evaluate each component in isolation.
Composition checks evaluate the access path end-to-end:

| Approach | What it evaluates | Result |
|---|---|---|
| Per-resource | API Gateway: PASS, Lambda: PASS, IAM Role: PASS, S3: PASS | 4 individual passes |
| Composition | anonymous → API GW → Lambda → Role → S3 (PHI) | **CRITICAL: unauthenticated path to sensitive data** |

Each resource is correctly configured for its intended purpose. The
API Gateway is meant to be public. The Lambda function needs its
execution role. The role needs S3 access. The composition reveals
the emergent risk — the end-to-end path that individual checks
cannot see.

## Relationship to other blast radius features

| Type | What it measures | Documentation |
|---|---|---|
| Control blast radius | How disabling a control blinds the account | [Blast Radius](blast-radius.md) |
| Identity blast radius | How many resources a compromised role reaches | [Identity Blast Radius](identity-blast-radius.md) |
| Unauthenticated reachability | Whether anonymous can reach sensitive data | This page |

## Key files

| File | Purpose |
|---|---|
| `controls/exposure/anon/CTL.EXPOSURE.ANON.001-004.yaml` | 4 reachability controls |
| `controls/exposure/anon/CTL.EXPOSURE.ANON.PARTIAL.001.yaml` | Graph completeness control |
| `chains/unauthenticated_data_path.yaml` | Compound chain definition |
| `docs/observation-contract.md` | `reachability.*` namespace specification |
| `docs/extractor-reachability.md` | Extractor implementation guide |
