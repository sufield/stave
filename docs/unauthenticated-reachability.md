# Unauthenticated Reachability

Unauthenticated reachability answers: "Can an anonymous principal
reach this sensitive resource through any composition of access
grants?"

This is the system-level check that no CIS benchmark tool provides.
Individual resources may pass every check in isolation, but the
composition of API Gateway → Lambda → IAM Role → S3 Bucket creates
an unauthenticated path to data. Stave detects this by evaluating
pre-computed reachability metadata from the extractor.

## How it works

### Extractor computes, Stave evaluates

Stave does not traverse access graphs. The extractor performs BFS
from the anonymous principal node and stores the results as
observation properties:

```
Extractor                              Stave
────────                              ─────
Build directed graph from config →    Check reachable == true
BFS from anonymous principal    →    Check target_data_classification in [phi, pii, confidential]
Count hops in shortest path     →    Check path_hop_count > 3
Detect auth boundaries in path  →    Check has_auth_boundary == false
Store on each target resource   →    Evaluate as standard predicates
```

This preserves Stave's core promise: deterministic evaluation of
YAML controls against observation properties. No graph engine in
the CLI.

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
        - "anonymous"
        - "apigateway:my-api/GET/*"
        - "lambda:my-function"
        - "iam_role:my-lambda-role"
        - "s3:my-phi-bucket"
      target_data_classification: phi
      has_auth_boundary: false
      auth_boundary_type: null
      entry_point_type: apigateway
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
6. Record the shortest path, hop count, and auth boundary presence
7. Store results as `reachability.*` properties on the target asset

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

The path from anonymous to the resource has zero authentication or
authorization friction — no WAF, no Cognito authorizer, no Lambda
authorizer, no IAM auth. The public internet has direct, unfiltered
access to the resource.

**Remediation:** Add a boundary. Attach a WAF web ACL with managed
rule groups. Configure a Cognito user pool or Lambda authorizer on
API Gateway routes. Enable IAM authorization on the API Gateway
stage.

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

### JSON

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
  }]
}
```

### Text

```
Compound Risk Chains
--------------------

  [CRITICAL] Chain: unauthenticated_data_path
  Sensitive resource reachable from anonymous with no auth boundary.
  Failing:    CTL.EXPOSURE.ANON.001, CTL.EXPOSURE.ANON.003
  Fix any of: CTL.APIGATEWAY.AUTH.001, CTL.WAF.RULES.001
  Score:      62.5
  Stages:     initial_access
```

"Fix any of" shows the cheapest remediation: adding an API Gateway
authorizer or enabling WAF rules would break the chain below its
escalation threshold.

## The composition problem

This feature detects what no CIS benchmark or CSPM scanner catches:

| Tool | What it sees | What it misses |
|---|---|---|
| Scanner | API Gateway: PASS, Lambda: PASS, IAM Role: PASS, S3: PASS | The chain creates anonymous access to PHI |
| Stave | Same 4 resources pass individually | **CRITICAL: anonymous → API GW → Lambda → Role → S3 (PHI)** |

Each resource is correctly configured for its intended purpose. The
API Gateway is meant to be public. The Lambda function needs its
execution role. The role needs S3 access. But the composition is
not intended — and no individual check flags it.

## Relationship to other blast radius features

| Type | What it measures | Documentation |
|---|---|---|
| Control blast radius | How disabling a control blinds the account | [Blast Radius](blast-radius.md) |
| Identity blast radius | How many resources a compromised role reaches | [Identity Blast Radius](identity-blast-radius.md) |
| Unauthenticated reachability | Whether anonymous can reach sensitive data | This page |

## Key files

| File | Purpose |
|---|---|
| `controls/exposure/anon/CTL.EXPOSURE.ANON.001-003.yaml` | 3 reachability controls |
| `chains/unauthenticated_data_path.yaml` | Compound chain definition |
| `docs/observation-contract.md` | `reachability.*` namespace specification |
