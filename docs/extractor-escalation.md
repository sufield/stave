# Privilege Escalation Extractor

Detects multi-step privilege escalation chains by pattern-matching
IAM permissions against 10 known escalation vectors.

## Implementation

**Source:** `iam-explainer/Stave/Extract/Escalation.lean`
(`Extract.Escalation` namespace)

Pure function over already-collected IAM data. No live API calls.

### Known escalation vectors

| Vector | Required permissions |
|---|---|
| PassRoleToLambda | `iam:PassRole`, `lambda:CreateFunction`, `lambda:InvokeFunction` |
| CreatePolicyVersion | `iam:CreatePolicyVersion` |
| AttachRolePolicy | `iam:AttachRolePolicy` |
| CreateAccessKey | `iam:CreateAccessKey` |
| AssumeRoleChain | `sts:AssumeRole` |
| UpdateLoginProfile | `iam:UpdateLoginProfile` |
| EC2RunWithRole | `ec2:RunInstances`, `iam:PassRole` |
| GlueDevEndpoint | `glue:CreateDevEndpoint`, `iam:PassRole` |
| SageMakerNotebook | `sagemaker:CreateNotebookInstance`, `iam:PassRole` |
| CloudFormationRole | `cloudformation:CreateStack`, `iam:PassRole` |

### Types

```lean
structure EscalationVector where
  name : String
  requiredActions : List String

structure PrincipalPerms where
  arn : String
  principalType : String       -- "user" | "role"
  effectiveActions : List String
  adminRoleArns : List String  -- known admin roles for target resolution
```

### Pipeline

1. **`actionsMatch`** — Case-insensitive permission matching. Handles
   `*` (full wildcard) and `service:*` (service wildcard) grants.

2. **`collectAllowActions`** — Extracts all `Allow` actions from a
   policy document's statements. Handles both single-string and
   array-valued `Action` fields.

3. **`findEscalations`** — For a given principal, returns all matching
   vectors paired with a target admin role ARN (if known).

4. **`transformEscalation`** — Orchestrator. Takes `List PrincipalPerms`,
   outputs `List ObsAsset` with one asset per principal-vector match.

### Input

Build `PrincipalPerms` by enumerating each IAM principal's effective
permissions: attached policies, inline policies, and group memberships.
The `effectiveActions` field is the union of all `Allow` actions.

## Output (obs.v0.1)

```json
{
  "id": "arn:aws:iam::123456789:user/dev-user",
  "type": "aws_iam_user",
  "vendor": "aws",
  "properties": {
    "identity": {
      "kind": "user",
      "escalation": {
        "can_escalate_to_admin": true,
        "escalation_vector": "PassRoleToLambda",
        "steps": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "target_admin_role": "arn:aws:iam::123456789:role/AdminRole",
        "step_count": 3
      }
    }
  }
}
```

## Verified properties

- Exact permission match works (`#guard`)
- Non-matching permissions produce no results (`#guard`)
- `*` wildcard covers all required actions (`#guard`)
- `service:*` wildcard covers service-scoped actions (`#guard`)
- `CreatePolicyVersion` detected from single permission (`#guard`)
- Read-only principal produces empty escalation list (`#guard`)

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.ESCALATE.CHAIN.001 | Multi-step admin path | critical |
| CTL.IAM.POLICY.ESCALATION.001 | Self-modification (single step) | critical |
| CTL.IAM.POLICY.PASSROLE.001 | Unrestricted PassRole | high |
