# Building a Privilege Escalation Extractor

This guide describes how to build an extractor that detects
multi-step privilege escalation chains.

## Overview

The escalation extractor analyzes known IAM escalation patterns
and traces whether a low-privileged principal can chain permissions
to reach administrative access.

## Known escalation vectors

| Vector | Steps | How it works |
|---|---|---|
| PassRoleToLambda | `iam:PassRole` → `lambda:CreateFunction` → `lambda:InvokeFunction` | Pass an admin role to a new Lambda, invoke it |
| CreatePolicyVersion | `iam:CreatePolicyVersion` on self | Create a new policy version granting full admin |
| AttachRolePolicy | `iam:AttachRolePolicy` on self | Attach AdministratorAccess to own role |
| CreateAccessKey | `iam:CreateAccessKey` on admin user | Generate keys for an existing admin |
| AssumeRoleChain | `sts:AssumeRole` → `sts:AssumeRole` | Chain through roles to reach admin |
| UpdateLoginProfile | `iam:UpdateLoginProfile` on admin | Reset an admin user's password |
| EC2RunWithRole | `ec2:RunInstances` + `iam:PassRole` | Launch an instance with an admin role |
| GlueDevEndpoint | `glue:CreateDevEndpoint` + `iam:PassRole` | Create a Glue endpoint with an admin role |
| SageMakerNotebook | `sagemaker:CreateNotebookInstance` + `iam:PassRole` | Notebook with admin role |
| CloudFormationRole | `cloudformation:CreateStack` + `iam:PassRole` | Stack with admin service role |

## Algorithm

### Step 1: Build permission graph

For each IAM principal, enumerate all effective permissions:

```bash
for USER in $(aws iam list-users --query 'Users[].UserName' --output text); do
  # Attached policies
  aws iam list-attached-user-policies --user-name $USER
  # Inline policies
  aws iam list-user-policies --user-name $USER
  # Group memberships → group policies
  for GROUP in $(aws iam list-groups-for-user --user-name $USER \
      --query 'Groups[].GroupName' --output text); do
    aws iam list-attached-group-policies --group-name $GROUP
  done
done
```

### Step 2: Match escalation patterns

For each principal, check if their effective permissions match any
known escalation vector:

```python
VECTORS = {
    "PassRoleToLambda": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
    "CreatePolicyVersion": ["iam:CreatePolicyVersion"],
    "AttachRolePolicy": ["iam:AttachRolePolicy"],
    # ...
}

for principal in principals:
    perms = get_effective_permissions(principal)
    for name, required in VECTORS.items():
        if all(p in perms for p in required):
            # Check if target role exists with admin access
            if can_reach_admin(principal, name):
                flag_escalation(principal, name, required)
```

### Step 3: Output obs.v0.1 JSON

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

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.ESCALATE.CHAIN.001 | Multi-step admin path | critical |
| CTL.IAM.POLICY.ESCALATION.001 | Self-modification (single step) | critical |
| CTL.IAM.POLICY.PASSROLE.001 | Unrestricted PassRole | high |
