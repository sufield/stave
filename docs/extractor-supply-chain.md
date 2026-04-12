# Building a Supply Chain Ingress Extractor

This guide describes how to build an extractor that analyzes OIDC
federation trust policies for CI/CD ingress risks.

## Overview

The extractor inspects IAM role trust policies for OIDC identity
provider conditions. It determines whether the subject claim is
scoped, whether wildcards are used, and whether the assumed role
has admin-level permissions.

## Algorithm

### Step 1: Find OIDC-trusted roles

```bash
# List all IAM roles and check trust policies for OIDC providers
for ROLE in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  TRUST=$(aws iam get-role --role-name "$ROLE" \
    --query 'Role.AssumeRolePolicyDocument' --output json)

  # Check for OIDC provider principals
  OIDC_PROVIDERS=$(echo "$TRUST" | jq -r '
    [.Statement[] | select(.Effect == "Allow") |
     .Principal.Federated // empty |
     select(test("oidc|token.actions|gitlab|bitbucket"))] | unique[]')

  if [ -n "$OIDC_PROVIDERS" ]; then
    echo "OIDC role: $ROLE (providers: $OIDC_PROVIDERS)"
  fi
done
```

### Step 2: Analyze subject claim conditions

```bash
check_oidc_trust() {
  local TRUST="$1"

  # Extract the sub condition
  SUB_CONDITION=$(echo "$TRUST" | jq -r '
    .Statement[] | select(.Effect == "Allow") |
    .Condition // {} |
    (.StringEquals // {}) + (.StringLike // {}) |
    to_entries[] |
    select(.key | test(":sub$")) | .value')

  if [ -z "$SUB_CONDITION" ]; then
    echo "sub_claim_scoped=false"
    return
  fi

  # Check for wildcards
  if echo "$SUB_CONDITION" | grep -q '^\*$\|^\*:'; then
    echo "has_wildcard_sub=true"
    echo "sub_claim_scoped=false"
  else
    echo "has_wildcard_sub=false"
    echo "sub_claim_scoped=true"
  fi
}
```

### Step 3: Check role permissions

```bash
check_admin_permissions() {
  local ROLE_NAME="$1"

  # Check for AdministratorAccess policy
  ADMIN=$(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
    --query 'AttachedPolicies[?PolicyArn==`arn:aws:iam::aws:policy/AdministratorAccess`]' \
    --output text)
  if [ -n "$ADMIN" ]; then
    echo "has_admin_permissions=true"
    return
  fi

  # Check for broad wildcard actions
  for ARN in $(aws iam list-attached-role-policies --role-name "$ROLE_NAME" \
      --query 'AttachedPolicies[].PolicyArn' --output text); do
    VERSION=$(aws iam get-policy --policy-arn "$ARN" \
      --query 'Policy.DefaultVersionId' --output text)
    WILDCARD=$(aws iam get-policy-version --policy-arn "$ARN" \
      --version-id "$VERSION" \
      --query 'PolicyVersion.Document.Statement[?Effect==`Allow`]' --output json |
      jq '[.[] | select(.Action == "*" or .Action == ["*"])] | length')
    if [ "$WILDCARD" -gt 0 ]; then
      echo "has_admin_permissions=true"
      return
    fi
  done

  echo "has_admin_permissions=false"
}
```

### Step 4: Identify the OIDC provider

| Provider URL | `provider` value |
|---|---|
| `token.actions.githubusercontent.com` | `github` |
| `gitlab.com` | `gitlab` |
| `bitbucket.org` | `bitbucket` |
| `accounts.google.com` | `google` |

### Step 5: Output obs.v0.1 JSON

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-04-12T00:00:00Z",
  "assets": [
    {
      "id": "arn:aws:iam::123456789:role/github-deploy",
      "type": "aws_iam_role",
      "vendor": "aws",
      "properties": {
        "identity": {
          "kind": "role",
          "trust": {
            "oidc": {
              "has_oidc_trust": true,
              "provider": "github",
              "sub_claim_scoped": false,
              "sub_claim_value": "*",
              "has_wildcard_sub": true,
              "has_admin_permissions": true
            }
          }
        }
      }
    }
  ]
}
```

## Required AWS permissions

```json
{
  "Action": [
    "iam:ListRoles",
    "iam:GetRole",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicyVersion",
    "iam:ListOpenIDConnectProviders",
    "iam:GetOpenIDConnectProvider"
  ]
}
```

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.TRUST.OIDC.001 | Unscoped subject claim | critical |
| CTL.IAM.TRUST.OIDC.002 | Wildcard subject claim | critical |
| CTL.IAM.TRUST.OIDC.003 | Admin permissions on OIDC role | high |
