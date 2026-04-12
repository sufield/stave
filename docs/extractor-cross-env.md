# Building a Cross-Environment Extractor

This guide describes how to build an extractor that detects
transitive trust paths from non-production to production
environments.

## Overview

The cross-environment extractor traces `sts:AssumeRole` chains and
resource policy grants across AWS accounts to find paths from
non-production principals to production resources.

## Algorithm

### Step 1: Classify accounts by environment

Map each AWS account to its environment classification:

```json
{
  "111111111111": "production",
  "222222222222": "staging",
  "333333333333": "development"
}
```

Source from AWS Organizations tags, SSM parameters, or a
configuration file.

### Step 2: Enumerate cross-account trust

For each role in every account, check its trust policy:

```bash
for ROLE in $(aws iam list-roles --query 'Roles[].RoleName' --output text); do
  TRUST=$(aws iam get-role --role-name $ROLE \
    --query 'Role.AssumeRolePolicyDocument' --output json)

  # Extract trusted principals from other accounts
  TRUSTED_ACCOUNTS=$(echo "$TRUST" | jq -r '
    .Statement[] | select(.Effect == "Allow") |
    .Principal.AWS | if type == "array" then .[] else . end |
    capture("arn:aws:iam::(?<acct>[0-9]{12}):") | .acct')

  for ACCT in $TRUSTED_ACCOUNTS; do
    echo "$ROLE trusted by $ACCT"
  done
done
```

### Step 3: BFS from non-prod accounts

Starting from each non-prod account, traverse role assumption
chains to find any path that reaches a production resource.

### Step 4: Output obs.v0.1 JSON

Annotate each production role that is reachable from a lower
environment:

```json
{
  "id": "arn:aws:iam::111111111111:role/devops-deploy",
  "type": "aws_iam_role",
  "vendor": "aws",
  "properties": {
    "identity": {
      "kind": "role",
      "role": {
        "cross_env": {
          "reachable_from_lower_env": true,
          "source_env": "development",
          "path_hop_count": 2,
          "via_bridge_role": "arn:aws:iam::999999999999:role/shared-deploy"
        }
      }
    }
  }
}
```

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.IAM.CROSS.ENV.001 | Direct cross-env access (boolean) | critical |
| CTL.IAM.CROSS.ENV.PATH.001 | Transitive trust path | critical |
