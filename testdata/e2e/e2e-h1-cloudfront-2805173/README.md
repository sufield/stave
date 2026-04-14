# E2E Test: HackerOne Report 2805173
## CloudFront Extensions Console — Lambda Privilege Escalation

**Source:** https://hackerone.com/reports/2805173
**Disclosed:** 2024-11-19
**Severity:** Medium (HackerOne), Critical (Stave — admin-equivalent IAM)
**Status:** Resolved

## What This Tests

The cloudFrontExtensionsConsole AWS application created Lambda functions
with execution roles carrying IAM escalation primitives and admin-equivalent
permissions. Six functions across two shared roles were affected.

## Controls That Fire

| Control | Finding | Resource |
|---|---|---|
| CTL.IAM.NEP.ESCALATION.001 | iam:AttachRolePolicy + iam:CreatePolicy + iam:CreateRole on Resource:* | CloudFrontConfigVersionCo role |
| CTL.IAM.NEP.ESCALATION.001 | iam:* on Resource:* — full escalation capability | RepoConstructExtDeployerR role |
| CTL.IAM.NEP.ADMIN.001 | Admin-equivalent effective permissions | RepoConstructExtDeployerR role |
| CTL.LAMBDA.ROLE.LEASTPRIV.001 | Execution role exceeds least privilege | All 6 functions |

## Stave Detection

Stave detects this class of misconfiguration through:
1. NEP resolution — resolving all policy layers to compute effective permissions
2. Escalation primitive detection — checking for IAM actions that enable privilege escalation
3. PrivilegeLevel classification — classifying iam:* on Resource:* as admin-equivalent
4. Lambda least privilege — flagging execution roles with excessive permissions

## Remediation

1. Create separate roles per function with only the specific permissions required
2. Scope all IAM resource grants to specific ARNs, not Resource:*
3. Remove IAM management permissions entirely if not required for normal function
4. Add a permission boundary to restrict the maximum permissions any role can hold
