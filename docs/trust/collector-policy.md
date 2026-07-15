# Collector IAM Policy

Stave's collector requires a read-only IAM role. Every granted
action is Get, List, or Describe — no write, no modify, no delete.

## Audit the policy before granting access

### Human audit

[View the full policy document](collector-policy/collector-policy.json)

51 actions across 10 AWS services. Every action is listed. Read it.

| Service | Actions | What It Reads |
|---|---|---|
| CloudTrail | DescribeTrails, GetEventSelectors | Trail configs, data event settings |
| CloudWatch | DescribeAlarms | Alarm definitions |
| Config | DescribeConfigurationRecorders | Recorder settings |
| EC2 | DescribeInstances, DescribeVolumes, DescribeSecurityGroups, DescribeNetworkInterfaces, DescribeInstanceAttribute | Compute, storage, network configs |
| IAM | GetAccount*, GetPolicy*, GetRolePolicy, GetUserPolicy, GetGroupPolicy, List* (13 actions) | Policies, roles, users, groups |
| KMS | GetKeyPolicy, GetKeyRotationStatus, ListKeys | Key configs, rotation status |
| Organizations | DescribeOrganization, ListAccounts | Org structure |
| S3 | GetBucket* (6 actions), GetPublicAccessBlock, ListAllMyBuckets | Bucket configs, access settings |
| SES | GetIdentityDkimAttributes, ListIdentities, ListIdentityPolicies | Email identity configs |
| STS | GetCallerIdentity | Caller identity (own account ID) |

### Machine audit

[View the SMT proof](collector-policy/verify-readonly.smt2)

The proof verifies that every action in the policy has a read-only
verb prefix (Get, List, or Describe). Run it with Z3:

```bash
z3 docs/trust/collector-policy/verify-readonly.smt2
# Expected output: unsat (no non-read-only action found)
```

`unsat` means Z3 could not find any action that violates the
read-only property. If a write action were added to the policy,
Z3 would return `sat` — the proof would fail.

### Deploy the role

[CloudFormation template](collector-policy/collector-role.yaml)

```bash
aws cloudformation deploy \
  --template-file docs/trust/collector-policy/collector-role.yaml \
  --stack-name stave-collector \
  --parameter-overrides ExternalId=your-chosen-id \
  --capabilities CAPABILITY_NAMED_IAM
```

## What the collector does NOT do

- No write operations (no PutObject, no CreateBucket, no ModifyInstance)
- No credential creation (no CreateAccessKey, no CreateToken)
- No cross-account access (no AssumeRole to other accounts)
- No network operations (no CreateSecurityGroup, no AuthorizeIngress)
- No data access (no GetObject, no SelectObjectContent — reads bucket
  configs, never object contents)
- No delete operations of any kind

## Updating the policy

When the collector gains support for a new AWS service, the action
list grows. The update process:

1. Add the new actions to `collector-policy.json`
2. Add the matching assertions to `verify-readonly.smt2`
3. Run `z3 verify-readonly.smt2` — must return `unsat`
4. Update `collector-role.yaml` to match
5. Users redeploy the CloudFormation stack
