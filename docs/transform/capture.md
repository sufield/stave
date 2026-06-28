# Capturing snapshots for `stave transform`

The easiest way to capture is to run the bundled collector, which does everything
below automatically (read-only):

```bash
bash scripts/aws-snapshot.sh ./my-snapshot
# -> ./my-snapshot/raw/ (captured) and ./my-snapshot/observations/ (converted)
```

This page is the reference for **manual or selective** capture: the exact AWS CLI
call per resource type, the **output filename**, and the **join key** the
transform needs. All calls are read-only (SecurityAudit suffices). Put every file
in one directory and run `stave transform -i <dir> -o <obs> --account <id>`.

Placeholders: `<id>` = AWS account ID, `<bucket>` / `<role>` / `<user>` /
`<group>` / `<keyid>` = the resource name, `<arn>` = that resource's ARN.

## Conventions

- **Base list calls** — the filename doesn't matter; the transform detects the
  filter from the JSON's top-level key. Use the suggested name for clarity.
- **Filename-keyed enrichments** — the per-resource call returns no resource
  name, so the **filename supplies it**. Name the file exactly as shown
  (`s3-pab-<bucket>.json`, `user-inline-<user>.json`, …).
- **Annotated enrichments** — the call returns no usable id even in the name, so
  stamp the join key into the JSON with `jq`. Shown inline below.
- `--account <id>` is needed for filters whose raw input carries no ARN
  (password policy, user/group inline). Get it with
  `aws sts get-caller-identity --query Account --output text`.

## IAM

| Asset | Command | Output file | Key |
|---|---|---|---|
| roles (base) | `aws iam list-roles --output json` | `iam-roles.json` | top-level |
| role attached policies | `aws iam list-attached-role-policies --role-name <role> \| jq '. + {RoleArn:"<arn>"}'` | `iam-attached-<role>.json` | annotate `RoleArn` |
| role tags | `aws iam list-role-tags --role-name <role> \| jq '. + {RoleArn:"<arn>"}'` | `iam-tags-<role>.json` | annotate `RoleArn` |
| users (base) | `aws iam list-users --output json` | `iam-users.json` | top-level |
| user inline policies | `aws iam list-user-policies --user-name <user> --output json` | `user-inline-<user>.json` | filename |
| groups (base) | `aws iam list-groups --output json` | `iam-groups.json` | top-level |
| group inline policies | `aws iam list-group-policies --group-name <group> --output json` | `group-inline-<group>.json` | filename |
| inline policy doc | `aws iam get-user-policy --user-name <user> --policy-name <pol> --output json` (or `get-group-policy` / `get-role-policy`) | any name | self-describing |
| password policy | `aws iam get-account-password-policy --output json` | `iam-password-policy.json` | needs `--account` |

## S3

| Asset | Command | Output file | Key |
|---|---|---|---|
| buckets (base) | `aws s3api list-buckets --output json` | `s3-buckets.json` | top-level |
| public access block | `aws s3api get-public-access-block --bucket <bucket>` | `s3-pab-<bucket>.json` | filename |
| encryption | `aws s3api get-bucket-encryption --bucket <bucket>` | `s3-encryption-<bucket>.json` | filename |
| tags | `aws s3api get-bucket-tagging --bucket <bucket>` | `s3-tags-<bucket>.json` | filename |

## EC2

| Asset | Command | Output file | Key |
|---|---|---|---|
| EBS volumes | `aws ec2 describe-volumes --output json` | `ec2_volumes.json` | top-level |
| security groups | `aws ec2 describe-security-groups --output json` | `ec2_security_groups.json` | top-level |
| instances | `aws ec2 describe-instances --output json` | `ec2_instances.json` | top-level |

## Other services

| Asset | Command | Output file | Key |
|---|---|---|---|
| CloudTrail trails | `aws cloudtrail describe-trails --output json` | `cloudtrail_trails.json` | top-level |
| Config recorders | `aws configservice describe-configuration-recorders --output json` | `config_recorders.json` | top-level |
| OpenSearch domain | `aws opensearch describe-domain --domain-name <name> --output json` | `es_domain_<name>.json` | self-describing |
| CloudWatch alarms | `aws cloudwatch describe-alarms --output json` | `cloudwatch_alarms.json` | top-level |
| KMS keys (base) | `aws kms list-keys --output json` | `kms_keys.json` | top-level |
| KMS rotation | `aws kms get-key-rotation-status --key-id <keyid> --output json` | `kms-rotation-<keyid>.json` | self-describing |
| KMS key policy | `aws kms get-key-policy --key-id <keyid> --policy-name default \| jq '. + {KeyArn:"<arn>"}'` | `kms-policy-<keyid>.json` | annotate `KeyArn` |

## Calls collected for filters still in development

`aws-snapshot.sh` also captures these (their filters are documented in
`ctf/stave-transform/pending-items.md` but not built — `stave transform`
skips files it has no filter for): `aws iam get-account-authorization-details`,
`aws ec2 describe-network-interfaces`, `aws ec2 describe-instance-attribute
--attribute userData`, `aws cloudtrail get-event-selectors`, `aws ses
get-identity-dkim-attributes`, `aws ses list-identity-policies`.

Run `stave transform --coverage` for the live list of recognized input shapes.
