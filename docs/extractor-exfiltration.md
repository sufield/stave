# Building an Exfiltration Extractor

This guide describes how to build an extractor that detects data
exfiltration paths and produces `obs.v0.1` JSON for evaluation by
Stave's `CTL.EXPOSURE.EXFIL.*` controls.

## Overview

The exfiltration extractor traces reverse reachability: starting at
sensitive resources and finding compute instances that can both read
the data and reach the internet.

## Algorithm

### Step 1: Identify sensitive resources

Enumerate all resources with sensitive data classification tags:

```bash
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=data-classification,Values=phi,pii,confidential
```

### Step 2: Find compute with read access

For each sensitive resource, identify compute instances that can
read it:

- **S3 buckets:** Find IAM roles with `s3:GetObject` grants, then
  find EC2/Lambda/ECS using those roles
- **DynamoDB:** Find roles with `dynamodb:GetItem` / `dynamodb:Query`
- **RDS:** Find instances in the same VPC with security group access

### Step 3: Check internet egress

For each compute instance, check if its subnet has an outbound
internet path:

```bash
# Get the instance's subnet
SUBNET=$(aws ec2 describe-instances --instance-ids $INSTANCE \
  --query 'Reservations[0].Instances[0].SubnetId' --output text)

# Get the route table
RT=$(aws ec2 describe-route-tables \
  --filters "Name=association.subnet-id,Values=$SUBNET" \
  --query 'RouteTables[0].RouteTableId' --output text)

# Check for internet gateway or NAT gateway routes
aws ec2 describe-route-tables --route-table-ids $RT \
  --query 'RouteTables[0].Routes[?GatewayId!=`local`]'
```

Egress types:
- `internet_gateway` — direct internet access via IGW
- `nat_gateway` — outbound via NAT (can still exfiltrate)
- `vpc_peering` — to a VPC with internet access

### Step 4: Check wildcard write permissions

```bash
# For each role attached to the instance, check for wildcard writes
POLICIES=$(aws iam list-attached-role-policies --role-name $ROLE \
  --query 'AttachedPolicies[].PolicyArn' --output text)

for ARN in $POLICIES; do
  VERSION=$(aws iam get-policy --policy-arn $ARN \
    --query 'Policy.DefaultVersionId' --output text)
  aws iam get-policy-version --policy-arn $ARN \
    --version-id $VERSION \
    --query 'PolicyVersion.Document.Statement[?Effect==`Allow`]' |
    jq '[.[] | select(.Action | tostring | test("s3:Put|s3:\\*"))] |
        [.[] | select(.Resource == "*" or .Resource == ["*"])] | length'
done
```

### Step 5: Output obs.v0.1 JSON

```json
{
  "schema_version": "obs.v0.1",
  "captured_at": "2026-04-12T00:00:00Z",
  "assets": [
    {
      "id": "arn:aws:s3:::phi-records",
      "type": "aws_s3_bucket",
      "vendor": "aws",
      "properties": {
        "reachability": {
          "kind": "exfiltration_path",
          "exfiltration": {
            "path_to_internet_exists": true,
            "vector": "compute_with_igw_plus_wildcard_write",
            "egress_type": "internet_gateway",
            "compute_id": "arn:aws:ec2:us-east-1:123456789:instance/i-abc123",
            "has_wildcard_write": true,
            "sensitive_data_readable": true,
            "target_data_classification": "phi"
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
    "ec2:DescribeInstances",
    "ec2:DescribeRouteTables",
    "ec2:DescribeSubnets",
    "ec2:DescribeNatGateways",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeSecurityGroups",
    "iam:ListAttachedRolePolicies",
    "iam:GetPolicyVersion",
    "lambda:ListFunctions",
    "lambda:GetFunction",
    "tag:GetResources",
    "s3:GetBucketPolicy"
  ]
}
```

## Controls that evaluate this output

| Control | What it checks | Severity |
|---|---|---|
| CTL.EXPOSURE.EXFIL.001 | Sensitive data + internet egress | critical |
| CTL.EXPOSURE.EXFIL.002 | Wildcard write + internet egress | high |
| CTL.EXPOSURE.EXFIL.INCOMPLETE.001 | Missing egress data | low |
