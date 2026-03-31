# HIPAA Evidence Sources

Contract for extractor authors: observation fields, AWS CLI commands,
and JSON schemas required by pending HIPAA controls.

Extractors produce `obs.v0.1` observation snapshots. Each evidence
source below defines a new observation field that an extractor must
populate for the corresponding control to evaluate.

---

## CloudTrail Object-Level Logging

**Requirement**: HIPAA.REQ.023
**HIPAA Section**: §164.312(b)
**Control**: `CTL.S3.AUDIT.OBJECTLEVEL.001`
**Observation field**: `properties.storage.logging.object_level_logging`

**AWS CLI**:
```bash
aws cloudtrail get-event-selectors --trail-name <trail-name>
aws cloudtrail describe-trails --trail-name-list <trail-name>
```

**Schema**:
```json
{
  "object_level_logging": {
    "enabled": true,
    "source": "cloudtrail",
    "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/my-trail",
    "selectors": [
      {
        "read_write_type": "All",
        "data_resources": [
          {
            "type": "AWS::S3::Object",
            "values": ["arn:aws:s3:::my-phi-bucket/"]
          }
        ]
      }
    ]
  }
}
```

**How to populate**:
1. List CloudTrail trails with `describe-trails`
2. For each trail, call `get-event-selectors`
3. Check if any data event selector covers `AWS::S3::Object` for the
   target bucket ARN (or uses the `arn:aws:s3` wildcard)
4. Set `enabled: true` if a matching selector exists with
   `read_write_type` of `All` or `ReadOnly` + `WriteOnly`
5. Set `enabled: false` if no trail covers the bucket

**Control predicate**: Fails when `enabled` is `false`.

---

## VPC Endpoint Policy

**Requirement**: HIPAA.REQ.024
**HIPAA Section**: §164.312(e)(1)
**Control**: `CTL.S3.NETWORK.POLICY.001`
**Observation field**: `properties.storage.network.vpc_endpoint_policy`

**AWS CLI**:
```bash
aws ec2 describe-vpc-endpoints \
  --filters Name=service-name,Values=com.amazonaws.<region>.s3
```

**Schema**:
```json
{
  "vpc_endpoint_policy": {
    "attached": true,
    "is_default_full_access": false,
    "vpc_endpoint_id": "vpce-0123456789abcdef0"
  }
}
```

**How to populate**:
1. Call `describe-vpc-endpoints` filtered to the S3 service
2. For each endpoint, check if `PolicyDocument` exists and is not the
   default full-access policy (`{"Statement":[{"Effect":"Allow",
   "Principal":"*","Action":"*","Resource":"*"}]}`)
3. Set `attached: true` if any VPC endpoint exists for S3 in the VPC
4. Set `is_default_full_access: true` if the policy document matches
   the default full-access pattern
5. If no endpoint exists, set `attached: false`

**Control predicate**: Fails when `attached` is `false` OR
`is_default_full_access` is `true`.

---

## IAM Least Privilege

**Requirement**: HIPAA.REQ.025
**HIPAA Section**: §164.312(a)(1), §164.502(b)
**Control**: Pending — will be `CTL.S3.ACCESS.LEASTPRIV.001`
**Observation field**: `properties.access.iam`

**AWS CLI**:
```bash
aws iam get-role-policy --role-name <role> --policy-name <policy>
aws iam list-attached-role-policies --role-name <role>
aws iam get-policy-version --policy-arn <arn> --version-id <v>
aws access-analyzer list-findings --analyzer-arn <arn>
```

**Schema**:
```json
{
  "iam": {
    "least_privilege_verified": false,
    "allowed_principals": [
      "arn:aws:iam::123456789012:role/my-app-role"
    ],
    "allowed_prefixes": [
      "data/input/*"
    ],
    "excessive_scope_findings": [
      {
        "principal": "arn:aws:iam::123456789012:role/admin-role",
        "actions": ["s3:*"],
        "resource": "*",
        "reason": "wildcard action and resource"
      }
    ]
  }
}
```

**How to populate**:
1. Identify all IAM roles/users with S3 access to the target bucket
2. For each principal, resolve effective permissions (inline + managed
   policies, permission boundaries)
3. Flag principals with `s3:*` action, `*` resource, or actions beyond
   what the workload requires
4. Optionally use IAM Access Analyzer findings for automated discovery
5. Set `least_privilege_verified: true` only when no excessive scope
   findings remain

**Control predicate**: Will fail when `least_privilege_verified` is
`false`.

---

## GuardDuty Malware Protection

**Requirement**: HIPAA.REQ.026
**HIPAA Section**: §164.308(a)(5)(ii)(B)
**Control**: Pending — will be `CTL.S3.MALWARE.001`
**Observation field**: `properties.malware_protection`

**AWS CLI**:
```bash
aws guardduty list-detectors
aws guardduty get-detector --detector-id <id>
aws guardduty get-malware-scan-settings --detector-id <id>
```

**Schema**:
```json
{
  "malware_protection": {
    "enabled": false,
    "engine": "guardduty",
    "scan_on_upload": false,
    "detector_id": "abc123def456"
  }
}
```

**How to populate**:
1. List GuardDuty detectors with `list-detectors`
2. For each detector, call `get-detector` and check
   `Features` for `S3_DATA_EVENTS` or `MALWARE_PROTECTION`
3. Call `get-malware-scan-settings` to check if S3 object scanning
   is enabled for the target bucket
4. Set `enabled: true` and `scan_on_upload: true` if the detector has
   malware protection active for S3 objects
5. Set `enabled: false` if no detector covers the bucket

**Control predicate**: Will fail when `enabled` is `false`.

---

## Field Placement in Observations

All fields above nest under `properties` in the `obs.v0.1` asset
object. Example observation snippet showing all 4 evidence sources:

```json
{
  "schema": "obs.v0.1",
  "source_type": "aws-s3-snapshot",
  "captured_at": "2026-03-29T00:00:00Z",
  "assets": [
    {
      "asset_id": "arn:aws:s3:::my-phi-bucket",
      "asset_type": "bucket",
      "properties": {
        "storage": {
          "kind": "bucket",
          "logging": {
            "object_level_logging": {
              "enabled": true,
              "source": "cloudtrail",
              "trail_arn": "arn:aws:cloudtrail:us-east-1:123456789012:trail/phi-trail"
            }
          },
          "network": {
            "vpc_endpoint_policy": {
              "attached": true,
              "is_default_full_access": false,
              "vpc_endpoint_id": "vpce-0123456789abcdef0"
            }
          },
          "access": {
            "has_vpc_condition": true,
            "has_ip_condition": false,
            "presigned_url_restricted": true
          }
        },
        "access": {
          "iam": {
            "least_privilege_verified": true,
            "allowed_principals": [],
            "allowed_prefixes": [],
            "excessive_scope_findings": []
          }
        },
        "malware_protection": {
          "enabled": true,
          "engine": "guardduty",
          "scan_on_upload": true,
          "detector_id": "abc123def456"
        }
      }
    }
  ]
}
```

## Missing Fields

Controls handle missing fields gracefully. When an observation does
not include a required field, the control evaluates as a finding with
a message indicating which observation data is needed. This means
extractors can be implemented incrementally — each new evidence source
unlocks the corresponding control without breaking existing ones.
