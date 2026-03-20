# S3 Access Controls

Controls in this directory detect cross-account and over-permissive access patterns in S3 bucket policies and ACLs.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.ACCESS.001 | No Unauthorized Cross-Account Access | Any external AWS account granted access via bucket policy |
| CTL.S3.ACCESS.002 | No Wildcard Action Policies | Policies using `s3:*` or `*` actions |
| CTL.S3.ACCESS.003 | No External Write Access | External accounts granted write/delete permissions |
| CTL.S3.AUTH.READ.001 | No Authenticated-Users Read Access | Read access granted to all authenticated AWS users |
| CTL.S3.AUTH.WRITE.001 | No Authenticated-Users Write Access | Write/delete access granted to all authenticated AWS users |

## MVP 1.0 Notes

- `CTL.S3.ACCESS.001` enforces `allowed_accounts` using extracted `external_account_ids` (12-digit IDs).
- Leave `allowed_accounts: []` to fail closed (any external account access is a violation).
