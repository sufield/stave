# S3 ACL Privilege Escalation Controls

Controls in this directory detect ACL-based privilege escalation and reconnaissance patterns that enable attackers to modify bucket permissions or enumerate access grants.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.ACL.ESCALATION.001 | No Public ACL Modification | WRITE_ACP granted to AllUsers or AuthenticatedUsers via ACL or policy (s3:PutBucketAcl, s3:PutObjectAcl) |
| CTL.S3.ACL.RECON.001 | No Public ACL Readability | READ_ACP granted to AllUsers via ACL or policy (s3:GetBucketAcl, s3:GetObjectAcl) |
| CTL.S3.ACL.FULLCONTROL.001 | No FULL_CONTROL ACL Grants to Public | Explicit FULL_CONTROL granted to AllUsers or AuthenticatedUsers |

## Attack Patterns

These controls address three related S3 ACL attack patterns documented in bug bounty disclosures:

1. **WRITE_ACP (ACL modification):** An attacker calls `put-bucket-acl` to grant themselves `FULL_CONTROL`, then reads or modifies all objects. This is privilege escalation -- the data isn't directly exposed, but the attacker can change who has access.

2. **READ_ACP (ACL readability):** An attacker calls `get-bucket-acl` to enumerate which principals have access, discovering escalation paths. Information disclosure that enables targeted attacks.

3. **FULL_CONTROL grants:** The worst-case ACL misconfiguration -- the grantee can read, write, and delete objects and modify the ACL itself. Stave distinguishes this from individual READ+WRITE grants because FULL_CONTROL includes ACL modification capability.

## Detection Sources

Each control fires based on fields set by both the ACL analyzer and the policy analyzer:

- **ACL grants:** `READ_ACP`, `WRITE_ACP`, and `FULL_CONTROL` permissions to `AllUsers` or `AuthenticatedUsers` groups
- **Bucket policy statements:** Actions `s3:PutBucketAcl`, `s3:PutObjectAcl`, `s3:GetBucketAcl`, `s3:GetObjectAcl` granted to `*` or authenticated-users principals
- **Wildcard actions:** `s3:*` and `*` trigger all applicable ACL flags

All fields are gated by Public Access Block -- when PAB is fully enabled, these flags stay false.
