# S3 Assessment Workflow

This is the supported S3 MVP workflow for the current CLI surface.

## Golden Path

```text
extract (external) -> validate -> apply -> verify
```

## 1) Extract observations from an offline AWS snapshot

Use an extractor (any language) to produce `obs.v0.1` JSON from your AWS snapshot directory. See [Building an Extractor](extractor-prompt.md) for a jumpstart template, or use an existing extractor such as `stave-extractor`.

Input:
- Snapshot directory with AWS CLI exports (`list-buckets.json`, `get-bucket-*` files)

Output:
- `observations.json` (`obs.v0.1`)

## 2) Evaluate observations against the S3 control pack

```bash
stave apply --profile aws-s3 --input observations.json --include-all --now 2026-01-15T00:00:00Z > evaluation.json
```

Input:
- `observations.json`
- Built-in S3 controls under `controls/s3`

Output:
- `evaluation.json` (`out.v0.1`)
- Exit code `3` when violations are found

## 3) Verify remediation (before vs after)

```bash
stave verify \
  --before ./obs-before \
  --after ./obs-after \
  --controls ./controls/s3 \
  --now 2026-01-15T00:00:00Z \
  --out ./output
```

Input:
- Before/after observations directories
- Controls directory

Output:
- stdout JSON verification summary
- `output/verification.json` when `--out` is set

## What the S3 pack covers

The `aws-s3` profile evaluates 64 controls across these categories:

| Category | Controls | What they detect |
|----------|----------|-----------------|
| Public exposure | PUBLIC.001–008, PUBLIC.LIST, PUBLIC.PREFIX | Public read, list, write via policy or ACL |
| ACL misconfiguration | ACL.ESCALATION, ACL.FULLCONTROL, ACL.RECON, ACL.WRITE, ACL.OBJECT | Bucket and object-level ACL grants |
| Access control | ACCESS.001–003, AUTH.READ, AUTH.WRITE, PRESIGNED, ACCESS.GRANTS | Cross-account, wildcard actions, presigned URLs |
| Encryption | ENCRYPT.001–004 | At-rest, in-transit, KMS for PHI/sensitive data |
| Block Public Access | CONTROLS.001, ACCOUNT.PAB.001 | Bucket-level and account-level PAB |
| Object Ownership | OWNERSHIP.001 | BucketOwnerEnforced to disable ACLs |
| Logging & audit | LOG.001, AUDIT.OBJECTLEVEL.001 | Server access logging, CloudTrail object-level |
| Sensitive data discovery | DETECT.MACIE.001–002 | Macie enablement, automated discovery |
| Versioning & integrity | VERSION.001–002, MFADELETE.001, LOCK.001–003 | Versioning, MFA delete, Object Lock |
| Replication | REPLICATION.001–003 | Replication enabled, cross-region, destination encrypted |
| Lifecycle & retention | LIFECYCLE.001–002 | Lifecycle rules, PHI minimum retention |
| Visibility | INVENTORY.001 | S3 Inventory for bucket content auditing |
| Governance | GOVERNANCE.001, REGION.001 | Data classification tags, approved regions |
| Network | NETWORK.001, NETWORK.POLICY.001, NETWORK.VPC.001, MRAP.* | VPC endpoints, MRAP policies |
| CDN & takeover | CDN.OAC.001, CDN.EXPOSURE.001, BUCKET.TAKEOVER.001, DANGLING.ORIGIN.001 | CloudFront OAC, dangling origins |
| Write scope | WRITE.SCOPE.001, WRITE.CONTENT.001 | Signed upload key/content-type binding |
| Tenant isolation | TENANT.ISOLATION.001 | Prefix-scoped multi-tenant access |

## Notes

- Offline by design: reads local files only.
- Deterministic in CI: always set `--now`.
- For troubleshooting unexpected results, run `stave diagnose`.
