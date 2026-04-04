# S3 Public Access Controls

Controls in this directory detect active and latent public access exposure via bucket policies, ACLs, static website hosting, CloudFront CDN, and prefix-level permissions.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.PUBLIC.001 | No Public S3 Bucket Read | Anonymous read via policy or ACL |
| CTL.S3.PUBLIC.002 | No Public S3 Buckets With Sensitive Data | Public read/list on buckets tagged PHI, PII, or confidential |
| CTL.S3.PUBLIC.003 | No Public Write Access | Public write or delete via policy or ACL |
| CTL.S3.PUBLIC.004 | No Public Read via ACL | ACL grants read to AllUsers or AuthenticatedUsers |
| CTL.S3.PUBLIC.005 | No Latent Public Read Exposure | Public read masked only by PAB (removing PAB would expose the bucket) |
| CTL.S3.PUBLIC.006 | No Latent Public Bucket Listing | Public list masked only by PAB |
| CTL.S3.PUBLIC.007 | No Public Read via Policy | Bucket policy grants read to Principal `*` |
| CTL.S3.PUBLIC.008 | No Public List via Policy | Bucket policy grants listing to Principal `*` |
| CTL.S3.PUBLIC.LIST.001 | No Public S3 Bucket Listing | Anonymous object listing enabled |
| CTL.S3.PUBLIC.LIST.002 | Anonymous S3 Listing Must Be Explicitly Intended | Public listing without `public_list_intended=true` tag |
| CTL.S3.PUBLIC.PREFIX.001 | Protected Prefixes Must Not Be Publicly Readable | Protected prefixes (invoices/, secrets/, etc.) are publicly readable |
| CTL.S3.ACL.WRITE.001 | No Public Write via ACL | ACL grants write to AllUsers or AuthenticatedUsers |
| CTL.S3.CDN.EXPOSURE.001 | Private Bucket Must Not Be Publicly Exposed Via CloudFront | PAB-enabled bucket serves objects publicly via CloudFront |
| CTL.S3.CDN.OAC.001 | CloudFront Access Must Use OAC Not Legacy OAI | CloudFront uses legacy OAI instead of OAC |
| CTL.S3.WEBSITE.PUBLIC.001 | No Public Website Hosting with Public Read | Static website hosting enabled with public read access |

## Exposure Layers

These controls address distinct exposure vectors, each requiring separate detection:

- **Direct public access (PUBLIC.001, .003, .007, .008):** Active public read, write, or list exposure via policy or ACL. These fire when data is currently accessible to the internet.
- **ACL-specific (PUBLIC.004, ACL.WRITE.001):** ACL grants to AllUsers or AuthenticatedUsers, tracked separately from policy-based access because ACLs and policies are independent mechanisms.
- **Sensitive data (PUBLIC.002):** Compound check -- public access AND sensitive data classification tag. Fires only when both conditions hold.
- **Latent exposure (PUBLIC.005, .006):** Public access mechanisms masked by PAB. Not currently exposed, but one config change away. Detects defense-in-depth failures.
- **Listing controls (PUBLIC.LIST.001, .002):** Object listing enables targeted exfiltration even when individual object URLs are not known. LIST.002 allows intentional listing via an explicit tag.
- **Prefix exposure (PUBLIC.PREFIX.001):** Parameterized control with `protected_prefixes` and `allowed_public_prefixes` lists. Customizable per bucket layout.
- **CDN exposure (CDN.EXPOSURE.001, CDN.OAC.001):** CloudFront can serve objects from PAB-protected buckets via service principal grants. CDN.EXPOSURE.001 detects this false sense of security. CDN.OAC.001 flags legacy OAI usage.
- **Website hosting (WEBSITE.PUBLIC.001):** Static website hosting with public read serves content directly via the S3 website endpoint.

## Compliance Mapping

| Control | HIPAA | CIS AWS 1.4.0 | PCI DSS 3.2.1 | SOC 2 |
|---------|-------|---------------|---------------|-------|
| PUBLIC.001 | 164.312(a)(1) | 2.1.5 | 1.2.1 | CC6.1 |
| CDN.EXPOSURE.001 | 164.312(a)(1) | -- | -- | -- |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.access.public_read` | bool | PUBLIC.001, .002, WEBSITE.PUBLIC.001, REPO.ARTIFACT.001 |
| `properties.storage.access.public_write` | bool | PUBLIC.003 |
| `properties.storage.access.public_list` | bool | PUBLIC.002, LIST.001, LIST.002 |
| `properties.storage.access.read_via_resource` | bool | PUBLIC.004 |
| `properties.storage.access.read_via_identity` | bool | PUBLIC.007 |
| `properties.storage.access.list_via_identity` | bool | PUBLIC.008 |
| `properties.storage.access.write_via_resource` | bool | ACL.WRITE.001 |
| `properties.storage.access.latent_public_read` | bool | PUBLIC.005 |
| `properties.storage.access.latent_public_list` | bool | PUBLIC.006 |
| `properties.storage.tags.data-classification` | string | PUBLIC.002 |
| `properties.storage.tags.public_list_intended` | string | LIST.002 |
| `properties.storage.kind` | string | PUBLIC.006, LIST.002, CDN.EXPOSURE.001, CDN.OAC.001 |
| `properties.storage.controls.public_access_fully_blocked` | bool | CDN.EXPOSURE.001 |
| `properties.storage.cdn_access.bucket_policy_grants_cloudfront` | bool | CDN.EXPOSURE.001 |
| `properties.storage.cdn_access.cloudfront_oai.enabled` | bool | CDN.OAC.001 |
| `properties.storage.website.enabled` | bool | WEBSITE.PUBLIC.001 |

PUBLIC.005 uses a predicate alias (`s3.latent_public_read`). LIST.002 uses a compound predicate: public_list must be true AND the `public_list_intended` tag must be missing or not `"true"`.
