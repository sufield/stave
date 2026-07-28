# DNS Dangling Record Controls

Controls in this directory detect DNS records that point to cloud resources
that no longer exist or are not owned by the organization. Dangling DNS
records enable subdomain takeover — an attacker claims the target resource
and serves content under a trusted domain.

## Tiered Coverage

The three controls form a generic-to-specific hierarchy. The generic control
catches everything; the specialized controls add context-specific severity
and remediation for high-impact resource types.

| ID | Scope | Fires on |
|----|-------|----------|
| CTL.DNS.DANGLING.001 | **Any** DNS record → any unclaimed resource | Released Elastic IPs, deleted instances, deprovisioned load balancers, unclaimed buckets — any target |
| CTL.DNS.DANGLING.002 | DNS → cloud storage (S3, GCS, Azure Blob) | Bucket names are globally unique — a deleted bucket can be claimed by any account |
| CTL.DNS.DANGLING.003 | DNS → software distribution endpoints | Package repos, binary downloads, update servers — supply chain risk |

For a dangling A record to a released Elastic IP (e.g., Shopify `turn.shopify.com`),
only **CTL.DNS.DANGLING.001** fires.

For a dangling CNAME to a deleted S3 bucket (e.g., Brave apt repo), all three
layers may fire depending on the resource type:
- CTL.DNS.DANGLING.001 (generic — any dangling record)
- CTL.DNS.DANGLING.002 (cloud storage — bucket name is claimable)
- CTL.DNS.DANGLING.003 (if the bucket served software distribution)

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.dns.record_type` | string | Context (A, CNAME, ALIAS) |
| `properties.dns.target_exists` | bool | 001, 002, 003 |
| `properties.dns.target_owned` | bool | 001, 002, 003 |
| `properties.dns.target_type` | string | 002 (gates on `cloud_storage`) |
| `properties.dns.blast_radius` | string | 003 (gates on `software_distribution`) |

## Cross-Reference: S3 Takeover Controls

The `s3/takeover/` directory has complementary controls that evaluate the
resource side (bucket references) rather than the DNS side:

| ID | What it checks | Relationship |
|----|---------------|-------------|
| CTL.S3.BUCKET.TAKEOVER.001 | S3 bucket reference where `bucket_exists: false` or `bucket_owned: false` | Resource-side equivalent of DNS.DANGLING.002 |
| CTL.S3.DANGLING.ORIGIN.001 | CloudFront distribution with dangling S3 origin | CDN-specific — detects the distribution config, not the DNS record |

Both perspectives (DNS record → missing target, and resource reference → missing
bucket) should be evaluated. A dangling CNAME that passes DNS resolution but
points to a non-existent bucket is caught by the DNS controls. A CloudFront
distribution with a dangling S3 origin is caught by the S3 controls even if
no DNS record points to the distribution directly.

## Attack Pattern

1. Organization provisions infrastructure (EC2 instance, S3 bucket, ELB)
2. DNS record is created pointing to the resource (A, CNAME, or ALIAS)
3. Infrastructure is decommissioned but DNS record persists
4. Attacker discovers the dangling record via DNS enumeration
5. Attacker claims the resource (registers the IP, creates the bucket name)
6. Traffic to the domain now reaches the attacker's resource

The fix is always the same: delete the DNS record when you decommission the
infrastructure. Better: manage both in the same IaC stack so they are created
and destroyed together.
