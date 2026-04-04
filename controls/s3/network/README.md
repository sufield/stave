# S3 Network Controls

Controls in this directory enforce network-level access restrictions on S3 buckets, including VPC endpoint policies, IP conditions, and Multi-Region Access Point (MRAP) configurations.

| ID | Name | What it checks |
|----|------|----------------|
| CTL.S3.NETWORK.001 | Public-Principal Policies Must Have Network Conditions | Wildcard-principal policy has no network-scoping conditions (SourceIp, SourceVpce, SourceVpc, PrincipalOrgID) |
| CTL.S3.NETWORK.VPC.001 | VPC Endpoint or IP Condition Required | Bucket has no VPC endpoint or IP address condition restricting access |
| CTL.S3.NETWORK.POLICY.001 | VPC Endpoint Policy Must Restrict Access | VPC endpoint uses the default full-access policy (Allow * on *) or has no policy attached |
| CTL.S3.MRAP.PAB.001 | Multi-Region Access Point Must Have Block Public Access Enabled | MRAP has PAB disabled (independent of bucket PAB) |
| CTL.S3.MRAP.POLICY.001 | Multi-Region Access Point Policy Must Not Be Public | MRAP resource policy grants public access |

## Why Five Controls

Network restrictions operate at multiple layers, each independently bypassable:

1. **Effective network scope (NETWORK.001):** A bucket policy with `Principal: *` and no network conditions is reachable from anywhere on the internet. This control checks the effective scope after analyzing all policy conditions.

2. **VPC/IP conditions (NETWORK.VPC.001):** Even without wildcard principals, PHI workloads require explicit VPC endpoint or IP restrictions for transmission security.

3. **Endpoint policy (NETWORK.POLICY.001):** A VPC endpoint with the default policy (Allow * on *) allows any VPC principal to reach any S3 bucket in any account. The endpoint policy must restrict both actions and bucket ARNs. Uses an `any` predicate -- fires if the policy is missing OR is the default full-access policy.

4. **MRAP PAB (MRAP.PAB.001):** MRAPs have their own PAB settings independent of bucket PAB. A bucket can have PAB enabled while the MRAP bypasses it entirely.

5. **MRAP policy (MRAP.POLICY.001):** MRAPs can have their own resource policy, evaluated independently of the bucket policy. A public MRAP policy creates a separate public access path.

## Compliance Mapping

| Control | HIPAA |
|---------|-------|
| NETWORK.VPC.001 | 164.312(e)(1) |
| NETWORK.POLICY.001 | 164.312(e)(1) |
| MRAP.PAB.001 | 164.312(a)(1) |

## Detection Fields

| Field path | Type | Used by |
|------------|------|---------|
| `properties.storage.access.effective_network_scope` | string | NETWORK.001 |
| `properties.storage.kind` | string | NETWORK.VPC.001, MRAP.PAB.001, MRAP.POLICY.001 |
| `properties.storage.access.has_vpc_condition` | bool | NETWORK.VPC.001 |
| `properties.storage.access.has_ip_condition` | bool | NETWORK.VPC.001 |
| `properties.storage.network.vpc_endpoint_policy.attached` | bool | NETWORK.POLICY.001 |
| `properties.storage.network.vpc_endpoint_policy.is_default_full_access` | bool | NETWORK.POLICY.001 |
| `properties.storage.mrap_public_access_blocked` | bool | MRAP.PAB.001 |
| `properties.storage.mrap_policy_is_public` | bool | MRAP.POLICY.001 |

NETWORK.VPC.001 gates on `kind == "bucket"` and requires both VPC and IP conditions to be false (compound `all`). NETWORK.POLICY.001 fires on either missing or default-full-access (compound `any`).
