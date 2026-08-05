# Control Reference — LIGHTSAIL

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.LIGHTSAIL.ACCESS.KEY.001

**Lightsail Bucket Has Active Access Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI1; soc2: CC6.1;

A Lightsail bucket has active access keys created via lightsail:CreateBucketAccessKey — outside the IAM credential lifecycle. Not in credential reports, not subject to rotation.

**Remediation:** Delete with aws lightsail delete-bucket-access-key; migrate to IAM.

---

### CTL.LIGHTSAIL.BLUEPRINT.RETIRED.001

**Lightsail Instance Must Not Use Retired Blueprint**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Lightsail instances must not run retired OS or application blueprints. AWS retires blueprints when the underlying OS reaches end-of-life (Ubuntu 18.04, CentOS 7, Amazon Linux 1) or when the application version is no longer maintained. Instances on retired blueprints no longer receive security patches through the blueprint update channel. Unlike EC2, Lightsail instances are often managed by operators who do not run their own patch pipelines — the blueprint is their sole patch source.

**Remediation:** Create a new instance with a supported blueprint and migrate your application. Export data from the retired instance, launch a replacement with a current blueprint (e.g. ubuntu_22_04), and restore. Use aws lightsail create-instances with the updated --blueprint-id.

---

### CTL.LIGHTSAIL.DB.PUBLIC.001

**Lightsail Databases Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail managed databases must not be publicly accessible.

**Remediation:** Disable public mode on the database.

---

### CTL.LIGHTSAIL.INSTANCE.IPV6.001

**Lightsail Instance Has IPv6 Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.1;

Lightsail instance has dual-stack (IPv6) networking enabled. When IPv6 is active the instance gets a publicly routable /128 address that bypasses the Lightsail firewall's IPv4-only rule set in default configurations. Unless firewall rules explicitly cover IPv6 CIDRs, the instance is reachable on all ports over IPv6 while appearing firewalled over IPv4.

**Remediation:** Disable IPv6 on the instance if dual-stack is not required. If IPv6 is needed, add explicit firewall rules covering IPv6 CIDRs (::/0) to match the IPv4 rule set.

---

### CTL.LIGHTSAIL.INSTANCE.PATCHSTATE.001

**Lightsail Instance Has Pending Security Patches**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

Lightsail instance has pending security patches. Unlike EC2 instances managed by Systems Manager Patch Manager, Lightsail instances rely on manual patching or blueprint updates. The OpenClaw-on-Lightsail disclosure found 47 pending security patches from first boot, including three critical OpenSSH CVEs (CVE-2026-3497, CVE-2025-61984, CVE-2025-61985). Unpatched instances with public-facing services are direct RCE targets.

**Remediation:** SSH into the instance and run the OS package manager to apply pending security updates. For Ubuntu: sudo apt update && sudo apt upgrade -y. Schedule regular patching or consider migrating to EC2 with Systems Manager Patch Manager for automated compliance.

---

### CTL.LIGHTSAIL.INSTANCE.PUBLIC.001

**Lightsail Instances Must Not Expose Public Ports Broadly**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail instances with public IPs must not have firewall rules allowing broad public access to service ports.

**Remediation:** Restrict firewall rules to specific CIDR ranges.

---

### CTL.LIGHTSAIL.LOG.EXPORT.001

**Lightsail Instance Has No Log Export Configuration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-4, AU-9; soc2: CC7.1;

Lightsail instance has no configured log export destination. Logs stored in ephemeral locations (/tmp, instance-store volumes) are lost on reboot — total forensic blindness. Unlike EC2 instances, Lightsail instances cannot attach CloudWatchAgentServerPolicy to instance roles via the standard IAM console flow. Log export requires manual CloudWatch agent installation with IAM user credentials or a custom instance profile. This manual step is easily missed, leaving the instance without any durable audit trail.

**Remediation:** Install the CloudWatch agent on the Lightsail instance and configure it to export application and system logs to a CloudWatch Log Group. Create an IAM user with CloudWatchAgentServerPolicy, generate access keys, and configure the agent with those credentials. Alternatively, configure rsyslog to forward to a remote syslog server or an S3 bucket via a cron-based upload script.

---

### CTL.LIGHTSAIL.ROLE.OVERBROAD.001

**Lightsail Instance Role Exceeds Required Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

Lightsail instance's IAM credentials have permissions beyond what the instance workload requires. Lightsail instances that use IAM roles (via instance metadata service) should be scoped to the specific resources the application needs. Any wildcard actions — s3:*, iam:PassRole, sts:AssumeRole on broad targets — mean the Lightsail instance becomes an over-permissioned compute node. Lightsail instances are often used for simple workloads with less security scrutiny than EC2; an overbroad role on a less-monitored service is a high-value lateral movement target.

**Remediation:** Scope the instance role to the specific S3 buckets, DynamoDB tables, or other resources the application needs. Remove wildcard actions. Consider whether the Lightsail instance should use IAM roles at all — many Lightsail workloads can use application-level credentials instead.

---

### CTL.LIGHTSAIL.SERVICE.ACTIVE.001

**Lightsail Service Is Active in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

The account has active Lightsail resources. Lightsail operates in an AWS-managed VPC outside the customer's governance boundary: not in AWS Config, not in VPC Flow Logs, own credential namespace.

**Remediation:** Evaluate intent; if unwanted, decommission and SCP deny lightsail:*.

---

