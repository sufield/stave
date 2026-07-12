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

### CTL.LIGHTSAIL.INSTANCE.PUBLIC.001

**Lightsail Instances Must Not Expose Public Ports Broadly**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lightsail instances with public IPs must not have firewall rules allowing broad public access to service ports.

**Remediation:** Restrict firewall rules to specific CIDR ranges.

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

