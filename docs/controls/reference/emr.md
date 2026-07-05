# Control Reference — EMR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EMR.ENCRYPT.001

**EMR Clusters Must Use a Security Configuration for Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

EMR clusters must have a security configuration enabling encryption at rest (EMRFS S3, local disk) and in transit (TLS). Without a security configuration, data processed by Spark and Hadoop jobs is stored and transmitted in plaintext.

**Remediation:** Create an EMR security configuration with encryption enabled for at-rest (S3 via EMRFS, local disk via LUKS) and in-transit (TLS) and attach it to the cluster.

---

### CTL.EMR.LOG.001

**EMR Clusters Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

EMR clusters must enable logging to S3 for cluster events, step execution, and application logs. Without logging, job failures, security events, and data access patterns are invisible.

**Remediation:** Enable logging with an S3 log URI when creating or updating the cluster.

---

### CTL.EMR.PUBLIC.BLOCK.001

**EMR Account Must Enable Block Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

The EMR account-level Block Public Access setting must be enabled. When enabled, clusters cannot use security groups with inbound rules allowing public sources (0.0.0.0/0, ::/0) except on explicitly permitted ports.

**Remediation:** Enable Block Public Access in the EMR console or via aws emr put-block-public-access-configuration.

---

### CTL.EMR.PUBLIC.IP.001

**EMR Cluster Nodes Must Not Have Public IP Addresses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

EMR cluster nodes (master and worker) must not have public IP addresses assigned. Public IPs make cluster nodes directly reachable from the internet, exposing Hadoop, Spark, and YARN management interfaces.

**Remediation:** Launch clusters in private subnets without public IP assignment. Use a bastion host or VPN for administrative access.

---

### CTL.EMR.PUBLIC.SG.001

**EMR Cluster Security Groups Must Not Allow Public Inbound**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Security groups attached to EMR cluster nodes must not have inbound rules allowing traffic from 0.0.0.0/0 or ::/0. Open security groups expose Hadoop, Spark, and YARN interfaces to the internet.

**Remediation:** Restrict security group inbound rules to specific CIDR ranges or security group IDs. Remove 0.0.0.0/0 and ::/0 rules.

---

### CTL.EMR.RELEASE.EOL.001

**EMR Clusters Must Not Use End-of-Life Release Labels**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

EMR clusters must not run release labels that have reached end-of-life. AWS publishes support timelines for EMR release series; the emr-5.x series is approaching full EOL, and early emr-6.x releases (6.0-6.3) are past support. EOL release labels include outdated versions of Spark, Hadoop, Hive, and Presto with known CVEs. EMR clusters process data at scale — an unpatched Spark or Hadoop version on the data plane is a direct exposure for any data the cluster reads, transforms, or writes. This is distinct from CTL.EMR.ENCRYPT.001 which checks encryption configuration; an encrypted but unpatched cluster still runs vulnerable processing code.

**Remediation:** Launch new clusters with a supported release label (emr-7.x or latest emr-6.x). Migrate running workflows to the new release. Test Spark/Hive jobs against the new release in a non-production cluster first — major release upgrades may change default configurations, deprecate APIs, or alter SQL behavior.

---

