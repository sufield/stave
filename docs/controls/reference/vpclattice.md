# Control Reference — VPCLATTICE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.VPCLATTICE.NETWORK.CROSSACCOUNT.001

**VPC Lattice Service Network Has Cross-Account Associations**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, AC-4; soc2: CC6.1;

A VPC Lattice service network has VPC associations from accounts outside the organization. Cross-account service network associations extend the trust boundary to external accounts, creating lateral movement paths between organizations.

**Remediation:** Review and remove external VPC associations: aws vpc-lattice list-service-network-vpc-associations --service-network-identifier <network-id>. Delete associations from untrusted accounts.

---

### CTL.VPCLATTICE.NETWORK.NOAUTH.001

**VPC Lattice Service Network Has No Auth Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A VPC Lattice service network has no auth policy configured. The service network is the trust boundary for all associated services and VPCs. Without a network-level auth policy, any VPC associated with the network can reach all services with no centralized access control.

**Remediation:** Apply a network-level auth policy: aws vpc-lattice put-auth-policy --resource-identifier <network-id> --policy <json>.

---

### CTL.VPCLATTICE.SERVICE.ENCRYPT.001

**VPC Lattice Service Not Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

A VPC Lattice service does not use encryption for service-to-service communication. Without encryption, traffic between services is transmitted in cleartext within the VPC, exposing it to interception by any workload with network access.

**Remediation:** Configure the service listener to use HTTPS: aws vpc-lattice create-listener --service-identifier <service-id> --protocol HTTPS.

---

### CTL.VPCLATTICE.SERVICE.NOAUTH.001

**VPC Lattice Service Has No Auth Policy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; soc2: CC6.1;

A VPC Lattice service has no auth policy configured. Without an auth policy, any source in the service network can send traffic to this service with no identity verification — equivalent to an open security group for service-to-service communication.

**Remediation:** Apply an auth policy: aws vpc-lattice put-auth-policy --resource-identifier <service-id> --policy <json>.

---

### CTL.VPCLATTICE.SERVICE.NOLOGGING.001

**VPC Lattice Service Access Logging Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-2, AU-3; soc2: CC7.1;

A VPC Lattice service does not have access logging enabled. Without logging, service-to-service traffic patterns, failed authentication attempts, and anomalous access are not recorded.

**Remediation:** Create an access log subscription: aws vpc-lattice create-access-log-subscription --resource-identifier <service-id> --destination-arn <s3-or-cloudwatch-arn>.

---

