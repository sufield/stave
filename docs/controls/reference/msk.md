# Control Reference — MSK

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.MSK.AUTH.MTLS.001

**MSK Clusters Must Enforce Mutual TLS Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

MSK clusters must enforce mutual TLS (mTLS) for client-broker connections. Without mTLS, adversaries can impersonate clients, intercept sessions, and connect unauthorized producers or consumers.

**Remediation:** Enable mTLS with a certificate authority ARN in the cluster authentication configuration.

---

### CTL.MSK.AUTH.UNRESTRICTED.001

**MSK Clusters Must Not Allow Unauthenticated Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

MSK clusters must not enable unauthenticated client access. Without authentication, any network-reachable client can produce or consume messages — reading sensitive data, injecting malicious events, or disrupting the stream.

**Remediation:** Disable unauthenticated access and enable IAM, SASL, or mTLS authentication.

---

### CTL.MSK.CONNECTOR.ENCRYPT.001

**MSK Connect Connectors Must Encrypt Traffic in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

MSK Connect connectors must use TLS for in-transit encryption. Without TLS, data streams between connectors and Kafka brokers are transmitted in plaintext.

**Remediation:** Set connector EncryptionType to TLS.

---

### CTL.MSK.ENCRYPT.REST.001

**MSK Clusters Must Use Customer-Managed KMS Key for Encryption at Rest**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

MSK clusters must use a customer-managed KMS key for data volume encryption. Service-managed keys prevent granular key policies, independent rotation, and crypto-shredding capability.

**Remediation:** Specify a customer-managed KMS key via DataVolumeKMSKeyId.

---

### CTL.MSK.ENCRYPT.TRANSIT.001

**MSK Clusters Must Encrypt All Traffic in Transit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

MSK clusters must enforce TLS for both client-broker and inter-broker traffic. Without TLS, Kafka messages — including credentials, event data, and replication traffic — are transmitted in plaintext.

**Remediation:** Set client-broker encryption to TLS only and enable inter-broker encryption.

---

### CTL.MSK.LOG.001

**MSK Clusters Must Have Broker Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

MSK clusters must have at least one logging destination configured (CloudWatch Logs, S3, or Firehose) for broker logs. Without logging, broker operations, authentication events, and access patterns are invisible.

**Remediation:** Enable broker logging to CloudWatch Logs, S3, or Firehose in the cluster logging configuration.

---

### CTL.MSK.MONITORING.001

**MSK Clusters Must Enable Enhanced Monitoring**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-6;

MSK clusters must use enhanced monitoring (PER_BROKER or higher). Default monitoring provides insufficient metrics for detecting broker health issues, replication lag, and consumer problems.

**Remediation:** Set enhanced monitoring to PER_BROKER or PER_TOPIC_PER_BROKER.

---

### CTL.MSK.PUBLIC.001

**MSK Clusters Must Not Be Publicly Accessible**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

MSK cluster broker endpoints must not be exposed to the public internet. Public brokers allow unauthorized consumers to read topics, rogue producers to inject events, and internet-wide scanning to enumerate cluster metadata.

**Remediation:** Disable public access on the cluster configuration.

---

### CTL.MSK.REPLICATION.ENCRYPT.MISMATCH.001

**MSK Replicator Target Has Inconsistent Encryption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

MSK cluster with cross-region replication has a target cluster in another region with a different encryption configuration than the source. If the source uses a customer-managed KMS key and the target does not, the same streaming data has different protection levels across regions. The weakest cluster's encryption level is the effective protection for the replicated data set.

**Remediation:** Recreate the target cluster with the same CMK tier as the source. Each region's key must exist in that region. Reconfigure the MSK Replicator after updating the target.

---

### CTL.MSK.REPLICATION.FACTOR.001

**MSK Topic Replication Factor Must Be At Least 3**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** nist_800_53_r5: CP-9; soc2: A1.2;

MSK cluster default topic replication factor must be at least 3. A replication factor below 3 means a single broker failure can cause data loss if the remaining replicas are also unavailable. Combined with min.insync.replicas < 2, producers may acknowledge writes that are stored on only one broker, creating a silent durability gap.

**Remediation:** Set default.replication.factor >= 3 and min.insync.replicas >= 2 in the MSK cluster configuration. This ensures writes are acknowledged only when replicated to multiple brokers.

---

### CTL.MSK.VERSION.001

**MSK Clusters Must Run a Supported Kafka Version**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

MSK clusters must run a supported Kafka version. Outdated versions lack security patches and may have known vulnerabilities.

**Remediation:** Upgrade the cluster to the latest supported Kafka version.

---

