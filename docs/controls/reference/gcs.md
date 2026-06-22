# Control Reference — GCS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.GCS.ENCRYPT.001

**Customer-Managed Encryption Key Required**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets containing sensitive data must use a customer-managed encryption key (CMEK) via Cloud KMS, not the default Google-managed key. CMEK provides key rotation control, access policies, and audit trails that Google-managed keys do not.

**Remediation:** Set a default CMEK on the bucket. Run: gcloud storage buckets update gs://BUCKET --default-encryption-key=projects/PROJECT/locations/LOCATION/keyRings/RING/cryptoKeys/KEY

---

### CTL.GCS.INCOMPLETE.001

**Complete Data Required for GCS Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** storage

GCS bucket safety cannot be proven when access control data is missing from the snapshot. The extractor must populate storage.access.public_read to evaluate public exposure controls.

**Remediation:** Re-run the extractor with storage permissions: storage.buckets.getIamPolicy, storage.buckets.get.

---

### CTL.GCS.LOG.001

**Access Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have access logging enabled. Without logging, access patterns cannot be audited and unauthorized access goes undetected.

**Remediation:** Enable access logging for the bucket. Run: gcloud storage buckets update gs://BUCKET --log-bucket=LOG_BUCKET --log-object-prefix=PREFIX

---

### CTL.GCS.PUBLIC.001

**No Public GCS Bucket Read**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public read access. Detects buckets where IAM bindings include allUsers or allAuthenticatedUsers with read permissions, or where uniform bucket-level access is disabled and object ACLs may grant public access.

**Remediation:** Remove allUsers and allAuthenticatedUsers from bucket IAM bindings. Run: gcloud storage buckets remove-iam-policy-binding gs://BUCKET --member=allUsers --role=roles/storage.objectViewer

---

### CTL.GCS.PUBLIC.002

**No Public GCS Bucket Listing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.1;

GCS buckets must not allow public listing. Anonymous bucket listing exposes the full object inventory, enabling bulk data discovery.

**Remediation:** Remove allUsers from bucket IAM bindings for storage.objects.list. Enable uniform bucket-level access to prevent object ACL overrides.

---

### CTL.GCS.UNIFORM.001

**Uniform Bucket-Level Access Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.2;

GCS buckets must use uniform bucket-level access. When disabled, both IAM policies and object ACLs control access, creating a dual-path exposure risk that is harder to audit and more prone to misconfiguration.

**Remediation:** Enable uniform bucket-level access. Run: gcloud storage buckets update gs://BUCKET --uniform-bucket-level-access

---

### CTL.GCS.VERSION.001

**Object Versioning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_gcp_v1.3.0: 5.3;

GCS buckets must have object versioning enabled. Without versioning, deleted or overwritten objects cannot be recovered, and ransomware attacks that encrypt objects are irreversible.

**Remediation:** Enable versioning. Run: gcloud storage buckets update gs://BUCKET --versioning

---

