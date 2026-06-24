# Control Reference — DATACLASS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.DATACLASS.PROD.UNTAGGED.001

**Production Data-Bearing Resource Must Not Be Unclassified**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** soc2: CC6.1;

A data-bearing resource in a production environment with no data-classification tag is treated as HIGH severity, not as routine hygiene. The fail-loud principle applied to classification: absence of classification in production is not "unclassified" — it is "unknown, assume worst case." Production data that no control knows is sensitive is the root cause behind a large share of data-leak incidents.
The collector emits governance.environment (the resolved environment, e.g. production, derived from account tag / name pattern / org unit), governance.is_data_bearing, and governance.data_classification. This predicate fires on production + data-bearing + no classification.

**Remediation:** Classify the resource immediately with an approved taxonomy value. If it truly holds no sensitive data, tag it public/internal explicitly — silence is not an acceptable classification in production.

---

### CTL.DATACLASS.TAG.MISSING.001

**Data-Bearing Resource Must Carry a Classification Tag**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** soc2: CC6.1;

Every data-bearing resource (S3 bucket, RDS instance, DynamoDB table, Secrets Manager secret, OpenSearch collection, Redshift cluster, EFS filesystem) must declare a data-classification tag. Stave's intent-tag controls only fire when a classification tag EXISTS and mismatches reality — a resource with NO classification tag is invisible to them: there is no declared intent to check against. This control closes that blind spot by treating absence of classification as a violation, not a silent pass.
The collector normalizes whichever tag key the organization uses (data_classification, data-classification, classification, sensitivity) into the derived signals this predicate reads: governance.is_data_bearing (the asset stores data and is therefore in scope) and governance.data_classification (the resolved classification value, absent when no recognized tag is present).
Fail-loud: an in-scope resource with no classification is a governance gap, not "unclassified data is fine." Tag it, then the value-level controls (taxonomy, PHI markers, retention) can reason about it.

**Remediation:** Apply a data-classification tag drawn from the approved taxonomy (public, internal, confidential, restricted, pii, phi, pci). Wire tagging into the resource's IaC module so new resources are classified at creation.

---

### CTL.DATACLASS.TAG.TAXONOMY.001

**Data-Classification Tag Must Use an Approved Taxonomy Value**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** soc2: CC6.1;

When a data-bearing resource declares a data-classification, the value must come from the approved taxonomy: public, internal, confidential, restricted, pii, phi, or pci. Freeform values ("important", "sensitive-ish", "team-data") defeat sensitivity-scoped controls just as surely as a missing tag — a control that keys on data_classification == "phi" never matches "phi-data" or "Protected Health Info". This control flags any non-approved value so the taxonomy stays machine-comparable.
The collector emits governance.data_classification as the resolved tag value. This predicate fires when that value is present but is none of the approved terms.

**Remediation:** Replace the freeform value with an approved term: public, internal, confidential, restricted, pii, phi, or pci. Enforce the allowed set in the tagging policy / IaC validation.

---

