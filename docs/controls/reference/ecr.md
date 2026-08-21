# Control Reference — ECR

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.ECR.ENCRYPT.CMK.001

**ECR Repository Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

ECR repository uses the default AES-256 encryption rather than a customer-managed KMS key (CMK). The default encryption is real encryption — image layers and manifests are encrypted at rest inside ECR — but the key is AWS-owned: the account has no key policy to control, no audit trail for decrypts, and no way to revoke encryption (deny decrypt) if the data needs to become unreadable. Same pattern as S3 default encryption vs. CMK, EBS default encryption vs. CMK, and Lambda environment KMS — the operational control over the key is the upgrade. For repositories that hold proprietary application code, embedded build artifacts, or images for regulated workloads, the CMK is the typical baseline; for ephemeral test repositories or intentionally public images the default may be acceptable and the finding can be acknowledged in a triage override.

**Remediation:** Re-create the repository with a customer-managed KMS key selected at creation time (encryptionConfiguration.kmsKey set to your CMK ARN). Existing repositories cannot be converted in place — mirror images to the new repository, update task definitions to point at the new repository ARN, and delete the old one. Update the CMK's key policy to grant ecr.amazonaws.com use of the key on behalf of the repository's account.

---

### CTL.ECR.ENHANCED.SCANNING.001

**ECR Repository Uses Basic Scanning Instead of Enhanced**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; nist_800_53_r5: RA-5; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

ECR repository has scanning enabled but uses BASIC scanning (Clair-based, OS package only) rather than ENHANCED scanning (Amazon Inspector). Basic scanning runs only on push and only detects vulnerabilities in OS packages installed via the distro package manager — it misses vulnerabilities in application dependencies (npm, pip, Maven, Go modules, gem, cargo) and does not rescan when new CVEs are published. Enhanced scanning catches application-layer dependencies and rescans existing images continuously — a CVE published today shows up against an image pushed six months ago. Distinct from CTL.ECR.SCAN.001, which checks only that some kind of scanning is enabled; this control fires when scanning is enabled but in BASIC mode where ENHANCED is the appropriate baseline for production registries.

**Remediation:** Enable Amazon Inspector for ECR enhanced scanning at the registry level (it covers all repositories in the account by default). Confirm Inspector findings appear against existing images within the documented rescan window (typically minutes for new pushes, hours for backlog). Adjust the existing CTL.ECR.SCAN.001 finding workflow if it relied on basic scanning being sufficient.

---

### CTL.ECR.FINDINGS.UNRESOLVED.001

**ECR Image Has Unresolved Critical or High Vulnerability Findings**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-2; nist_800_53_r5: SI-2; pci_dss_v4.0: 6.3.3; soc2: CC7.1;

ECR repository contains image scan findings of CRITICAL or HIGH severity that have been outstanding past the policy remediation window — 14 days for CRITICAL, 30 days for HIGH. The vulnerabilities have been detected. Patches or updated base images are available. The image has not been rebuilt. The finding is not "scanning detected something"; it is "scanning detected something and it has been ignored long enough to qualify as an operational gap." Distinct from CTL.ECR.SCAN.001 (scanning is enabled at all) and CTL.ECR.ENHANCED.SCANNING.001 (scanning is the appropriate type) — both of those check that the scanner is running; this control checks that its output is being acted on.

**Remediation:** Identify the affected images and rebuild them against patched base images / dependency versions, then push the rebuilt images and update task definitions or deployments to reference the new digests. For findings that genuinely cannot be remediated (CVE has no patch, false positive against the workload), record the rationale in a triage override on this control with the specific finding ID and affected image digest.

---

### CTL.ECR.INCOMPLETE.001

**Complete Data Required for ECR Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure

ECR repository safety cannot be proven when access control data is missing from the snapshot. The extractor must populate container_registry.access.public to evaluate exposure controls.

**Remediation:** Re-run the extractor with ECR permissions: ecr:DescribeRepositories, ecr:GetRepositoryPolicy.

---

### CTL.ECR.LIFECYCLE.001

**ECR Repositories Must Have a Lifecycle Policy**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-7;

ECR repositories must have a lifecycle policy to expire untagged and old images. Without it, images with known CVEs remain pullable and deployable indefinitely.

**Remediation:** aws ecr put-lifecycle-policy --repository-name <name> --lifecycle-policy-text '<policy JSON>'

---

### CTL.ECR.POLICY.BROAD.001

**ECR Repository Policy Must Not Grant Broad Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

ECR repository policies must not grant ecr:GetDownloadUrlForLayer, ecr:BatchGetImage, or ecr:PutImage to external accounts without restricting to specific account IDs or aws:PrincipalOrgID. Broad cross-account access allows image theft (pull) or supply chain compromise (push) from any granted account.

**Remediation:** Restrict the repository policy to specific account IDs or add an aws:PrincipalOrgID condition. For push access, restrict to CI/CD pipeline roles only.

---

### CTL.ECR.PUBLIC.001

**ECR Repository Must Not Be Public**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; owasp_subtractive: S08; soc2: CC6.1; subtractive_tier: deletion;

ECR repositories must not be publicly accessible. A public ECR repository allows anyone to pull container images, potentially exposing proprietary code, embedded credentials, internal architecture details, and software supply chain artifacts. Public repositories should use ECR Public Gallery only for intentionally open-source images.

**Remediation:** Set the repository policy to restrict access to specific IAM principals. If the repository was created as ECR Public, migrate images to a private ECR repository and update deployment configs.

---

### CTL.ECR.SCAN.001

**Image Scanning Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: RA-5; nist_800_53_r5: RA-5; soc2: CC7.1;

ECR repositories must have image scanning enabled (basic or enhanced). Without scanning, container images with known vulnerabilities are deployed to production undetected.

**Remediation:** Enable scan-on-push in the repository configuration. For enhanced scanning, enable Amazon Inspector ECR integration.

---

### CTL.ECR.SIGNING.001

**ECR Repositories Must Have Image Signing Verification Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

ECR repositories must have container image signing verification configured in enforce mode. Image signing cryptographically verifies that container images were built by a trusted source and have not been tampered with. Without signing verification, any image pushed to the repository — including one from a compromised CI/CD pipeline or supply chain attack — can be deployed without proof of origin or integrity. AWS ECR supports signing through AWS Signer with Notation and Sigstore Cosign. Verification must be in enforce mode — audit mode detects unsigned images but still allows deployment, providing observability without protection. This mirrors the WAF COUNT vs BLOCK and Lambda code signing Warn vs Enforce distinction.

**Remediation:** Configure image signing using AWS Signer with Notation or Sigstore Cosign. Set the ECR registry policy or repository policy to enforce signature verification — unsigned or invalidly signed images must be rejected at pull time. For Kubernetes workloads, configure an admission controller (Kyverno, OPA Gatekeeper) to verify signatures. For ECS, configure the ECR registry signing policy in enforce mode.

---

### CTL.ECR.SIGNING.MANAGED.001

**ECR Repository Has No Managed Signing Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); nist_800_53_r5: SI-7, SA-10; pci_dss_v4.0: 6.3.2; soc2: CC7.1, CC8.1;

ECR repository does not have AWS Managed Signing configured. Managed Signing automatically signs container images at push time using an AWS Signer signing profile, providing cryptographic proof of origin without requiring CI/CD pipeline changes. Without managed signing, images are pushed unsigned — downstream signature verification (admission controllers, ECR pull policies) has nothing to verify, and the entire image-trust chain is unanchored. GA August 2026.

**Remediation:** Enable ECR Managed Signing on the repository by attaching an AWS Signer signing profile. All subsequent pushes will be automatically signed. Verify with: aws ecr describe-repositories --repository-names <name> and confirm the signingConfiguration is present. Pair with CTL.ECR.SIGNING.001 (enforcement) for end-to-end image trust.

---

### CTL.ECR.SIGNING.REVOKED.001

**ECR Signing Profile Has Been Revoked**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; nist_800_53_r5: SI-7, SC-12; pci_dss_v4.0: 6.3.2; soc2: CC6.1, CC7.1;

The AWS Signer signing profile attached to this ECR repository has been revoked. Images pushed after revocation carry invalid signatures that downstream verification will reject. This creates a silent deployment failure — CI/CD pushes succeed at the ECR layer but admission controllers or pull-time verification reject the images. Revocation may indicate a key compromise event, an operational error, or a deliberate security action that was not propagated to the ECR configuration.

**Remediation:** Create a new AWS Signer signing profile and update the ECR repository's signing configuration to reference it. If revocation was due to key compromise, audit all images signed with the old profile and re-sign with the new one. Verify: aws signer get-signing-profile --profile-name <name> Status should be "Active", not "Revoked".

---

### CTL.ECR.TAG.IMMUTABLE.001

**ECR Repositories Must Enforce Image Tag Immutability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 5.4; nist_800_53_r5: SI-7;

ECR repositories must enforce image tag immutability to prevent supply chain attacks where a compromised pipeline overwrites a trusted image tag with malicious content.

**Remediation:** aws ecr put-image-tag-mutability --repository-name <name> --image-tag-mutability IMMUTABLE

---

