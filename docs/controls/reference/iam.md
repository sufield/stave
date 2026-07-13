# Control Reference — IAM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.IAM.ACCOUNT.INACTIVE.001

**Inactive Accounts Must Be Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM accounts with no login or API activity for 90 days or more must be disabled. Dormant accounts are high-value targets — they have permissions but no active user monitoring their usage. Legacy accounts, test accounts, and accounts from departed employees accumulate over time and provide persistent, unmonitored access paths for attackers.

**Remediation:** Disable or delete the IAM user. If the account is still needed, review and renew its access with a documented justification and an updated expiry date.

---

### CTL.IAM.ADMIN.COUNT.001

**Admin User Count Must Not Exceed Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.2; soc2: CC6.1;

AWS accounts must have no more than 2 users with full administrator access. Excessive admin accounts expand the credential compromise surface and violate least privilege. Use IAM roles with temporary elevation (break-glass) instead of permanent admin access.

**Remediation:** Reduce admin users to 2 or fewer. Convert permanent admin access to IAM roles with temporary elevation via sts:AssumeRole. Use IAM Access Analyzer to identify unused admin permissions.

---

### CTL.IAM.AGENT.CHAIN.SENSITIVE.001

**Agent Role Must Not Reach Sensitive Resources via Trust Chain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

An agent-identified execution role must not be able to reach a sensitive resource (Secrets Manager secret, customer-managed KMS key, RDS, or a bucket tagged confidential/restricted/pii/phi) — directly, through an AssumeRole/PassRole chain of arbitrary length, or via a resource-based policy. Each hop can look least-privilege in isolation: the agent role only has AssumeRole, the intermediate role only has access to one secret. The danger is the composition — an attacker with prompt control over the agent inherits the transitive reach.
This is a compound (graph-reachability) control. Per-resource CEL sees only direct access; the transitive path is what the graph reasoning sees. The catalog control reads the derived signals the reasoning layer computes: identity.role.workload_type (the role is an agent / non-human identity) and identity.agent_reaches_sensitive (graph reachability from this agent role to a sensitive resource is true). The reasoning spec that computes the boolean — and proves it two independent ways, Soufflé and Z3 — lives at examples/agent-chain-sensitive-reach/. identity.agent_reach_path carries the full path as finding evidence.
Fail-closed on the agent signal: a role whose reach the graph could not resolve is not silently passed; the reasoning emits the boolean explicitly.

**Remediation:** Break the path: remove the AssumeRole/PassRole edge to the intermediate role, scope the intermediate role's permissions off the sensitive resource, or constrain the agent role's trust so it cannot pivot. Review identity.agent_reach_path (the full hop-by-hop chain) to choose the narrowest cut.

---

### CTL.IAM.AGENT.LONGLIVEDKEYS.001

**Agent / Non-Human Identity Must Not Hold Long-Lived Access Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI1; soc2: CC6.1;

An IAM identity that represents an agent or automation workload (a non-human identity, NHI) must obtain credentials through short-lived STS session assumption, never through long-lived IAM access keys. NHIs now outnumber human identities many times over; a static access key on an agent identity is a durable, exfiltratable secret with no built-in expiry — exactly the credential an attacker wants. Agent workloads should assume a role for the duration of a task and let the session expire.
The collector classifies the identity's workload type from its trust policy principals (bedrock/sagemaker/lambda/states service principals), name pattern (*agent*, *bot*, *automation*, *pipeline*), or an explicit role-type/ workload-type tag, emitting identity.role.workload_type. It also emits identity.role.long_lived_keys_present (an active IAM access key exists). This control fires when an agent-classified identity has a long-lived key.
Complements the Bedrock-agent permission-scope controls (CTL.BEDROCK.AGENT.OVERPERM.*): those bound what an agent role can do; this bounds how its credentials are issued.

**Remediation:** Delete the long-lived access key and have the workload assume a role (instance profile, IRSA, Bedrock/SageMaker service role, or OIDC web-identity federation) so credentials are session-scoped and expire automatically.

---

### CTL.IAM.ANALYZER.001

**IAM Access Analyzer Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC6.1;

IAM Access Analyzer must be enabled in every region. Access Analyzer identifies resources shared with external entities and generates findings for unintended exposure.

**Remediation:** Create an Access Analyzer in each region: aws accessanalyzer create-analyzer --analyzer-name default --type ACCOUNT --region <region>

---

### CTL.IAM.ANALYZER.MONITOR.001

**IAM Access Analyzer Must Be Configured for Continuous Monitoring**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.21; fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 11.3.1; soc2: CC7.1;

IAM Access Analyzer must be in ACTIVE status and findings must be reviewed within 30 days. CIS 1.21 requires not just enablement (covered by CTL.IAM.ANALYZER.001) but active monitoring and finding review. An analyzer with unreviewed findings has detected external access paths — S3 buckets, IAM roles, KMS keys, Lambda functions accessible outside the account — that have not been evaluated for legitimacy. Active findings are confirmed external access paths waiting to be investigated, not theoretical risks. For PHI environments, any unreviewed external access path is a potential breach path.

**Remediation:** Verify the analyzer is in ACTIVE status in all regions. Review all active (unarchived) findings. For each finding, determine if the external access is intended — archive intended access, remediate unintended access. Establish an operational process to review new findings within 30 days of detection.

---

### CTL.IAM.ANALYZER.ORG.001

**IAM Access Analyzer Must Be Configured at Organization Level**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; scs_c02: 12.2; soc2: CC6.1;

IAM Access Analyzer should include an organization-level analyzer (type ORGANIZATION), not just account-level analyzers. An account- level analyzer only detects access from outside that specific account. An organization-level analyzer detects access from outside the entire organization — including cross-account access between member accounts that bypasses intended boundaries. Without an org-level analyzer, a role trusted by another member account looks "internal" to the account analyzer but may violate organizational access policy.

**Remediation:** Create an organization-level Access Analyzer from the management or delegated admin account: aws accessanalyzer create-analyzer --analyzer-name org-analyzer --type ORGANIZATION.

---

### CTL.IAM.ANALYZER.UNUSEDACCESS.001

**No IAM Access Analyzer for Unused Access Detection**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(3); scs_c02: 12.5; soc2: CC6.1;

No IAM Access Analyzer of type UNUSED_ACCESS exists. The unused access analyzer identifies IAM roles and users with permissions they have not used within a specified period, plus unused access keys and passwords. Without it, over-privileged identities accumulate permissions that expand the blast radius of credential compromise.

**Remediation:** Create an unused access analyzer: aws accessanalyzer create-analyzer --analyzer-name unused-access --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess": {"unusedAccessAge": 90}}'.

---

### CTL.IAM.BOUNDARY.001

**IAM Roles Must Have Permissions Boundary**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must have a permissions boundary attached. A permissions boundary sets a ceiling on the effective permissions of a role, regardless of what identity policies are attached. Without a boundary, a developer who can create or modify roles has no ceiling preventing the provisioned role from granting full admin access.

**Remediation:** Attach a permissions boundary policy to the role using aws iam put-role-permissions-boundary. Define a boundary that caps permissions to the services and actions required for the role's documented function.

---

### CTL.IAM.BOUNDARY.ESCAPE.001

**Principal Can Delete Own Permission Boundary**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An IAM principal has iam:DeleteRolePermissionsBoundary or iam:PutRolePermissionsBoundary on its own role ARN. The principal can remove or replace its own boundary — instantly expanding its effective permissions to whatever its IAM policies allow without boundary constraint. This is the most direct bypass of boundary-based delegation models.

**Remediation:** Remove iam:DeleteRolePermissionsBoundary and iam:PutRolePermissionsBoundary permissions from the principal for its own role ARN. Boundaries must be managed by a separate admin principal.

---

### CTL.IAM.BOUNDARY.MISSING.001

**Delegated Admin Role Can Create Unbounded Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.3;

An IAM role with iam:CreateRole or iam:CreateUser permission does not have a permission boundary that requires setting a boundary on created principals. The role can create new IAM roles and users without any boundary constraint — the created principals have no upper bound on their effective permissions.

**Remediation:** Add a permission boundary condition to the delegated admin role that requires iam:PermissionsBoundary on CreateRole and CreateUser calls.

---

### CTL.IAM.BOUNDARY.WILDCARD.001

**Permission Boundary Uses Wildcard Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

A permission boundary includes Action * or Action service:* — the boundary does not actually constrain the principal's actions. A boundary with Action * on Resource * is equivalent to no boundary. The boundary exists in the IAM configuration but provides no effective restriction.

**Remediation:** Replace wildcard actions in the permission boundary with specific service actions that the bounded principal requires. A boundary with Action * is equivalent to no boundary.

---

### CTL.IAM.CERT.EXPIRED.001

**Remove Expired IAM Server Certificates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.19;

Expired SSL/TLS server certificates must be removed from IAM. Expired certificates cannot serve TLS but create confusion during audits and may mask missing certificate rotation.

**Remediation:** Delete expired certificates and migrate active ones to ACM: aws iam delete-server-certificate --server-certificate-name <name>

---

### CTL.IAM.CHAIN.GHOST.DELETION.001

**Role Chain Reaches a Role Scheduled for Deletion (TOCTOU)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, CM-3; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: AC-2, CM-3, IR-4; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.1, 10.6; soc2: CC6.1, CC8.1;

A principal has a transitive role-assumption chain whose target is scheduled for deletion at a known future time. The chain is reachable now, but every consumer caching the reachability decision is stale once the deletion completes — the time-of-check / time-of-use pattern. After the deletion window closes, the chain has a future-ghost reference: any policy that re-evaluated against the cached chain would assume permissions that no longer exist (or — worse — that another team has recreated under the same ARN with different intent). Same ghost-reference primitive as CTL.SECRETS.GHOST.DELETION.REFERENCED.001, lifted from per-asset to multi-hop chain analysis. The .present boolean is folded upstream from Stave's chain walker, which stamps each emitted RoleChainFact with `scheduled_deletion_at` whenever the chain crosses an identity scheduled for future deletion (the earliest such timestamp wins per chain).

**Remediation:** Decide intent: (a) if the deletion is unintended, cancel it and restore the role; (b) if intentional, remove the intermediate hops that lead to this role BEFORE the deletion window closes — typically by tightening sts:AssumeRole on the trust policies of the upstream roles, or by removing iam:PassRole grants that aim at the doomed role. After the deletion completes, audit any IaC / Terraform state that references the role's ARN; recreating the role under the same name is the foundational TOCTOU step the attacker would race for.

---

### CTL.IAM.CONSOLE.MFA.001

**Console Users Must Have MFA Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.10; cis_aws_v3.0: 1.10; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; owasp_nhi: NHI4; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with console access must have multi-factor authentication enabled. Console access without MFA allows credential-only login, making accounts vulnerable to password compromise.

**Remediation:** Enable MFA for the user via IAM > Users > Security credentials > MFA. Alternatively, disable console access if the user only needs programmatic access.

---

### CTL.IAM.CRED.EXPIRY.001

**Credentials Must Have Defined Expiry**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.8.5; nist_800_53_r5: AC-2; owasp_nhi: NHI7; pci_dss_v4.0: 8.1.4; soc2: CC6.1;

IAM credentials must have a defined maximum lifetime. Credentials without expiry — access keys created for QA, debugging, or temporary integrations — persist indefinitely and become permanent attack surfaces. Time transforms temporary mistakes into permanent breaches. Every credential must have a TTL enforced at creation time or through automated lifecycle policies.

**Remediation:** Replace long-lived access keys with STS temporary credentials that expire automatically. If access keys are required, enforce a maximum age policy and automate rotation via Secrets Manager. Tag credentials with creation date and intended expiry.

---

### CTL.IAM.CRED.RECUR.001

**IAM Console Password Must Not Be Disabled and Re-Enabled Repeatedly**

- **Severity:** high
- **Type:** unsafe_recurrence
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC7.1;

IAM user console password has been disabled and re-enabled more than once in 30 days. Password lifecycle manipulation — disable, re-enable, repeat — is the pattern of an attacker maintaining persistence through credential lifecycle events that would otherwise revoke access.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.IAM.CRED.ROTATION.001

**Access Keys Must Be Rotated Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.14; cis_aws_v3.0: 1.14; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); owasp_nhi: NHI7; pci_dss_v3.2.1: 8.2.4; pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user access keys older than 90 days must be rotated. Long-lived access keys accumulate exposure risk and may have been leaked in code repositories, logs, or configuration files.

**Remediation:** Create a new access key, update all systems using the old key, then deactivate and delete the old key.

---

### CTL.IAM.CRED.SETUPKEY.001

**No Access Keys Created at User Setup**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.11; owasp_nhi: NHI1; soc2: CC6.2;

Access keys should not be created at user creation time. Keys created during setup are often distributed insecurely and may not be needed. Create keys only for specific programmatic access.

**Remediation:** Delete the setup-time access key and create a new one only if programmatic access is specifically required.

---

### CTL.IAM.CRED.SINGLEKEY.001

**Single Active Access Key per User**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.13; fedramp_moderate: IA-5; nist_800_53_r5: IA-5; owasp_nhi: NHI7, NHI10; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

Each IAM user must have at most one active access key. Multiple active keys increase the attack surface and complicate key rotation.

**Remediation:** Deactivate and delete the extra access key: aws iam update-access-key --status Inactive --access-key-id AKIA... aws iam delete-access-key --access-key-id AKIA...

---

### CTL.IAM.CRED.TTL.EXCEEDED.001

**IAM Credential Has Exceeded Its Declared TTL**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(d); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, AC-2; owasp_nhi: NHI7; pci_dss_v4.0: 8.3.5; soc2: CC6.1;

IAM credential has a declared TTL (maximum lifetime) and the current age exceeds it. The credential should have been rotated or deactivated when its TTL elapsed. A credential beyond its TTL is a permanent attack surface masquerading as a temporary one. Distinct from CTL.IAM.CRED.EXPIRY.001 which checks whether an expiry IS DECLARED — this control checks whether the declared expiry HAS ELAPSED. A credential with has_expiry=true and ttl_exceeded=true passed the first check and fails the second: the operator set a TTL but nobody enforced it. Same shape as CTL.AD.KRBTGT.ROTATION.001 (krbtgt_password_age_days > 180) and CTL.IAM.CRED.UNUSED45.001 (access_key_unused_days > 45) — the Time-Bound Credential Invariant stricter variant called out in the temporal-features audit (GAP-L, row 12b).

**Remediation:** Rotate or deactivate the credential immediately. For access keys:

    aws iam update-access-key --access-key-id <key-id> \
      --status Inactive --user-name <user>

Then issue a new credential with a fresh TTL, or migrate the workload to ephemeral credentials (OIDC federation via GitHub Actions / GitLab CI assume-role, IAM Roles Anywhere with SPIFFE/SPIRE, or short-lived STS sessions tied to a workload identity). Audit how the TTL was bypassed — typically the collector pre-computes ttl_exceeded from the credential's creation date + declared max lifetime; the bypass is usually "the rotation Lambda failed and nobody noticed."

---

### CTL.IAM.CRED.UNUSED.001

**Disable Unused Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.12; cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.1.4; soc2: CC6.2;

IAM credentials unused for 90 days or more must be disabled. Dormant credentials are a persistent attack surface that provides access without triggering normal usage patterns.

**Remediation:** Disable or delete unused credentials. Review the user's need for access and remove the IAM user if no longer required.

---

### CTL.IAM.CRED.UNUSED45.001

**Disable Credentials Unused for 45 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; owasp_nhi: NHI1;

IAM credentials (passwords and access keys) unused for 45 or more days must be disabled. CIS v3.0 requires a 45-day threshold, which is stricter than the 90-day HIPAA threshold.

**Remediation:** Disable inactive access keys and console passwords: aws iam update-access-key --status Inactive --access-key-id AKIA...

---

### CTL.IAM.CREDENTIAL.CFN.001

**CloudFormation Stack Contains Embedded Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5(7); nist_800_53_r5: IA-5(7); owasp_nhi: NHI2; pci_dss_v4.0: 8.6.2; soc2: CC6.1;

CloudFormation stack parameters, resources, or outputs contain AWS access keys, secret keys, or hardcoded passwords. Stack parameters marked as NoEcho are still visible in the template source. Stack history retains parameter values across updates — credentials embedded in any historical version remain retrievable.

**Remediation:** Replace hardcoded credentials in CloudFormation with dynamic references to Secrets Manager or SSM Parameter Store SecureString. Use NoEcho for sensitive parameters and rotate any exposed credentials immediately.

---

### CTL.IAM.CREDENTIAL.CICD.001

**CI/CD Uses Long-Lived Access Keys Instead of OIDC Federation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5(1); nist_800_53_r5: IA-5(1); owasp_nhi: NHI2; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

CI/CD pipelines (GitHub Actions, GitLab CI, Bitbucket Pipelines) authenticate to AWS using long-lived IAM access keys stored as CI/CD secrets instead of OIDC federation. OIDC federation provides short-lived credentials scoped to specific repositories and workflows — no long-lived secrets to leak, no keys to rotate.

**Remediation:** Replace long-lived IAM access keys with OIDC federation. Configure an IAM OIDC provider for your CI/CD platform and create a role with a trust policy scoped to specific repositories and workflows.

---

### CTL.IAM.CREDENTIAL.CICD.AI.001

**CI/CD Pipeline Stores Long-Lived AI Provider API Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5(1); owasp_nhi: NHI2, NHI7; soc2: CC6.1;

CI/CD pipelines (GitHub Actions, GitLab CI, Bitbucket Pipelines) store long-lived API keys for external AI providers (OpenAI, Anthropic, Google Gemini) as pipeline secrets or environment variables. If the pipeline is compromised — through a supply- chain attack on a dependency, a malicious pull request, or a trojanized GitHub Action — the attacker gains persistent access to the AI provider's API under the organization's account.
Long-lived AI-provider keys in CI/CD are the AI equivalent of long-lived AWS access keys in CI/CD (see CTL.IAM.CREDENTIAL.CICD.001). The mitigation pattern is the same: prefer short-lived, scoped credentials over permanent API keys, and where OIDC federation is not yet available for the AI provider, rotate the key on a short interval and scope it to the minimum required API surface.
The TeamPCP / UNC6780 campaign (GTIG, March 2026) demonstrated this exact extraction path against AWS keys; the same technique extracts AI-provider API keys from the same secret stores (LiteLLM/BerriAI compromise is the canonical case study).

**Remediation:** Replace the long-lived AI-provider API key with a short-lived credential. For providers that support OIDC federation (e.g., Google Cloud service-account OIDC), use that. Otherwise: store the key in a secrets manager configured for automatic rotation (AWS Secrets Manager, HashiCorp Vault, GitHub OIDC-fronted issuance); scope it to the minimum required API surface; and set billing alerts to surface unauthorized usage spikes early.

---

### CTL.IAM.CREDENTIAL.USERDATA.001

**EC2 User Data Contains AWS Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5(7); hipaa: 164.312(a)(1); nist_800_53_r5: IA-5(7); owasp_nhi: NHI2; pci_dss_v4.0: 8.6.2; soc2: CC6.1;

EC2 instance user data contains AWS access keys, secret keys, or session tokens. User data is retrievable via the instance metadata service (169.254.169.254/latest/user-data) and visible in the EC2 console, API responses, and CloudFormation stack history. Credentials in user data are exposed to anyone with EC2 describe permissions or metadata access — four separate attack surfaces.

**Remediation:** Remove hardcoded credentials from user data. Use IAM instance profiles for EC2 access to AWS services. For bootstrap secrets use Secrets Manager or SSM Parameter Store SecureString.

---

### CTL.IAM.CROSS.ENV.001

**Non-Production Must Not Access Production Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; iso_27001_2022: A.8.22; nist_800_53_r5: AC-4; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles in non-production environments (test, staging, QA) must not have access to production resources. Cross-environment access collapses security boundaries — a compromised test account becomes a path to production data. The Microsoft breach (2024) demonstrated this exact failure: a test tenant with production-scope grants enabled a nation-state actor to pivot from test to production.

**Remediation:** Remove production resource ARNs from non-production role policies. Use separate AWS accounts for prod and non-prod with no cross- account trust. Enforce environment boundaries via SCPs that deny non-prod accounts from accessing prod resources. Tag all accounts and roles with their environment classification.

---

### CTL.IAM.CROSS.ENV.PATH.001

**Production Must Not Be Reachable from Lower Environment via Transitive Trust**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Production resources must have no transitive access path from non-production environments. The extractor traces sts:AssumeRole chains and resource policy grants from non-production accounts to production resources. A direct cross-account role is one hop; a chain through an intermediate shared-services account is two or more. Each hop widens the attack surface — a compromised dev credential becomes a production breach when bridge roles exist.

**Remediation:** Remove cross-account trust relationships that bridge non-prod to prod. Use separate deployment pipelines per environment. Enforce environment isolation via SCPs that deny non-prod accounts from assuming prod roles.

---

### CTL.IAM.CROSSCLOUD.ADMIN.001

**No Full Admin Policies Across Any Cloud Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

No IAM policy on any cloud provider should grant unrestricted administrative access (Action: *, Resource: * or equivalent). This control extends CTL.IAM.POLICY.ADMIN.001 beyond AWS to Azure (Contributor/Owner at subscription scope) and GCP (roles/owner, roles/editor at project scope). The same least-privilege principle applies regardless of cloud provider.

**Remediation:** Replace admin policies with scoped policies granting only required permissions. Use cloud-specific access analyzers to identify unused permissions.

---

### CTL.IAM.CROSSCLOUD.MFA.001

**MFA Must Be Enforced Across All Cloud Providers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; soc2: CC6.1;

All privileged accounts across all cloud providers must have MFA enforced. This control extends AWS MFA controls to Azure AD (Conditional Access requiring MFA) and GCP (2-Step Verification enforcement). A single cloud account without MFA is a breach vector regardless of how well other clouds are protected.

**Remediation:** Enforce MFA at the identity provider level. AWS: IAM MFA policy conditions. Azure: Conditional Access policies. GCP: 2-Step Verification enforcement in Workspace/Cloud Identity.

---

### CTL.IAM.ESCALATE.ADDLAYER.001

**Principal Must Not Escalate via Lambda AddLayerVersionPermission**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with lambda:AddLayerVersionPermission can modify shared Lambda layers that other functions depend on. If the attacker modifies a widely-used layer, every function using that layer is compromised on next deployment. This is a supply chain attack via Lambda layers — the attacker doesn't modify the function code, they modify a dependency the function imports.

**Remediation:** Remove lambda:AddLayerVersionPermission or scope it to specific layer ARNs. Modifying layer permissions can share layers cross-account, enabling supply chain attacks on functions that depend on the layer.

---

### CTL.IAM.ESCALATE.ADDUSERTOGROUP.001

**Principal Must Not Escalate via iam:AddUserToGroup To A Broader Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AddUserToGroup` can add itself to any group whose Resource scope includes it. When a candidate target group grants permissions that exceed the principal's current set, joining that group is a single-call privilege escalation. This is Rhino Security Labs privilege-escalation technique #6 ("IAM — AddUserToGroup"). Unlike techniques #3 and #4, the escalating principal does not need to modify the group's policies at all; it only needs the group to exist with broader permissions and for `AddUserToGroup` to be scoped to reach that group.
Scope: gated on `identity.kind == "user"`. The `iam:AddUserToGroup` AWS action targets users specifically; IAM groups cannot contain roles. No role-side analogue exists.

**Remediation:** Scope `iam:AddUserToGroup` to groups whose permissions do not exceed the principal's, or remove the permission entirely from non-admin principals. If developer self-service group joins are needed, constrain the target group set with a Condition on `iam:ResourceTag` or a specific group-name prefix.

---

### CTL.IAM.ESCALATE.ASSUMEROLE.001

**Principal Must Not Escalate via sts:AssumeRole To A Broader Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `sts:AssumeRole` reaching a role whose attached permissions exceed its own — and whose trust policy permits the principal to assume it — has a one-call path to those permissions. The principal does not grant itself anything; it pivots into a role that already carries the broader set. This is Rhino Security Labs' role-assumption escalation pattern, adjacent to the direct-policy cluster (CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001 etc.) but distinct: the escalation vector here is the role's existing trust, not a self-modification of any policy. Remediation also differs — remove `sts:AssumeRole` from the principal or narrow the trust policy on the target role — so the control is separate from CTL.IAM.ESCALATE.UPDATETRUST.001 even though the two can chain.

**Remediation:** Either remove `sts:AssumeRole` from the principal, or narrow the target role's trust policy so the principal is no longer permitted. If cross-service pivots are intentional (CI/CD deploy roles, break-glass admin roles), gate the trust with `sts:ExternalId`, `aws:MultiFactorAuthPresent`, or `aws:PrincipalOrgID` and audit use via CloudTrail. For account-root trusts, add an explicit Condition on the calling principal's ARN or role.

---

### CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.001

**Principal Must Not Escalate via iam:AttachGroupPolicy On A Belonging Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AttachGroupPolicy` whose Resource field includes a group the principal belongs to can attach any managed policy to that group, elevating every member including itself. This is Rhino Security Labs privilege-escalation technique #3 ("IAM — Attach to group"). The group hop adds one indirection over `AttachUserPolicy` on self but is functionally equivalent: attach `AdministratorAccess` to a belonging group, and the principal is admin.
Scope: gated on `identity.kind == "user"`. IAM groups are a user-only concept — roles cannot belong to groups. The technique has no role-side analogue; there is no future control waiting in the queue for a role-side version because AWS IAM does not have role groups.

**Remediation:** Scope `iam:AttachGroupPolicy` to groups the principal does not belong to, or remove the permission entirely from non-admin principals. Use an SCP to deny `iam:AttachGroupPolicy` where the target group has the principal in its membership list.

---

### CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001

**Principal Must Not Escalate via iam:AttachRolePolicy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal (IAM user or role) holding `iam:AttachRolePolicy` on a role it can reach can attach any managed policy — including `arn:aws:iam::aws:policy/AdministratorAccess` — to that role and gain the policy's permissions with a single API call. Two shapes share one outcome: a ROLE whose Resource field includes its own ARN self-attaches admin (one step), or a USER with `iam:AttachRolePolicy` scoped to a role it can assume attaches admin to that role and then assumes it (the Rhino/Bishop Fox privesc9 technique). The escalating principal is the one holding the permission; the victim is the role. Distinct AWS action from `iam:AttachUserPolicy`, which targets users (see `CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001`) — this control covers `iam:AttachRolePolicy` whether the holding principal is a user or a role. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate it.

**Remediation:** Remove `iam:AttachRolePolicy` from the role, or scope its Resource to role ARNs that do not include the role itself (admin-only role-creation workflows, for example). Enforce at the organization level with an SCP that denies `iam:AttachRolePolicy` on `${aws:PrincipalArn}`. A permissions boundary on the role that prevents the attached policy from taking effect is an additional defensive layer.

---

### CTL.IAM.ESCALATE.ATTACHUSERPOLICY.001

**Principal Must Not Escalate via iam:AttachUserPolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:AttachUserPolicy` whose Resource field includes its own user ARN can attach any managed policy — including `arn:aws:iam::aws:policy/AdministratorAccess` — to itself and become admin with a single API call. This is Rhino Security Labs privilege-escalation technique #1 ("IAM — Attach to user") and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. No other permission is required; self-scoped AttachUserPolicy is a one-step path to full admin.
Scope: gated on `identity.kind == "user"`. The `iam:AttachUserPolicy` AWS action targets users specifically — roles cannot be the self- target. The role-side analogue is `iam:AttachRolePolicy` on self, a separate technique covered by its own `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001` control.

**Remediation:** Remove `iam:AttachUserPolicy` from the principal, or scope its Resource field to user ARNs that do not include the principal itself (admin-only bootstrap roles, for example). Enforce at the organization level with an SCP that denies `iam:AttachUserPolicy` on `${aws:PrincipalArn}`. Also consider a permissions boundary on the principal that prevents the attached policy from taking effect.

---

### CTL.IAM.ESCALATE.CHAIN.001

**Principal Must Not Have Multi-Step Path to Admin**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM principals must have no multi-step permission chain that leads to administrative access. The extractor analyzes known escalation patterns (iam:PassRole + lambda:CreateFunction, iam:CreatePolicyVersion on self, sts:AssumeRole to admin role, etc.) and traces whether a low-privileged principal can chain permissions to reach admin. Each step is individually authorized but the composition creates a privilege escalation path that policy reviews miss.

**Remediation:** Remove the weakest link in the escalation chain. Common fixes: scope iam:PassRole to specific role ARNs, restrict lambda:CreateFunction to approved execution roles, add permissions boundaries that deny IAM self-modification.

---

### CTL.IAM.ESCALATE.COGNITO.UPDATEATTR.001

**Principal Can Set Any User Attribute via Unscoped AdminUpdateUserAttributes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6, AC-16; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal can call cognito-idp:AdminUpdateUserAttributes without an attribute-scoping Condition. The permission is legitimate for SCIM / JIT provisioning — but unconstrained, it can set ANY attribute on ANY user in the pool, including security-sensitive ones (custom:role, custom:isAdmin, custom:tenantID). A SCIM handler (or any holder of this permission) thus escalates: write custom:role=admin on a user and application-side authorization treats them as admin. The fix is an IAM Condition restricting which attributes may be updated (cognito-idp:AllowedAttributesForUpdate); with that condition present, the permission is safe and this control does not fire.
Generic least-privilege controls (CTL.LAMBDA.ROLE.LEASTPRIV.001, CTL.IAM.POLICY.SERVICEWILDCARD.001) do not catch this — AdminUpdateUserAttributes is a normal provisioning action, not a wildcard or admin grant. The collector resolves the permission across inline + attached managed policies (e.g. AmazonCognitoPowerUser grants cognito-idp:* with no condition) and matches not just the exact action and cognito-idp:* but any partial wildcard whose glob covers it (cognito-idp:Admin*, cognito-idp:AdminUpdate*) — FN traps. It sets the .present boolean when the action is reachable AND no attribute-scoping condition SAFELY constrains it: an AllowedAttributesForUpdate condition counts as safe only when its allowed set contains no sensitive attribute — a condition that allows custom:role does not make it safe.
Infrastructure control inspired by Doyensec "SCIM Hunting — Beyond SSO".

**Remediation:** Add an IAM Condition restricting the updatable attributes (cognito-idp:AllowedAttributesForUpdate) to the non-sensitive set the integration needs, or remove AdminUpdateUserAttributes if provisioning does not require attribute writes. Inspect attached managed policies (AmazonCognitoPowerUser grants cognito-idp:* unconstrained).

---

### CTL.IAM.ESCALATE.CONFUSED.CFN.UPDATE.001

**Principal Must Not Escalate via Existing CloudFormation Stack (Confused Deputy)**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5), CM-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5), CM-3; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with cloudformation:UpdateStack, CreateChangeSet, or ExecuteChangeSet on a SPECIFIC existing stack whose attached service role exceeds the principal's own permissions can escalate via the confused-deputy pattern. The stack's execution role was bound at creation time; UpdateStack with an attacker-controlled template runs that template under the existing role, deploying arbitrary AWS resources at the role's authority level. No iam:PassRole is required at update time because the role binding pre-existed the attack — that is precisely what makes this path invisible to controls focused on the create-and-pass primitive. The .present boolean is folded upstream from Stave's chain walker, which emits hops of type `cfn_update_existing` whenever this primitive matches.

**Remediation:** Scope cloudformation:UpdateStack / CreateChangeSet / ExecuteChangeSet away from this principal on the specific stack ARN, OR detach the over-privileged role from the stack via UpdateStack (--role-arn) and rebind a least-privilege role. For environments where stack updates must remain self-service, gate the action behind a Condition tying it to a specific change-set name pattern that an approval pipeline produces.

---

### CTL.IAM.ESCALATE.CONFUSED.LAMBDA.INVOKE.001

**Principal Must Not Escalate via Existing Lambda Function (Confused Deputy)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with lambda:InvokeFunction or lambda:UpdateFunctionCode on a SPECIFIC existing Lambda function whose execution role exceeds the principal's own permissions can escalate via the confused-deputy pattern. Distinct from the create-and-pass technique covered by CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001: this path requires NO iam:PassRole. The role binding pre-existed the attack — the principal needs only the trigger action against the specific function ARN. UpdateFunctionCode escalates by replacing the function's payload with attacker-controlled code that runs under the existing execution role; InvokeFunction escalates when the function already exposes data-exfil or privilege-mutation behavior to its caller. The .present boolean is folded upstream from Stave's chain walker, which emits hops of type `lambda_invoke_existing` whenever this primitive matches.

**Remediation:** Scope lambda:InvokeFunction and lambda:UpdateFunctionCode away from this principal on the specific function ARN, OR detach the over-privileged role from the function and bind a least- privilege role instead. If the function genuinely needs the elevated role, restrict invocation to a narrow IAM principal set (e.g., a specific application role) via the function's resource-based policy.

---

### CTL.IAM.ESCALATE.CREATEACCESSKEY.001

**Principal Must Not Escalate via iam:CreateAccessKey On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:CreateAccessKey` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can create a second access key for that user and authenticate as them immediately. The target user's password, console session, or MFA state is irrelevant; access keys are standalone long-lived credentials. This is Rhino Security Labs' credential-manipulation escalation technique and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The target user is limited to two access keys by AWS; when the victim already has two keys the attack requires an extra `DeleteAccessKey` call, which the `target_has_max_keys` diagnostic exposes.

**Remediation:** Scope `iam:CreateAccessKey` to the principal's own user ARN (or remove it entirely from non-admin principals). If a break-glass key-rotation workflow is needed, gate the permission through an assumed admin role rather than attaching it directly. Organization-level SCPs denying `iam:CreateAccessKey` on `${aws:PrincipalArn}` inversions are an effective perimeter control. Monitor `CreateAccessKey` calls in CloudTrail with an alert on any call where the subject user is not the caller.

---

### CTL.IAM.ESCALATE.CREATEACCOUNT.001

**Principal Must Not Escalate via Organizations CreateAccount**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI5; soc2: CC6.1;

Principals with organizations:CreateAccount can create new AWS accounts within the organization. The creator gets root access to the new account via the root email address. A new account starts with no SCPs applied beyond the default FullAWSAccess, providing unrestricted access until organizational policies are applied.

**Remediation:** Remove organizations:CreateAccount or restrict it to designated automation roles. Use AWS Control Tower or Organizations SCPs to enforce baseline guardrails on new accounts automatically. Require MFA and approval workflows for account creation.

---

### CTL.IAM.ESCALATE.CREATEGRANT.001

**Principal Must Not Escalate via KMS CreateGrant**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with kms:CreateGrant can delegate KMS key access to other principals without modifying the key policy. A grant allows the grantee to perform cryptographic operations (Decrypt, Encrypt, GenerateDataKey) on the key. An attacker with CreateGrant on a KMS key used for S3, RDS, or EBS encryption can grant themselves decrypt access, bypassing all IAM and bucket policies.

**Remediation:** Scope kms:CreateGrant to specific KMS keys via resource ARN conditions, or remove unrestricted kms:CreateGrant from the principal. If grants are operationally required, restrict the grantee principal via the kms:GranteePrincipal condition key.

---

### CTL.IAM.ESCALATE.CREATEINSTANCEPROFILE.001

**Principal Must Not Escalate via Instance Profile Creation and Association**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:CreateInstanceProfile, iam:AddRoleToInstanceProfile, and ec2:AssociateIamInstanceProfile can escalate by creating a new instance profile, attaching a powerful role, and associating it with an EC2 instance they control. The instance then receives credentials for the powerful role via IMDS. This is distinct from the RunInstances vector (which creates a new instance with a profile) — this vector modifies an existing instance. No iam:PassRole is required for the iam:AddRoleToInstanceProfile step.

**Remediation:** Remove iam:CreateInstanceProfile or ec2:AssociateIamInstanceProfile from the principal. If instance profile management is required, restrict the roles that can be added via IAM policy conditions on iam:AddRoleToInstanceProfile.

---

### CTL.IAM.ESCALATE.CREATELOGINPROFILE.001

**Principal Must Not Escalate via iam:CreateLoginProfile On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:CreateLoginProfile` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own AND who currently has no console login profile — can create a console password for that user and log in as them. Programmatic-only service accounts (no password set) are the specific target: the absence of a login profile is the precondition that makes `CreateLoginProfile` succeed. Once a profile exists, future takeover requires `UpdateLoginProfile` (covered by `CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001`). Rhino Security Labs enumerates this as a distinct technique because the victim population — service accounts that "can't be logged into as" — is often overlooked during permission review.

**Remediation:** Scope `iam:CreateLoginProfile` to the principal's own user ARN (or remove it entirely from non-admin principals). As a defensive measure, apply a service-control policy that denies `iam:CreateLoginProfile` for any user tagged `type = service` or similar. Alert on CloudTrail `CreateLoginProfile` events on long-dormant service users.

---

### CTL.IAM.ESCALATE.CREATEPOLICYVERSION.001

**Principal Must Not Escalate via iam:CreatePolicyVersion + iam:SetDefaultPolicyVersion**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with both `iam:CreatePolicyVersion` and `iam:SetDefaultPolicyVersion` on a managed policy attached to itself — directly or via a group it belongs to — can create a new version of that policy granting broader permissions and mark the new version default. Every attached principal, including the one that authored the change, picks up the new effective policy immediately. This is Rhino Security Labs privilege-escalation technique #5 ("IAM — CreatePolicyVersion"). The version mechanism makes the escalation subtle: policy ARN and attachments are unchanged; only the default version pointer moves.

**Remediation:** Remove one of the two permissions from the principal — `CreatePolicyVersion` alone cannot activate a new version, and `SetDefaultPolicyVersion` alone cannot author one. Or scope the Resource of both grants to policies that are not attached to the principal or to groups it belongs to. AWS-managed policies (`arn:aws:iam::aws:policy/*`) cannot have versions created by customer principals; this control specifically targets customer-managed policies.

---

### CTL.IAM.ESCALATE.DELETEBOUNDARY.001

**Principal Must Not Escalate via DeleteRolePermissionsBoundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:DeleteRolePermissionsBoundary can remove permission boundaries from IAM roles. Permission boundaries limit the maximum permissions a role can use regardless of its identity policies. Removing the boundary instantly expands the role's effective permissions to whatever its identity policies allow — potentially full admin access that was previously constrained by the boundary.

**Remediation:** Deny iam:DeleteRolePermissionsBoundary via SCP or scope it to specific role ARNs via resource conditions. Use SCPs to enforce that permission boundaries cannot be removed from roles in production accounts. Monitor boundary deletion attempts via CloudTrail.

---

### CTL.IAM.ESCALATE.ECRTOKEN.001

**Principal Must Not Escalate via ECR GetAuthorizationToken**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with ecr:GetAuthorizationToken can obtain a Docker credential that authenticates to ALL ECR repositories in the account — not just the repositories the principal's IAM policy specifies. The ECR authorization token is account-scoped, not repository-scoped. Repository-level IAM restrictions are bypassed by the Docker authentication layer. This is an AWS design behavior, not a bug.

**Remediation:** Restrict ecr:GetAuthorizationToken to principals that need Docker access. The token is account-scoped — it grants pull/push access to ALL ECR repositories, not just those in the principal's IAM policy.

---

### CTL.IAM.ESCALATE.EDITLAMBDA.001

**Principal Must Not Escalate via Editing Existing Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with lambda:UpdateFunctionCode on a function whose execution role exceeds the principal's permissions can escalate by modifying the function's code. The modified code runs under the existing execution role on the next invocation. Unlike PassRole-based Lambda escalation, this technique does not require iam:PassRole — the powerful role is already attached. The attacker only changes what code the role executes. Rhino Security Labs documents this as "EditExistingLambdaFunctionWithRole" and Prowler's iam_policy_allows_privilege_escalation enumerates it.

**Remediation:** Restrict lambda:UpdateFunctionCode to functions whose execution roles do not exceed the principal's permissions, or scope the function's execution role to least privilege. If broader UpdateFunctionCode is required for deployment workflows, add a Lambda resource-based policy denying UpdateFunctionCode from non-deployment principals, or use code signing (CTL.LAMBDA.CODESIGN.ENFORCE.001) to prevent unauthorized code changes.

---

### CTL.IAM.ESCALATE.EXECUTECOMMAND.001

**Principal Must Not Escalate via ECS ExecuteCommand**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with ecs:ExecuteCommand can open a shell session inside running ECS containers and access the task role credentials via the container metadata endpoint. This provides the same privilege escalation as PassRole+RunInstances but without needing PassRole — the container and its role already exist. The attacker executes commands as the container process and inherits whatever AWS permissions the task role provides.

**Remediation:** Remove ecs:ExecuteCommand or scope it to specific clusters and tasks via resource ARN conditions. If interactive debugging is required, restrict ExecuteCommand to non-production clusters and use session logging to CloudWatch for audit trails.

---

### CTL.IAM.ESCALATE.GETPASSWORDDATA.001

**Principal Must Not Escalate via EC2 GetPasswordData**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with ec2:GetPasswordData can retrieve the administrator password for any Windows EC2 instance. The password is encrypted with the key pair specified at launch. If the attacker also has access to the key pair or the key pair is widely shared, they gain RDP administrator access to the instance and inherit its network position and IAM role.

**Remediation:** Remove ec2:GetPasswordData or scope it to specific instance ARNs. GetPasswordData retrieves the administrator password for Windows instances encrypted with the launch key pair.

---

### CTL.IAM.ESCALATE.KMSKEYPOLICY.001

**Principal Must Not Escalate via KMS PutKeyPolicy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Principals with kms:PutKeyPolicy can replace the key policy on any KMS key within scope. The attacker adds themselves as a key user with kms:Decrypt permission. All data encrypted by the key — S3 objects, EBS volumes, RDS snapshots, Secrets Manager secrets — becomes decryptable. Unlike kms:CreateGrant which adds a temporary grant, PutKeyPolicy modifies the permanent authorization on the key.

**Remediation:** Remove kms:PutKeyPolicy or scope it to specific key ARNs. PutKeyPolicy modifies the permanent authorization on the key — the attacker adds themselves as a key user with Decrypt access.

---

### CTL.IAM.ESCALATE.LAMBDAADDPERM.001

**Principal Must Not Escalate via Lambda AddPermission**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with lambda:AddPermission can modify a Lambda function's resource-based policy to allow cross-account invocation. If the Lambda function has a privileged execution role, the attacker grants an external account permission to invoke the function, then invokes it from that account to execute code with the function's role permissions.

**Remediation:** Remove lambda:AddPermission or scope it to specific function ARNs via resource conditions. If cross-account invocation is required, use a dedicated automation role with narrowly-scoped permissions and audit Lambda resource policy changes via CloudTrail.

---

### CTL.IAM.ESCALATE.MODIFYINSTANCE.001

**Principal Must Not Escalate via EC2 ModifyInstanceAttribute**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with ec2:ModifyInstanceAttribute can modify an EC2 instance's user-data script. On the next instance reboot, the modified user-data executes with the instance profile role's permissions. The attacker injects a reverse shell or credential exfiltration script into user-data, reboots the instance, and gains the instance role's permissions.

**Remediation:** Remove ec2:ModifyInstanceAttribute or scope it to specific instance ARNs via resource conditions. Use launch templates with immutable user-data instead of allowing runtime modifications. Enforce instance metadata service v2 (IMDSv2) to limit credential access from injected scripts.

---

### CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001

**Principal Must Not Escalate via Auto Scaling Launch Configuration with PassRole**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus autoscaling:CreateLaunchConfiguration and autoscaling:CreateAutoScalingGroup can escalate to R's permissions even when ec2:RunInstances is explicitly denied. The principal creates a launch configuration specifying R as the instance profile, then creates an auto scaling group with min-size 1. The AWSServiceRoleForAutoScaling service-linked role launches the EC2 instance on the principal's behalf, bypassing any ec2:RunInstances deny. The principal gains shell access via user-data reverse shell, SSH key, or vulnerable AMI, then reads IMDS credentials for R. This technique was documented in the 2022 EC2 Auto Scaling privilege escalation research and is detected by PMapper.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove autoscaling:CreateLaunchConfiguration and autoscaling:CreateAutoScalingGroup. If auto scaling capability is required, enforce an instance-profile allowlist via a Condition on iam:PassRole (Condition.StringEquals: iam:PassedToService == ec2.amazonaws.com together with a narrowly-scoped Resource ARN).

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEDEVENDPOINT.001

**Principal Must Not Escalate via Glue CreateDevEndpoint Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus glue:CreateDevEndpoint can escalate to R's permissions by creating a Glue development endpoint that runs under R and then connecting to its SSH interface. The principal executes arbitrary code on the endpoint under R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique. SSH public-key registration on the endpoint is captured in the diagnostic fields so an operator can see how the principal would reach the running environment.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove glue:CreateDevEndpoint. If broader endpoint creation is required, enforce a service allowlist on iam:PassRole (`iam:PassedToService == glue.amazonaws.com` plus narrow Resource ARN set) and disable SSH access to dev endpoints via the `PublicKeys` restriction.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEENDPOINT.001

**Principal Must Not Escalate via SageMaker Inference Endpoint Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R and sagemaker:CreateEndpointConfig + sagemaker:CreateEndpoint can create a SageMaker endpoint configuration and endpoint under role R with an attacker-controlled model/container; the inference container runs as R, so it reads R's credentials from the container credential endpoint and exfiltrates them. The SageMaker compute executes under R, so any code or container the principal controls runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Same IAM structure as the other PassRole compute-execution controls (Lambda, EC2, Glue, CloudFormation, Data Pipeline) — only the SageMaker action differs. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation enumerate the SageMaker variants; Bishop Fox iam-vulnerable ships them as privesc-sageMaker* users.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict it with a Condition (`iam:PassedToService == sagemaker.amazonaws.com` plus a narrowly-scoped Resource ARN set). Alternatively remove the SageMaker create permission from non-admin principals, or use a permissions boundary on the passed role so the SageMaker compute cannot exceed least privilege.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001

**Principal Must Not Escalate via Lambda CreateFunction Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R, lambda:CreateFunction, and a path to invoke the function (lambda:InvokeFunction directly, creation of a function URL, or wiring to another trigger) can escalate to R's permissions. The created Lambda executes under R, so any code the principal uploads runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique. The invocation step is folded into the .present boolean upstream — a CreateFunction grant without any invocation path is not an escalation; the diagnostic fields expose which invocation vector was observed.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove lambda:CreateFunction. If broader function-creation is required for deployment workflows, restrict iam:PassRole with a Condition (`iam:PassedToService == lambda.amazonaws.com` plus a narrowly- scoped Resource ARN set). Alternatively, deny lambda:InvokeFunction and lambda:CreateFunctionUrlConfig on non-admin principals so the created function cannot be triggered.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEJOB.001

**Principal Must Not Escalate via Glue CreateJob Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R, glue:CreateJob or glue:UpdateJob, and glue:StartJobRun can escalate to R's permissions. The Glue job executes under R, so any ETL script the principal supplies runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Rhino Security Labs' CloudGoat (glue_privesc) documents this technique. The invocation step (StartJobRun) is folded into the .present boolean upstream — PassRole + CreateJob without a run path is not an escalation.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove glue:CreateJob/glue:UpdateJob. If Glue job authoring is required for ETL workflows, restrict iam:PassRole with a Condition on the target role ARN.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATENOTEBOOK.001

**Principal Must Not Escalate via SageMaker Notebook CreateNotebookInstance Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R and sagemaker:CreateNotebookInstance can create a SageMaker notebook instance under role R, then open the Jupyter UI (via sagemaker:CreatePresignedNotebookInstanceUrl) and run arbitrary code from a notebook cell or terminal with R's credentials, read from the instance metadata / attached role. The SageMaker compute executes under R, so any code or container the principal controls runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Same IAM structure as the other PassRole compute-execution controls (Lambda, EC2, Glue, CloudFormation, Data Pipeline) — only the SageMaker action differs. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation enumerate the SageMaker variants; Bishop Fox iam-vulnerable ships them as privesc-sageMaker* users.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict it with a Condition (`iam:PassedToService == sagemaker.amazonaws.com` plus a narrowly-scoped Resource ARN set). Alternatively remove the SageMaker create permission from non-admin principals, or use a permissions boundary on the passed role so the SageMaker compute cannot exceed least privilege.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEPIPELINE.001

**Principal Must Not Escalate via DataPipeline CreatePipeline Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus datapipeline:CreatePipeline and datapipeline:ActivatePipeline can escalate to R's permissions by defining pipeline actions that run under R. The activation step is what triggers execution; creation alone is not sufficient. Both permissions folded into the .present boolean upstream; the diagnostic fields expose which sub-conditions held. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate this technique.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove datapipeline:CreatePipeline or datapipeline:ActivatePipeline. If the DataPipeline service is not used, deny the entire datapipeline:* namespace at the SCP level; AWS Data Pipeline is in maintenance mode and new workloads are expected to use Step Functions or Glue instead, so a blanket deny is commonly safe.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATEPROCESSINGJOB.001

**Principal Must Not Escalate via SageMaker Processing CreateProcessingJob Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R and sagemaker:CreateProcessingJob can submit a SageMaker processing job under role R with an attacker-controlled container image; the processing container runs as R, so its entrypoint reads R's credentials from the container credential endpoint and exfiltrates them. The SageMaker compute executes under R, so any code or container the principal controls runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Same IAM structure as the other PassRole compute-execution controls (Lambda, EC2, Glue, CloudFormation, Data Pipeline) — only the SageMaker action differs. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation enumerate the SageMaker variants; Bishop Fox iam-vulnerable ships them as privesc-sageMaker* users.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict it with a Condition (`iam:PassedToService == sagemaker.amazonaws.com` plus a narrowly-scoped Resource ARN set). Alternatively remove the SageMaker create permission from non-admin principals, or use a permissions boundary on the passed role so the SageMaker compute cannot exceed least privilege.

---

### CTL.IAM.ESCALATE.PASSROLE.CREATESTACK.001

**Principal Must Not Escalate via CloudFormation CreateStack**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus cloudformation:CreateStack (without a condition that denies CAPABILITY_IAM / CAPABILITY_NAMED_IAM) can escalate to R's permissions by submitting a template that CloudFormation executes under R. When R's effective permissions exceed the principal's own, this is a privilege escalation path. The attacker submits a template that performs IAM mutations (attach user policy, put user policy, create access key), and CloudFormation executes those mutations under R. The principal never gains R directly — but gains R's authority through CloudFormation's template execution.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict cloudformation:CreateStack with a condition that denies CAPABILITY_IAM / CAPABILITY_NAMED_IAM. Alternatively, remove the escalation-enabling permissions from the target role (iam:PutUserPolicy, iam:AttachUserPolicy, iam:CreateAccessKey, iam:UpdateAssumeRolePolicy).

---

### CTL.IAM.ESCALATE.PASSROLE.CREATETRAININGJOB.001

**Principal Must Not Escalate via SageMaker Training CreateTrainingJob Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R and sagemaker:CreateTrainingJob can submit a SageMaker training job under role R with an attacker-controlled container image; the training container runs as R, so its entrypoint reads R's credentials from the container credential endpoint and exfiltrates them. The SageMaker compute executes under R, so any code or container the principal controls runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege escalation path. Same IAM structure as the other PassRole compute-execution controls (Lambda, EC2, Glue, CloudFormation, Data Pipeline) — only the SageMaker action differs. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation enumerate the SageMaker variants; Bishop Fox iam-vulnerable ships them as privesc-sageMaker* users.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or restrict it with a Condition (`iam:PassedToService == sagemaker.amazonaws.com` plus a narrowly-scoped Resource ARN set). Alternatively remove the SageMaker create permission from non-admin principals, or use a permissions boundary on the passed role so the SageMaker compute cannot exceed least privilege.

---

### CTL.IAM.ESCALATE.PASSROLE.RUNINSTANCES.001

**Principal Must Not Escalate via EC2 RunInstances Instance Profile**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R plus ec2:RunInstances can escalate to R's permissions by launching an EC2 instance with R as its instance profile and executing code on the instance via user-data (first-boot) or direct shell access. When R's effective permissions exceed the principal's own, the running instance can call the IMDS for temporary credentials under R and perform actions the original principal lacks — including IAM mutations if R carries them.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove ec2:RunInstances. If a broader instance-launch capability is required, enforce an instance-profile allowlist via a Condition on iam:PassRole (Condition.StringEquals: iam:PassedToService == ec2.amazonaws.com together with a narrowly-scoped Resource ARN).

---

### CTL.IAM.ESCALATE.PASSROLE.RUNTASK.001

**Principal Must Not Escalate via ECS Task Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R, ecs:RegisterTaskDefinition, and ecs:RunTask can escalate to R's permissions. RegisterTaskDefinition lets the caller define an arbitrary task container running under task role R; RunTask executes it. Any code the principal supplies runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege-escalation path — and on EC2 launch type, combined with an IMDS-exposed container instance (CTL.ECS.IMDS.INSTANCEROLE.001), it reaches the instance role too. The invocation step (RunTask) is folded into the .present boolean upstream. Permissions are resolved across inline + attached managed policies (ecs:*), so a role granted ECS admin still fires.
The ECS equivalent of CTL.IAM.ESCALATE.PASSROLE.SUBMITJOB.001; mirrors CTL.IAM.ESCALATE.PASSROLE.CREATEJOB.001 (Glue). Inspired by Doyensec CloudsecTidbits No. 3 (the pattern applies to ECS EC2 launch type). Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove ecs:RegisterTaskDefinition. If task authoring is required, restrict iam:PassRole with a Condition on the target role ARN.

---

### CTL.IAM.ESCALATE.PASSROLE.SENDCOMMAND.001

**Principal Must Not Escalate via SSM SendCommand On Privileged Instance**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with ssm:SendCommand or ssm:StartSession on an EC2 instance whose attached instance profile role R has broader effective permissions than the principal can escalate to R. The command or interactive session executes on the instance under R (the instance-profile role is the caller from the OS's perspective); IMDS reads from that session return R's temporary credentials. Rhino Security Labs' iam__privesc_scan lists this technique; the iam:PassRole check captured upstream corresponds to whether the principal can also attach alternate instance profiles, which widens the target-role set. Distinct from PASSROLE.RUNINSTANCES, which covers creating a fresh instance with an attacker-chosen profile; this covers exploiting an already-running one.

**Remediation:** Scope ssm:SendCommand and ssm:StartSession to instances whose instance-profile role does not exceed the principal's permissions. Use resource tags plus a Condition on ssm:resourceTag/<key> to bind the principal to a specific instance population. If the principal also has iam:PassRole reaching this or a broader role, also remove that grant — it enables replacing the instance profile entirely.

---

### CTL.IAM.ESCALATE.PASSROLE.SUBMITJOB.001

**Principal Must Not Escalate via Batch Job Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with iam:PassRole on a role R, batch:RegisterJobDefinition, and batch:SubmitJob can escalate to R's permissions. RegisterJobDefinition lets the caller define an arbitrary job container (image, command, env) running under R; SubmitJob executes it on the compute environment. Any code the principal supplies runs with R's authority. When R's effective permissions exceed the principal's own, this is a privilege-escalation path — and combined with an IMDS-exposed EC2 compute environment (CTL.BATCH.IMDS.JOBACCESS.001) it reaches the instance role too. The invocation step (SubmitJob) is folded into the .present boolean upstream — PassRole + RegisterJobDefinition without a run path is not an escalation. Permissions are resolved across inline + attached managed policies (batch:*, AWSBatchFullAccess), so a CI/CD role granted Batch admin for "convenience" still fires.
Mirrors CTL.IAM.ESCALATE.PASSROLE.CREATEJOB.001 (Glue). Inspired by Doyensec CloudsecTidbits No. 3 — Messing Around With AWS Batch For Privilege Escalations. Lab: github.com/doyensec/cloudsec-tidbits.

**Remediation:** Scope iam:PassRole to a role whose effective permissions do not exceed the principal's, or remove batch:RegisterJobDefinition. If Batch job authoring is required, restrict iam:PassRole with a Condition on the target role ARN.

---

### CTL.IAM.ESCALATE.PUTBUCKETPOLICY.001

**Principal Must Not Escalate via S3 PutBucketPolicy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with s3:PutBucketPolicy can replace any S3 bucket's resource policy. The attacker can grant themselves or an external account full access to the bucket, bypassing all IAM-based access controls. This is a resource policy mutation — the bucket policy is an independent authorization mechanism that grants access regardless of the caller's IAM policies.

**Remediation:** Remove s3:PutBucketPolicy or scope it to specific bucket ARNs via resource conditions. Use S3 Access Points with delegated access control instead of direct bucket policy modifications. Enforce bucket policy guardrails via SCP to prevent overly-permissive policies.

---

### CTL.IAM.ESCALATE.PUTGROUPPOLICY.001

**Principal Must Not Escalate via iam:PutGroupPolicy On A Belonging Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:PutGroupPolicy` whose Resource field includes a group the principal belongs to can write an arbitrary inline policy onto that group. Every member of the group — including the principal — inherits the inline policy immediately. This is Rhino Security Labs privilege-escalation technique #4 ("IAM — Put inline policy on group"). Mirrors PUTUSERPOLICY but via the group hop.
Scope: gated on `identity.kind == "user"`. IAM groups are a user-only concept — roles cannot belong to groups. No role-side analogue exists because AWS IAM does not have role groups.

**Remediation:** Scope `iam:PutGroupPolicy` to groups the principal does not belong to, or remove the permission from non-admin principals. SCP-level deny on `iam:PutGroupPolicy` where the target group contains the calling principal closes the path.

---

### CTL.IAM.ESCALATE.PUTROLEPOLICY.001

**Principal Must Not Escalate via iam:PutRolePolicy**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal (IAM user or role) holding `iam:PutRolePolicy` on a role it can reach can write an arbitrary inline policy onto that role — including one that grants `"Action": "*"` on `"Resource": "*"`. Two shapes share one outcome: a ROLE whose Resource field includes its own ARN self-writes admin (one step), or a USER with `iam:PutRolePolicy` scoped to a role it can assume writes an admin inline policy onto that role and then assumes it (the Rhino/Bishop Fox privesc12 technique). A single `PutRolePolicy` call produces full admin authority without touching any managed policy. Distinct AWS action from `iam:PutUserPolicy`, which targets users (see `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`) — this control covers `iam:PutRolePolicy` whether the holding principal is a user or a role. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation both enumerate it.

**Remediation:** Remove `iam:PutRolePolicy` from the role, or scope its Resource to role ARNs that do not include the role itself. Organization SCPs denying `iam:PutRolePolicy` on `${aws:PrincipalArn}` close the path at the boundary. A permissions boundary on the role that forbids self-write of inline policies is an additional defensive layer.

---

### CTL.IAM.ESCALATE.PUTUSERPOLICY.001

**Principal Must Not Escalate via iam:PutUserPolicy On Self**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:PutUserPolicy` whose Resource field includes its own user ARN can write an arbitrary inline policy onto itself — including one that grants `"Action": "*"` on `"Resource": "*"`. This is Rhino Security Labs privilege-escalation technique #2 ("IAM — Put inline policy on user") and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. A single PutUserPolicy call produces full admin access without touching any managed policy or group.
Scope: gated on `identity.kind == "user"`. The `iam:PutUserPolicy` AWS action targets users specifically — roles cannot be the self- target. The role-side analogue is `iam:PutRolePolicy` on self, a separate technique covered by its own `CTL.IAM.ESCALATE.PUTROLEPOLICY.001` control.

**Remediation:** Remove `iam:PutUserPolicy` from the principal, or scope the Resource field so the principal cannot include itself. Organization SCPs can deny `iam:PutUserPolicy` on `${aws:PrincipalArn}` to close the path at the boundary.

---

### CTL.IAM.ESCALATE.RESYNCMFADEVICE.001

**Principal Must Not Escalate via iam:ResyncMFADevice On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:ResyncMFADevice` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can resynchronize or manipulate that user's MFA device. In combination with a password reset (`iam:UpdateLoginProfile`, covered separately) this clears the MFA barrier on console login; on its own it enables temporary MFA bypass by forcing the device into a resync window where a chosen code pair is accepted. This is one of Rhino Security Labs' credential-manipulation techniques and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The finding fires whenever the permission reaches a privileged user; whether the attack has already been chained with a password reset is a RiskEngine-level compounding concern, not something the single-resource control gates on.

**Remediation:** Scope `iam:ResyncMFADevice` to the principal's own user ARN (or remove it from non-admin principals). MFA-device management is an admin-role operation; direct user grants for it are rarely intentional. Alert on CloudTrail `ResyncMFADevice` events where the subject user differs from the caller.

---

### CTL.IAM.ESCALATE.SAGEMAKER.PRESIGNEDURL.001

**Principal Must Not Escalate via sagemaker:CreatePresignedNotebookInstanceUrl**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with `sagemaker:CreatePresignedNotebookInstanceUrl` reaching an EXISTING SageMaker notebook instance whose execution role carries permissions exceeding the principal's own can escalate. The principal calls `CreatePresignedNotebookInstanceUrl` (often after `ListNotebookInstances`) to mint a presigned, pre-authenticated URL into the running notebook, opens the Jupyter UI, drops to a terminal, and reads the notebook's execution-role credentials from the Instance Metadata Service — then operates with that role's full authority. Unlike the SageMaker PassRole techniques (CreateNotebook/CreateTrainingJob/CreateProcessingJob, which spin up NEW compute with a passed role), this technique requires no `iam:PassRole`: it hijacks the identity of compute that already exists. It is the SageMaker analogue of `ssm:StartSession` and `ec2-instance-connect:SendSSHPublicKey` (access-existing-compute), not a PassRole-CreateX escalation. Bishop Fox iam-vulnerable ships it as privesc-sageMakerCreatePresignedNotebookURL.

**Remediation:** Scope `sagemaker:CreatePresignedNotebookInstanceUrl` to specific notebook ARNs via resource conditions, or deny it entirely for principals that should not reach privileged notebooks. Keep notebook execution roles least-privilege so a presigned URL yields no excess authority, restrict notebook network access (no direct internet / VPC-only), and prefer SageMaker Studio with scoped user profiles over long-lived notebook instances.

---

### CTL.IAM.ESCALATE.SENDSSHPUBLICKEY.001

**Principal Must Not Escalate via ec2-instance-connect:SendSSHPublicKey**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with `ec2-instance-connect:SendSSHPublicKey` reaching an EC2 instance whose instance-profile role carries permissions exceeding the principal's own can escalate. The principal pushes a temporary SSH public key to the instance via the EC2 Instance Connect API (valid ~60 seconds), opens an SSH session within that window, and reads the instance-profile role's credentials from the Instance Metadata Service (IMDS), then operates with that role's full authority. Unlike `ssm:SendCommand` / `ssm:StartSession` (control- plane code execution, no SSH), this technique establishes an interactive SSH session and requires no SSM agent — only that EC2 Instance Connect is installed on the instance. Rhino Security Labs' iam__privesc_scan and Prowler's iam_policy_allows_privilege_escalation enumerate it; Bishop Fox iam-vulnerable ships it as privesc-ec2InstanceConnect.

**Remediation:** Scope `ec2-instance-connect:SendSSHPublicKey` (and `SendSerialConsoleSSHPublicKey`) to specific instance ARNs via resource conditions, or restrict it with an `ec2:osuser` / `aws:ResourceTag` condition so it cannot reach instances whose instance-profile role exceeds the principal's permissions. Enforce IMDSv2 with a low hop limit (CTL.EC2.IMDS.HOPLIMIT.001) to raise the cost of credential theft, and prefer SSM Session Manager (logged, keyless) over EC2 Instance Connect where interactive access is required.

---

### CTL.IAM.ESCALATE.SERVICELINKEDROLE.001

**Principal Must Not Escalate via CreateServiceLinkedRole**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with unrestricted iam:CreateServiceLinkedRole can create AWS service-linked roles for any AWS service. Service-linked roles have AWS-managed permission policies that cannot be modified. Some service-linked roles have broad permissions — creating them introduces new roles with predefined access that the principal does not directly control.

**Remediation:** Scope iam:CreateServiceLinkedRole to specific services via the iam:AWSServiceName condition key. Restrict the condition to only the AWS services the principal legitimately needs to configure.

---

### CTL.IAM.ESCALATE.SNSADDPERM.001

**Principal Must Not Escalate via SNS AddPermission**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with sns:AddPermission can modify an SNS topic's resource-based policy to allow cross-account subscription or publishing. If the topic carries sensitive notifications (CloudWatch alarms, security findings, application events), the attacker grants an external account subscribe access to receive all messages.

**Remediation:** Remove sns:AddPermission or scope it to specific topic ARNs via resource conditions. Use SNS topic policies with explicit deny for cross-account access and monitor topic policy changes via CloudTrail.

---

### CTL.IAM.ESCALATE.SQSADDPERM.001

**Principal Must Not Escalate via SQS AddPermission**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with sqs:AddPermission can modify an SQS queue's resource-based policy to allow cross-account message consumption. If the queue processes sensitive data or triggers downstream workflows (Lambda, Step Functions), the attacker grants an external account access to consume or inject messages.

**Remediation:** Remove sqs:AddPermission or scope it to specific queue ARNs via resource conditions. Use SQS queue policies with explicit deny for cross-account access and enable SQS server-side encryption to protect message contents.

---

### CTL.IAM.ESCALATE.SSOOAUTH.001

**Principal Must Not Escalate via sso-oauth:CreateTokenWithIAM**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

An IAM principal has sso-oauth:CreateTokenWithIAM permission. This is the IAM-side gate for IAM Identity Center application impersonation — it allows the principal's compute (Lambda, ECS, EC2) to exchange an IdP token for SSO credentials on behalf of any user who authenticates to an Identity Center application. Combined with an application that has sso:account:access scope, this permission enables organization-wide privilege escalation: the compute can call GetRoleCredentials to assume any role the authenticated user has access to, in any account. The permission name suggests narrow SSO functionality; its actual effect is user impersonation across the entire organization.

**Remediation:** Remove sso-oauth:CreateTokenWithIAM from the principal's policies unless the principal's compute explicitly needs to broker user credentials. If the permission is required, scope the Resource to the specific application ARN that needs it — never use Resource: *. Audit which applications have sso:account:access scope to understand the blast radius.

---

### CTL.IAM.ESCALATE.STARTBUILD.001

**Principal Must Not Escalate via CodeBuild Source Injection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with codebuild:StartBuild on project P, plus write access to P's source repository (CodeCommit push, S3 PutObject on source bucket, or external Git write) or the ability to override P's buildspec on invocation, can escalate to P's service role by injecting a malicious buildspec. The buildspec runs inside CodeBuild under P's service role and can perform any action the role is authorised for. This vector does not require iam:PassRole — the service role is already attached to the project; the attacker only needs to change what it executes.

**Remediation:** Remove the principal's write access to the source that feeds the project, or remove codebuild:StartBuild from the principal, or reduce the project's service role to permissions that do not exceed the principal's. If source-write is intentional (as in developer workflows), scope the project's service role narrowly and rely on source-approval controls (e.g., CodeCommit approval rules) before a build can run.

---

### CTL.IAM.ESCALATE.STARTSESSION.001

**Principal Must Not Escalate via SSM StartSession**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with ssm:StartSession can open an interactive shell on any EC2 instance managed by SSM without needing SSH keys or security group rules. The session runs as root (or ssm-user) and can access the instance profile credentials from the IMDS. Unlike PassRole+RunInstances, the instance and its role already exist — the attacker just connects.

**Remediation:** Scope ssm:StartSession to specific instance ARNs via resource conditions. Use SSM Session Manager preferences to enforce session logging to CloudWatch and S3, and restrict session access via IAM policies with ssm:resourceTag conditions to limit which instances a principal can connect to.

---

### CTL.IAM.ESCALATE.UPDATEDEVENDPOINT.001

**Principal Must Not Escalate via Updating Existing Glue Dev Endpoint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Principals with glue:UpdateDevEndpoint on an existing Glue development endpoint can replace the SSH public key and connect to the endpoint. The endpoint runs under its attached IAM role. If the role's permissions exceed the principal's, this is a privilege escalation path. Unlike PassRole-based Glue escalation (which creates a new endpoint), this technique modifies an existing one — no iam:PassRole required. Rhino Security Labs documents this as "UpdateExistingGlueDevEndpoint". Note: AWS deprecated Glue dev endpoints in favor of interactive sessions, but existing endpoints remain operational.

**Remediation:** Remove glue:UpdateDevEndpoint from the principal, or reduce the endpoint's IAM role to least privilege. If the endpoint is no longer needed, delete it — AWS deprecated Glue dev endpoints in favor of interactive sessions. For active endpoints, restrict glue:UpdateDevEndpoint via IAM policy conditions.

---

### CTL.IAM.ESCALATE.UPDATEFUNCTIONCONFIG.001

**Principal Must Not Escalate via Lambda UpdateFunctionConfiguration**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

Principals with lambda:UpdateFunctionConfiguration can modify a Lambda function's environment variables, VPC configuration, and runtime settings without changing its code. Environment variables often contain secrets (API keys, database credentials, tokens). The attacker can exfiltrate these by adding an environment variable that sends secrets to an external endpoint, or modify VPC settings to route traffic through an attacker-controlled network.

**Remediation:** Remove lambda:UpdateFunctionConfiguration or scope it to specific function ARNs via resource conditions. Store secrets in AWS Secrets Manager or SSM Parameter Store instead of Lambda environment variables. Use Lambda resource policies and VPC endpoint policies to restrict network access.

---

### CTL.IAM.ESCALATE.UPDATELOGINPROFILE.001

**Principal Must Not Escalate via iam:UpdateLoginProfile On Another User**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:UpdateLoginProfile` whose Resource field reaches another IAM user — one whose attached permissions exceed the principal's own — can reset that user's console password to a chosen value and log in as them. MFA enrollment on the target user is NOT a barrier: an attacker with `iam:ResyncMFADevice` (covered by `CTL.IAM.ESCALATE.RESYNCMFADEVICE.001`) or `iam:DeactivateMFADevice` on the same user can disarm MFA first. This is Rhino Security Labs' credential-manipulation escalation technique and is covered by Prowler's iam_policy_allows_privilege_escalation and Pacu's iam__privesc_scan. The control requires the target user to already have a console login profile; the `CREATELOGINPROFILE.001` control covers the case where the target has no profile and one must be created.

**Remediation:** Scope `iam:UpdateLoginProfile` to the principal's own user ARN (or remove it entirely from non-admin principals). Enforce MFA on all console logins at the account level so password reset alone does not yield a session. Alert on CloudTrail `UpdateLoginProfile` events where the subject user differs from the caller.

---

### CTL.IAM.ESCALATE.UPDATETRUST.001

**Principal Must Not Escalate via iam:UpdateAssumeRolePolicy On A Broader Role**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal with `iam:UpdateAssumeRolePolicy` reaching a role whose attached permissions exceed its own can rewrite the role's trust policy to admit itself and then call `sts:AssumeRole` to pick up the broader permissions. The update is a single call and leaves the role's permissions unchanged — only the trust-policy pointer moves — which makes the escalation subtle in post-incident review. This is Rhino Security Labs' two-step role-assumption pattern. Listed as a distinct control from CTL.IAM.ESCALATE.ASSUMEROLE.001 because the remediations are different: this control is fixed by removing `iam:UpdateAssumeRolePolicy` from the principal or narrowing its Resource; ASSUMEROLE is fixed by removing `sts:AssumeRole` or narrowing target trust.

**Remediation:** Remove `iam:UpdateAssumeRolePolicy` from the principal, or scope its Resource field to roles whose permissions do not exceed the principal's (role-creation bootstrap roles, for example). At the organization level, deny `iam:UpdateAssumeRolePolicy` on privileged roles via SCP, or enforce a permissions boundary that forbids it. CloudTrail alerting on `UpdateAssumeRolePolicy` calls is an effective detective control while the preventive change lands.

---

### CTL.IAM.FEDERATION.001

**IAM Console Users Should Use Identity Federation**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws: 1.21; nist_800_53_r5: IA-2; owasp_nhi: NHI3;

IAM users with console access should authenticate through identity federation rather than IAM-native passwords. Federated authentication centralizes identity management in the organization's identity provider and enforces consistent MFA, password policies, and session controls. IAM-native console users maintain a separate credential that bypasses the organization's identity governance — password resets, MFA enrollment, and access reviews must be managed independently in each AWS account. When console users authenticate directly through IAM, credential lifecycle management fragments across accounts and centralized access revocation requires visiting every account individually. Identity federation eliminates the IAM password as an attack surface and ensures that disabling a user in the identity provider immediately revokes AWS console access.

**Remediation:** Configure identity federation using AWS IAM Identity Center or a direct SAML/OIDC integration with the organization's identity provider. Migrate console users to federated access by creating corresponding identities in the identity provider. After verifying federated access works, remove the IAM console passwords from the migrated users. Retain IAM-native access only for break-glass emergency accounts.

---

### CTL.IAM.FEDERATION.ROLEMAPPING.001

**Federated Role Must Be Scoped to Specific IdP Groups**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Federated role trust policy allows any federated user to assume the role — not scoped to specific IdP groups or attributes. Any user who authenticates via the IdP can assume the role regardless of their group membership or job function.

**Remediation:** Add a condition to the role trust policy that restricts assumption to specific IdP groups or attributes. For SAML, add a StringEquals condition on the SAML:NameQualifier or group attribute. For OIDC, scope the sub claim to specific groups.

---

### CTL.IAM.FEDERATION.SAML.AUDIENCE.001

**SAML Trust Must Validate Audience Restriction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-8; owasp_nhi: NHI3; soc2: CC6.1;

SAML trust policy does not validate the audience restriction in assertions. Without audience validation, a SAML assertion intended for a different service provider can be replayed against AWS. The assertion is valid — signed by the IdP — but was meant for a different application.

**Remediation:** Configure the SAML trust to validate the audience restriction field in assertions. Set the audience to the AWS SAML endpoint URL for the account. Verify that assertions from other service providers are rejected.

---

### CTL.IAM.FEDERATION.SAML.CERT.001

**SAML Provider Certificate Must Be Rotated Within 365 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-5; owasp_nhi: NHI3; soc2: CC6.1;

SAML provider certificate is older than 365 days. The certificate authenticates the IdP to AWS. If the certificate's private key is compromised, an attacker can forge SAML assertions and assume any role that trusts the SAML provider. The SolarWinds/Nobelium attack (Golden SAML) used forged SAML tokens via compromised AD FS signing certificates.

**Remediation:** Generate a new signing certificate in the IdP, update the SAML provider metadata in AWS IAM, and verify federation still works. Remove the old certificate from both IdP and AWS after rollover.

---

### CTL.IAM.FEDERATION.SESSION.DURATION.001

**Federated Role Session Duration Must Not Exceed 4 Hours**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI3; soc2: CC6.1;

Federated role maximum session duration exceeds 4 hours. Federation sessions persist after the IdP revokes access. If a user is terminated in the IdP, their AWS session continues until expiry. A 12-hour session means a terminated employee retains AWS access for up to 12 hours after termination.

**Remediation:** Reduce the maximum session duration for federated roles to 4 hours or less. Use aws iam update-role --max-session-duration 14400 to set the limit. For sensitive roles, consider 1-hour sessions with re-authentication.

---

### CTL.IAM.FEDERATION.SESSIONTAG.001

**Federated Role Must Require Session Tags**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI3; soc2: CC6.2;

Federated role trust policy does not require session tags. Without session tags, federated sessions are not attributed to specific user identities in the IdP. CloudTrail shows the role ARN and session name but no IdP-side identity attributes. Session tags propagate IdP attributes into the AWS session for attribution and ABAC.

**Remediation:** Add sts:TagSession permission and required tag conditions to the role trust policy. Configure the IdP to pass user identity attributes (email, department, team) as session tags in the SAML assertion or OIDC token.

---

### CTL.IAM.FOOTHOLD.CICD.TRIPLE.001

**CI/CD Deploy Role Must Not Hold CloudFormation + IAM + Secrets Together**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

A single CI/CD deploy role whose effective permissions span all three of CloudFormation, IAM, and Secrets Manager has effective control of the entire environment: it can create infrastructure, modify identity, and read secrets. Any one of the three is normal for a pipeline — the conjunction is the foothold. The role is classified CI/CD when its trust policy admits a CI principal (GitHub Actions OIDC token.actions.githubusercontent.com, CodeBuild, CodePipeline, GitLab, CircleCI, Jenkins) or its name matches a CI pattern (*deploy*, *cicd*, *pipeline*, *build*, *github-actions*). The three effective-access signals are derived from inline + attached managed policies + permission boundaries, so wildcard (cloudformation:*) and specific (cloudformation:CreateStack) grants both resolve to the same boolean.

**Remediation:** Split the pipeline's privileges across separate roles: an infrastructure-deploy role (CloudFormation) distinct from any identity-management step (IAM) and from secret access (Secrets Manager). Scope each to the specific stacks, roles, and secrets it needs, and never grant all three to one role.

---

### CTL.IAM.FOOTHOLD.INTERNET.SENSITIVE.001

**Internet-Facing Compute Identity Must Not Reach Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

No IAM role attached to internet-facing compute may have transitive reach to a sensitive resource. Internet-facing compute is an EC2 instance with a public IP (or in a public subnet), an ECS task behind a public load balancer, or a Lambda with a Function URL or API Gateway trigger. Sensitive resources are Secrets Manager secrets, customer-managed KMS keys, RDS instances/clusters, and S3 buckets tagged sensitive/pii/confidential/restricted/high. Reach is any path — direct permission, sts:AssumeRole chain, iam:PassRole, or a resource-based policy grant — from the internet-facing role to the sensitive resource.
This control reads the `identity.reaches_sensitive` signal, which the graph layer derives by full reachability (direct AND transitive). The companion Soufflé + Z3 reasoning spec (examples/iam-foothold-internet-reach) computes that signal and proves it three ways; this per-resource control surfaces the derived verdict in the catalog. The two-hop case (role → AssumeRole → intermediate role → secret) resolves to `reaches_sensitive: true`, so it is caught here exactly like the direct case.
Fail-loud: if `identity.internet_facing` cannot be determined from the snapshot, the collector MUST populate it as the explicit unknown sentinel and surface it — it must never silently default to false (which would hide an internet-facing role). This control assumes the signal is populated.

**Remediation:** Break the path: remove the internet-facing compute's role access to the sensitive resource, or insert an isolation boundary (a non-internet-facing intermediary the public workload cannot assume). Prefer short-lived, narrowly-scoped credentials fetched at request time over a standing path from a public workload to a secret. Re-run the reachability spec to confirm UNSAT (no path).

---

### CTL.IAM.GROUP.EMPTY.001

**IAM Group Has Policies But No Members**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2(3); nist_800_53_r5: AC-2(3); soc2: CC6.3;

An IAM group has attached policies (managed or inline) but no members. The group's permissions serve no operational purpose. If the group has admin-level policies, adding a user to it grants admin — the orphaned group is a latent escalation path via AddUserToGroup (technique #13 in the Stave escalation catalog).

**Remediation:** Remove policies from empty groups or delete the group. Empty groups with admin-level policies are latent escalation paths via AddUserToGroup.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.001

**Role Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles must not be able to reach more than 50 resources through direct permissions and transitive role assumption chains. A role with wide blast radius means a single credential compromise gives an attacker access to a large surface area. The extractor computes reachable resources by traversing sts:AssumeRole edges and collecting data access permissions per reachable role.

**Remediation:** Reduce the role's permissions to the minimum set of resources required. Split broad roles into per-service roles with scoped Resource ARNs. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.002

**Cross-Account Role Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account blast radius (can reach resources in other AWS accounts) must require an external ID condition on the trust policy. Without an external ID, any principal in the trusted account can assume the role — including compromised service accounts and test tenants. Combined with cross-account reach, this is the maximum blast radius configuration.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Restrict the trust to specific role ARNs rather than account-wide principals. Review cross-account access grants for least privilege.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.003

**Role Assume Chain Must Not Exceed Depth Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM role assumption chains must not exceed 2 hops. Deep chains (Role A assumes Role B which assumes Role C) create hidden transitive access that is difficult to audit and often exceeds the intended permissions of the originating principal. Each hop in the chain potentially widens the blast radius.

**Remediation:** Flatten the role assumption chain. Grant permissions directly to the role that needs them rather than chaining through intermediate roles. Use service-linked roles where possible to avoid manual chain construction.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.004

**Role Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

IAM roles must have access to fewer than 20 resources classified as sensitive (PHI, PII, confidential). A role that can reach 85 sensitive resources is a qualitatively different risk than one that reaches 5 — credential compromise exposes a proportionally larger data surface. The extractor counts unique sensitive resources reachable through the role's attached and inline policies.

**Remediation:** Split broad roles into per-service roles scoped to specific resource ARNs. Use IAM Access Analyzer to identify unused permissions on sensitive resources. Apply permissions boundaries that restrict access to classified data.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.005

**User Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM users must not be able to reach more than 50 resources through their attached and inline policies. A user with wide blast radius means a single credential compromise — leaked access keys, phishing, stolen browser session — gives an attacker access to a large surface area. Iski's disclosure (April 2025) demonstrated this: an IAM user (dev-test) with long-term access keys and s3:GetObject / s3:ListBucket across multiple production buckets (vpc-logs-production, user-backups-staging, cdn-assets-public) was the precondition that turned a credential leak in a frontend CSS file into a full data breach. The user was not an admin; the leak was out-of-band from AWS configuration; but the breadth of AWS-side permissions made exploitation trivial. This is the user-kind equivalent of CTL.IAM.IDENTITY.BLASTRADIUS.001 for roles.

**Remediation:** Reduce the user's permissions to the minimum set of resources required. Split broad permissions into scoped Resource ARNs. Move programmatic workloads off long-term user access keys onto service-linked roles or IAM Roles Anywhere. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.006

**User Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); hipaa: 164.312(a)(1); nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

IAM users must have access to fewer than 20 resources classified as sensitive (PHI, PII, confidential). A user that can reach 85 sensitive resources is a qualitatively different risk than one that reaches 5 — credential compromise exposes a proportionally larger data surface. This is the user-kind equivalent of CTL.IAM.IDENTITY.BLASTRADIUS.004 for roles. Iski's disclosure (April 2025) showed the Iski pattern: a user with read access to user-backups-staging — which held production database backups and user PII — turned a leaked access key into a full PII breach. The extractor counts unique sensitive resources reachable through the user's attached and inline policies.

**Remediation:** Split broad user permissions into scoped Resource ARNs. Move programmatic access onto service-linked roles with tightly-scoped trust policies. Use IAM Access Analyzer to identify unused permissions on sensitive resources. Apply permissions boundaries that restrict access to classified data.

---

### CTL.IAM.IDENTITY.ROOTACCOUNT.001

**IAM Users Created in Management Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.1; nist_800_53_r5: AC-6(5); soc2: CC6.1;

IAM users exist in the AWS management (root) account of the organization. The management account should have minimal IAM users — ideally only break-glass accounts. Day-to-day access should be through SSO to member accounts. IAM users in the management account have access to organizational controls (SCPs, account creation, billing).

**Remediation:** Remove non-break-glass IAM users from the management account. Use SSO to member accounts for day-to-day access. Keep only emergency break-glass accounts in the management account.

---

### CTL.IAM.IDENTITY.USERS.EXCESSIVE.001

**Excessive IAM Users in Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; nist_800_53_r5: AC-2; owasp_nhi: NHI1; soc2: CC6.1;

More than 20 IAM users in the account. Large numbers of IAM users indicate that human access is managed through IAM users instead of federation (SSO/SAML/OIDC). IAM users require individual credential management, individual MFA enrollment, and individual access key rotation. Federation centralizes all of this in the identity provider.

**Remediation:** Migrate IAM users to AWS IAM Identity Center (SSO) federation. Use IAM roles for service-to-service access. Target fewer than 20 IAM users per account.

---

### CTL.IAM.INCOMPLETE.001

**Complete Data Required for IAM Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

IAM account safety cannot be proven when root account MFA status or access key data is missing from the snapshot. The extractor must populate identity.root.mfa_enabled and identity.root.has_access_keys.

**Remediation:** Re-run the extractor with IAM permissions: iam:GetAccountSummary, iam:GenerateCredentialReport, iam:ListMFADevices.

---

### CTL.IAM.LIGHTSAIL.CREDENTIAL.CREATE.001

**IAM Policy Grants Lightsail Credential Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI1; soc2: CC6.3;

An IAM principal has a policy granting lightsail:CreateBucketAccessKey. This allows creating S3-compatible access keys outside the IAM credential lifecycle — invisible to credential reports, rotation policies, and inventory tools. This is a privilege escalation vector: the attacker converts IAM-governed access into a shadow credential that survives key rotation and even IAM user deletion.

**Remediation:** Remove lightsail:CreateBucketAccessKey from the principal's policies.

---

### CTL.IAM.LIST.RESTRICT.001

**IAM Policies Must Not Grant Broad iam:List* Without Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1069.003; nist_800_53_r5: AC-6;

IAM policies must not grant broad iam:List* permissions without resource scope constraints. Unrestricted iam:List* access allows enumeration of all IAM users, roles, groups, and policies in the account. Attackers use this to map the identity surface and identify over-privileged roles or misconfigured trust policies for privilege escalation targeting.

**Remediation:** Scope iam:List* actions to specific resource ARNs. Replace wildcard iam:List* with the specific list actions required by the workload (e.g., iam:ListRolePolicies on a single role ARN). Apply conditions such as aws:ResourceTag to limit enumeration scope.

---

### CTL.IAM.MARKER.PRODUCTION.001

**IAM Role Tagged environment=production (Marker)**

- **Severity:** low
- **Type:** marker
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2(7); soc2: CC6.1;

Fact-recording marker for IAM roles tagged environment=production (or equivalent production-tier tag). Emits an informational finding (NOT a violation) on every production-tagged role so cross-resource chains can compose it with development-side controls. Examples: a SageMaker notebook role with sts:AssumeRole pointing at a production role; a Lambda execution role that can AssumeRole into a production database role; a CodeBuild role that can deploy to production endpoints. Production tagging on its own is the desired state — never a finding to triage. The marker exists so the chain engine can join "violation on the development side: this identity can reach production" with "the target is production" without forcing the collector to denormalise every dev→prod join shape into a per-asset boolean.

**Remediation:** None. This marker exists as a chain-detection ingredient. To suppress noise on dashboards, filter findings by control_id when rendering Findings — markers should appear in a separate "facts" panel rather than the violation list.

---

### CTL.IAM.MFA.ACCESSKEY.BYPASS.001

**MFA Enabled but Access Keys Bypass MFA Enforcement**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.4; hipaa: 164.312(d); nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.4.1; soc2: CC6.1;

An IAM user has MFA enabled for console login and also has active access keys, but the user's policies do not enforce aws:MultiFactorAuthPresent for API/CLI access. MFA protects the console session but API calls via the access key bypass MFA entirely — the credential alone is sufficient. The user appears MFA-protected in audit output, but an attacker who obtains the access key has full API access without a second factor. The compound failure: MFA is console-only, and the access key is an unprotected backdoor to the same permissions.

**Remediation:** Add an aws:MultiFactorAuthPresent condition to the user's IAM policies for destructive actions, or remove access keys if the user only needs console access. For programmatic access, use temporary credentials via IAM Identity Center or AssumeRole with MFA.

---

### CTL.IAM.MFA.HWKEY.001

**Privileged Accounts Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; owasp_nhi: NHI4; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

IAM users with admin access must use a hardware MFA device (FIDO2, YubiKey, Gemalto), not a virtual MFA app or SMS. Virtual MFA can be compromised through device theft, seed extraction, or SIM swap attacks. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identities.

**Remediation:** Replace virtual MFA with a hardware FIDO2 or TOTP device. Remove the existing virtual MFA device and enroll a hardware token via IAM > Users > Security credentials > MFA.

---

### CTL.IAM.NEP.ADMIN.001

**Net Effective Permissions Must Not Include Admin-Equivalent Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

After resolving all policy layers (SCPs, permission boundaries, identity-based policies, explicit denies), a principal not designated as administrative must not have admin-equivalent effective permissions. This is distinct from CTL.IAM.POLICY.ADMIN.001 which checks policy content — this control checks the resolved effective permissions after organizational constraints are applied. A principal may have an AdminAccess policy attached but be effectively constrained by an SCP.

**Remediation:** Review the identity-based policies granting admin-equivalent actions. Apply an SCP or permission boundary to constrain the effective permissions. If the principal requires admin access, tag it with stave/role-type: administrative to document the intent.

---

### CTL.IAM.NEP.BOUNDARY.001

**Permission Boundaries Must Meaningfully Constrain Effective Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

A principal with a permission boundary must have a boundary that meaningfully constrains its effective permissions. A boundary that allows iam:* or *:* on Resource: * is not a meaningful constraint. A boundary that is broader than the identity-based policy constrains nothing. Both conditions create a false sense of security — the boundary exists but provides no actual restriction.

**Remediation:** Review the permission boundary policy. Narrow it to exclude iam:* and *:* on Resource: *. Ensure the boundary is stricter than the identity-based policies — a boundary that is broader than the identity policy constrains nothing.

---

### CTL.IAM.NEP.ESCALATION.001

**No Principal May Have Net Effective Permissions to Escalate Privileges**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

After resolving all policy layers including transitive role assumption chains, no non-administrative principal may have effective permissions to escalate beyond their intended privilege scope. Escalation is detected in two forms: direct escalation primitives (iam:CreatePolicyVersion, iam:AttachRolePolicy, etc.) in the resolved effective allow set, and transitive escalation through role chains that reach higher privilege levels than the principal's direct permissions. A developer role that can assume a pipeline role that can assume an admin role has effective admin access — neither individual role appears dangerous, but the chain is the finding.

**Remediation:** For direct primitives: remove or scope the escalation action to specific resource ARNs. For transitive chains: remove the sts:AssumeRole grant that enables the chain, or scope it to specific non-admin role ARNs.

---

### CTL.IAM.NEP.PHI.001

**Only Designated Principals May Have Net Effective Access to PHI Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

For each resource tagged data-classification: phi, the complete set of principals with resolved effective access — via identity-based policies AND resource-based policies — must be limited to principals designated as PHI-authorized. A non-designated principal with effective read access to PHI data is a breach path regardless of how it was granted. This control resolves the complete multi-layer access picture including identity policies, SCPs, permission boundaries, and resource policies simultaneously. Cross-account resource policy grants on PHI are the highest-severity variant.

**Remediation:** Review the access path. For identity-based grants: restrict the principal's policies or add an SCP denying PHI resource access for non-designated principals. For resource policy grants: update the resource policy to restrict the Principal list to designated role ARNs. For public policies: remove the Principal: * statement.

---

### CTL.IAM.OAUTH.DELEGATIONBLAST.001

**Elevated Identity Must Not Delegate Permissions via OAuth**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An IAM identity has signin:CreateOAuth2Token permission AND elevated or admin effective permissions. Any agent operating under an OAuth token issued by this identity inherits the full permission scope. The risk is the blast radius of delegation — an identity with AdministratorAccess or service-wildcard grants that can also issue OAuth tokens creates a path where a compromised or misconfigured agent operates with privileges far beyond what the agent task requires.
This fires regardless of grant type (authorization_code or client_credentials) because the risk is the same whether a human clicked a browser button or a machine exchanged SigV4 credentials.
Note: this evaluation does not credit SCP-based OAuth restrictions that use condition keys. If your organization uses SCPs with signin:OAuthGrantType conditions, this finding may not apply.

**Remediation:** Create a dedicated role with minimum permissions required for the agent's task and grant signin:CreateOAuth2Token only to that role. Do not grant OAuth token creation to identities with admin or elevated permissions. If this identity must retain broad permissions, remove its ability to issue OAuth tokens.

---

### CTL.IAM.OAUTH.INVENTORY.001

**Identity Has OAuth MCP Server Capability**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CM-8(3); soc2: CC6.1;

An IAM identity has one or more of the four signin: OAuth actions (AuthorizeOAuth2Access, CreateOAuth2Token, IntrospectOAuth2Token, RevokeOAuth2Token). This is an inventory control — it surfaces which identities participate in OAuth delegation so defenders can review the set. The signin: action namespace was introduced on July 9, 2026; identities may have acquired these permissions via wildcard grants (signin:* or *) without explicit intent.

**Remediation:** Verify that this identity requires OAuth access to the AWS MCP Server. If not, remove the signin: actions. If access was granted via a wildcard (signin:* or *), consider narrowing to explicit actions with appropriate condition keys.

---

### CTL.IAM.OAUTH.MANAGEDPOLICY.001

**AWSMCPSignInOAuthAccessPolicy Attachment Must Be Reviewed**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CM-8(3); soc2: CC6.1;

An IAM identity has the AWSMCPSignInOAuthAccessPolicy managed policy attached. This AWS-managed policy grants OAuth access to the AWS MCP Server. Review whether this identity requires OAuth agent authorization — the policy was introduced on July 9, 2026, and attachment may be unintentional or overly broad.
This is an awareness control. The finding is informational — it surfaces which identities have the policy so defenders can review intentionality and verify that condition-key constraints are applied elsewhere (via SCP or inline policy conditions).

**Remediation:** Verify that this identity requires OAuth access to the AWS MCP Server. If not, detach the policy. If access is intended, ensure condition-key constraints (signin:OAuthRedirectUri, signin:OAuthGrantType) are applied via SCP or supplementary inline policy.

---

### CTL.IAM.OAUTH.NOINTROSPECTION.001

**Account Must Have OAuth Token Introspection Capability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2(1); soc2: CC6.1;

No identity in this account has signin:IntrospectOAuth2Token permission, but at least one identity has OAuth grant permissions (signin:AuthorizeOAuth2Access or signin:CreateOAuth2Token). Token status cannot be validated during incident response — defenders cannot determine whether a token is active, what scopes it has, or when it expires.

**Remediation:** Grant signin:IntrospectOAuth2Token permission to at least one security or incident response role. Consider pairing with signin:RevokeOAuth2Token for a complete token lifecycle management capability.

---

### CTL.IAM.OAUTH.NOREVOCATION.001

**Account Must Have OAuth Token Revocation Capability**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2(1); nist_800_53_r5: AC-2(1); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No identity in this account has signin:RevokeOAuth2Token permission, but at least one identity has OAuth grant permissions (signin:AuthorizeOAuth2Access or signin:CreateOAuth2Token). If an OAuth token is compromised, no one can revoke it. This is analogous to having IAM credentials without the ability to deactivate access keys.
This control evaluates at the account level — it fires on the account asset when the account has OAuth-capable identities but no revocation-capable identity.

**Remediation:** Grant signin:RevokeOAuth2Token permission to at least one security or break-glass role. Consider granting both signin:RevokeOAuth2Token and signin:IntrospectOAuth2Token to an incident response role.

---

### CTL.IAM.OAUTH.UNCONSTRAINEDAUTHORIZE.001

**OAuth Authorize Access Must Have Redirect URI Constraint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An IAM identity has signin:AuthorizeOAuth2Access permission without a signin:OAuthRedirectUri condition. Without this condition, OAuth tokens can be delivered to arbitrary endpoints — an attacker who compromises the role's credentials can redirect authorization tokens to infrastructure they control. The signin:OAuthRedirectUri condition restricts delivery to http://localhost:* for local development or to specific hosted provider URIs.
Note: this evaluation does not credit SCP-based OAuth restrictions that use condition keys. If your organization uses SCPs with signin:OAuthRedirectUri conditions, this finding may not apply.

**Remediation:** Add a signin:OAuthRedirectUri condition to the policy statement granting signin:AuthorizeOAuth2Access. For local development, constrain to http://localhost:* or http://127.0.0.1:*. For hosted MCP providers, constrain to the specific provider callback URI.

---

### CTL.IAM.OAUTH.UNSCOPEDRESOURCE.001

**OAuth Authorize Must Be Scoped to MCP Service Principal**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An IAM identity has signin:AuthorizeOAuth2Access with Resource: * rather than scoped to the MCP service principal ARN (arn:aws:signin:*:*:service-principal/aws-mcp.amazonaws.com). An unscoped resource permits authorization against any service principal registered in the signin namespace — current and future.

**Remediation:** Scope the Resource field to arn:aws:signin:*:*:service-principal/aws-mcp.amazonaws.com to limit authorization to the intended service.

---

### CTL.IAM.OAUTH.WILDCARDGRANT.001

**OAuth Permissions Must Not Come From Wildcard Action**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An IAM identity has OAuth MCP Server permissions via a wildcard action (signin:* or *). This is likely an unintentional grant — the signin:AuthorizeOAuth2Access and signin:CreateOAuth2Token actions were introduced on July 9, 2026. Any policy with signin:* or * in the Action field now implicitly grants OAuth agent authorization.
The wildcard grant is dangerous because the identity owner may not know they have OAuth permissions. Unlike explicit grants, wildcards are not reviewed when new actions are added to a namespace.

**Remediation:** Replace the wildcard action with explicit action grants. If OAuth access is intended, grant signin:AuthorizeOAuth2Access and signin:CreateOAuth2Token explicitly with appropriate condition keys. If not intended, narrow the Action field to exclude the signin: namespace.

---

### CTL.IAM.ORG.DELEGATED.001

**Delegated Administrator Has Excessive Permissions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

A delegated administrator account for an AWS service has permissions beyond what the delegated service requires. Delegated administrators manage AWS services across the organization. If the delegated admin account has excessive permissions, compromising the account gives the attacker organizational control beyond the intended delegation scope.

**Remediation:** Scope the delegated administrator account permissions to only the actions required by the delegated service. Remove AdministratorAccess or broad cross-account role assumption permissions.

---

### CTL.IAM.ORG.MGMT.PRINCIPALS.001

**Management Account Has Workload IAM Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

The AWS management account has IAM users or roles beyond the minimum break-glass set. The management account is exempt from all SCPs by AWS design — every principal in this account has unrestricted access to organization-wide actions that SCPs deny for member accounts. When the management account runs workloads or has non-administrative principals, the SCP security perimeter has an unprotected hole: any compromised principal in the management account bypasses every SCP guardrail. The management account should contain only break-glass roles and organization management automation, with no human users or workload roles.

**Remediation:** Move all workloads and non-administrative IAM users/roles out of the management account into dedicated member accounts. Keep only break-glass roles and organization management automation in the management account.

---

### CTL.IAM.PASSROLE.PRODUCTION.001

**PassRole Must Not Target Production Execution Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role's iam:PassRole Resource element targets a production execution role. A principal with this permission can deploy compute resources (Lambda, SageMaker, ECS, CodeBuild) using production credentials — reaching production data, secrets, and infrastructure without any promotion gate. This is the bridge between a development notebook and a production data breach: the principal passes the production role to a new resource and operates with full production authority.

**Remediation:** Restrict the iam:PassRole Resource element to non-production role ARNs. Use separate roles for development and production, and gate production PassRole behind an approval workflow or break-glass procedure. Add an iam:PassedToService condition to further restrict which service can receive the role.

---

### CTL.IAM.PASSWORD.COMPLEXITY.001

**Password Policy Must Require All Character Types**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require uppercase, lowercase, numbers, and symbols. Missing any character type requirement reduces the keyspace and makes passwords easier to crack.

**Remediation:** Update the IAM password policy to require all four character types.

---

### CTL.IAM.PASSWORD.EXPIRATION.001

**Password Policy Must Enforce Expiration Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.11; cis_aws_v3.0: 1.11; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); iso_27001_2022: A.5.17; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM account password policy must enforce password expiration within 90 days. Two unsafe states: max_password_age = 0 (passwords never expire, credentials valid indefinitely) or max_password_age > 90 (expiration too infrequent, exceeds CIS AWS Foundations Benchmark threshold). Either gives compromised passwords an unnecessarily long validity window.

**Remediation:** Set password expiration to 90 days or less: aws iam update-account-password-policy --max-password-age 90

---

### CTL.IAM.PASSWORD.LENGTH.001

**Password Minimum Length Must Be At Least 14**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.8; cis_aws_v3.0: 1.8; fedramp_moderate: IA-5(1); ffiec: CAT-D3; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.3; pci_dss_v4.0: 8.3.6; soc2: CC6.1;

The IAM account password policy must require a minimum password length of 14 characters. Shorter passwords are vulnerable to brute-force and dictionary attacks.

**Remediation:** Update the IAM account password policy to require at least 14 characters. Run: aws iam update-account-password-policy --minimum-password-length 14

---

### CTL.IAM.PASSWORD.REUSE.001

**Password Reuse Prevention Must Be At Least 24**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.9; cis_aws_v3.0: 1.9; fedramp_moderate: IA-5(1); ffiec: ISH-4; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.5; nist_800_53_r5: IA-5(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.2.5; pci_dss_v4.0: 8.3.7; soc2: CC6.1;

The IAM account password policy must prevent reuse of the last 24 passwords. Without reuse prevention, users cycle between a small set of passwords, negating the value of password rotation.

**Remediation:** Update the IAM password policy to prevent reuse of the last 24 passwords. Run: aws iam update-account-password-policy --password-reuse-prevention 24

---

### CTL.IAM.PASSWORD.ROTATION.001

**User Passwords Must Be Rotated Within Policy Period**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); owasp_nhi: NHI7; pci_dss_v4.0: 8.3.9; soc2: CC6.1;

IAM user console passwords must be rotated per organizational policy (typically 90 days). The credential report tracks password_last_changed; passwords older than the policy period have accumulated exposure risk and may have been shared, phished, or brute-forced. This complements access key rotation (CTL.IAM.CRED.ROTATION.001) to cover the full credential lifecycle.

**Remediation:** Require the user to change their password. Enforce a maximum password age via the account password policy. Run: aws iam update-account-password-policy --max-password-age 90

---

### CTL.IAM.POLICY.ADMIN.001

**No Full Admin Policies Attached**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No IAM policy with Effect Allow on Action "*" and Resource "*" should be attached to any IAM entity. Full admin policies violate least privilege and grant unrestricted access to all services.

**Remediation:** Replace wildcard admin policies with scoped policies granting only the specific permissions required. Use AWS Access Analyzer to generate least-privilege policies from CloudTrail activity.

---

### CTL.IAM.POLICY.ADMIN.002

**No Full Admin Policies on IAM Groups**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM groups must not have policies granting Effect Allow on Action "*" and Resource "*". An admin policy on a group grants every member full admin access by group membership alone — the group becomes a shadow admin factory. Adding a user to the group (iam:AddUserToGroup) is a single API call that bypasses all per-user permission review. CTL.IAM.POLICY.ADMIN.001 enforces this for users; this control enforces it for groups.

**Remediation:** Replace the wildcard admin policy with scoped policies granting only the permissions the group's members require. Use AWS Access Analyzer to generate least-privilege policies from CloudTrail activity for each group member.

---

### CTL.IAM.POLICY.ASSUMEROLE.001

**AssumeRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

sts:AssumeRole permissions must be scoped to specific role ARNs, not wildcard Resource *. With unrestricted AssumeRole, a compromised identity can assume any role in the account — including admin roles, cross-account trust roles, and service roles with elevated permissions. This is a direct privilege escalation path.

**Remediation:** Restrict sts:AssumeRole to specific role ARNs in the Resource field. Use IAM conditions like aws:PrincipalTag to further limit which roles can be assumed.

---

### CTL.IAM.POLICY.CLOUDSHELL.001

**Restrict AWSCloudShellFullAccess**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.22; owasp_nhi: NHI5; soc2: CC6.3;

The AWSCloudShellFullAccess managed policy should not be attached to any IAM entity unless specifically required. CloudShell provides a browser-based shell that can bypass network-level controls.

**Remediation:** Detach AWSCloudShellFullAccess from all IAM users, groups, and roles that do not require it.

---

### CTL.IAM.POLICY.COMPLEXITY.001

**IAM Policy Complexity Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies with more than 25 statements indicate excessive complexity that increases misconfiguration risk. Complex policies are harder to audit, more likely to contain shadowed statements or contradictory rules, and resist review. Policy complexity is itself a risk factor — it obscures the effective permissions and makes least-privilege verification impractical.

**Remediation:** Refactor complex policies into smaller, focused policies scoped to specific services. Use policy conditions and resource-scoped statements instead of many broad statements. Consider using AWS managed policies where appropriate.

---

### CTL.IAM.POLICY.CONDITION.NOTRESOURCE.001

**Policy Uses NotResource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Policy uses the NotResource element. NotResource inverts the resource scope — the policy applies to everything EXCEPT the listed resources. If the statement is an Allow with NotResource listing 3 S3 buckets, the policy allows access to every other resource in the account. Almost every use of NotResource is either a misconfiguration or could be expressed more safely with explicit Resource and Condition elements.

**Remediation:** Replace NotResource with explicit Resource elements. Express the intended scope positively rather than inverting it.

---

### CTL.IAM.POLICY.CONDITION.ORGID.001

**Resource-Based Policy Missing aws:PrincipalOrgID Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A resource-based policy grants cross-account access without the aws:PrincipalOrgID condition. Without this condition, access can be granted to principals from any AWS account — not just accounts in the organization. aws:PrincipalOrgID restricts access to principals whose accounts are members of the specified organization, preventing access from accounts that have left the org or were never members.

**Remediation:** Add an aws:PrincipalOrgID condition to all cross-account grants in resource-based policies. This restricts access to principals whose accounts are members of the organization.

---

### CTL.IAM.POLICY.CONDITION.REGION.001

**Policy Does Not Restrict AWS Regions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No aws:RequestedRegion condition on actions that create resources. Resources can be created in any AWS region including regions without organizational monitoring, CloudTrail, Config, or GuardDuty. An attacker deploys resources in an unmonitored region to evade detection.

**Remediation:** Add an aws:RequestedRegion condition to policies that allow resource-creation actions. Restrict to approved regions where organizational monitoring is deployed.

---

### CTL.IAM.POLICY.CONDITION.SOURCEIP.001

**Sensitive Actions Without SourceIp Condition**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

IAM-administrative actions (iam:Create*, iam:Delete*, iam:Attach*, iam:Put*, iam:Update*) are allowed without an aws:SourceIp condition. These actions can be called from any IP address. Note: SourceIp conditions do not work for calls through VPC endpoints or some assumed-role patterns — this is a defense-in-depth measure, not a primary control.

**Remediation:** Add an aws:SourceIp condition to policies allowing IAM-administrative actions. Note: SourceIp conditions do not work for calls through VPC endpoints or some assumed-role patterns.

---

### CTL.IAM.POLICY.CONDITION.STRINGLIKE.001

**Policy Condition Uses StringLike Where StringEquals Intended**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy condition uses the StringLike operator on identity-related condition keys where StringEquals should be used. StringLike supports wildcards (* and ?). On identity values like account IDs, an account ID pattern '12345678*' matches 10,000 possible accounts. StringEquals performs exact matching without wildcard interpretation.

**Remediation:** Replace StringLike with StringEquals on identity-related condition keys (aws:PrincipalArn, aws:SourceAccount, aws:PrincipalOrgID). Use exact matching for identity values.

---

### CTL.IAM.POLICY.CONDITION.TEMPORAL.001

**Policy Has Date Condition Without Expiration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

A policy has a date condition (aws:CurrentTime) with a DateGreaterThan start boundary but no DateLessThan end boundary. Temporary access intended to expire remains valid indefinitely after the start date passes. The condition is semantically equivalent to no condition once the start date is reached.

**Remediation:** Add a DateLessThan condition to match the DateGreaterThan start boundary. Temporary access should have both a start and an end date.

---

### CTL.IAM.POLICY.CONDITION.VIASERVICE.001

**KMS Actions Without kms:ViaService Condition**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

KMS actions (kms:Decrypt, kms:GenerateDataKey, kms:Encrypt) are allowed without a kms:ViaService condition. Without this condition, the KMS key can be used by any AWS service or directly via the KMS API — not just the intended service. An attacker with kms:Decrypt can decrypt data from any service that uses the key.

**Remediation:** Add a kms:ViaService condition to restrict KMS Decrypt and GenerateDataKey to the intended service (e.g., s3.us-east-1.amazonaws.com).

---

### CTL.IAM.POLICY.DIRECT.001

**No Direct Policy Attachment on IAM Users**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have managed policies attached directly. Policies should be attached to groups or roles, not individual users. Direct attachment creates unmanageable per-user permission sprawl.

**Remediation:** Create IAM groups with the required policies and add the user to the appropriate groups. Remove directly attached policies from the user.

---

### CTL.IAM.POLICY.ESCALATION.001

**IAM Policies Must Not Grant Self-Modification**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies must not grant the ability to modify, create, or attach policies to the principal's own role or user. Permissions like iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy scoped to self enable privilege escalation — a compromised identity can grant itself full admin access without needing any other vulnerability.

**Remediation:** Remove iam:CreatePolicyVersion, iam:AttachRolePolicy, and iam:PutRolePolicy permissions from non-admin roles. Use SCPs to deny self-modification at the organization level.

---

### CTL.IAM.POLICY.GHOSTREF.001

**IAM Policies Must Not Reference Non-Existent Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

All fully-qualified non-wildcard ARNs in IAM policy Allow statements must resolve to resources present in the snapshot inventory. A dangling reference — an Allow statement granting permissions on a resource that no longer exists — is a persistence mechanism waiting to be exploited. An attacker who can create a resource with the same name inherits all permissions that reference it. For S3 buckets, which have globally unique names and no account-scoped protection, this is an active supply chain takeover vector. This control cross-references the IAM policy ARN inventory against the resource inventory and only fires when snapshot completeness for the relevant resource types is confirmed.

**Remediation:** Remove or update Allow statements referencing ARNs for resources that no longer exist. If the resource was intentionally deleted, remove the policy statement. If the resource was renamed, update the ARN.

---

### CTL.IAM.POLICY.GHOSTREF.002

**Write-Permission Dangling References Are Critical Severity**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policy Allow statements granting write permissions to non-existent reclaimable resource names are an active exfiltration path. The victim's systems attempt to write to the resource — if an attacker registers the name, data flows directly to attacker-controlled infrastructure. S3 bucket ARNs contain no account ID and are globally reclaimable. Write-class permissions (PutObject, SendMessage, Publish, PutRecord) on non-existent S3 buckets, SQS queues, SNS topics, and Kinesis streams are the highest-severity ghost reference findings. This control only evaluates ARN types with confirmed complete collection in the snapshot.

**Remediation:** Remove write-permission Allow statements referencing non-existent resources. For S3 buckets, re-create the bucket in the account before an attacker claims the name, or remove the policy statement entirely.

---

### CTL.IAM.POLICY.GHOSTREF.003

**Dangling KMS Key References Must Not Exist in Active Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

IAM policies granting KMS permissions must only reference KMS key ARNs in enabled status. A policy referencing a pending-deletion or deleted KMS key means systems depending on that policy for encrypt/decrypt operations will fail silently — data integrity violations for PHI workloads. KMS key ARNs include the account ID and a random key ID so they cannot be claimed cross-account, but the operational impact of referencing a non-functional key is a direct compliance failure.

**Remediation:** Cancel the key deletion if the key is still needed, or remove the KMS permissions from the policy. If a replacement key exists, update the policy to reference the new key ARN.

---

### CTL.IAM.POLICY.INLINE.001

**No Inline Policies on IAM Users**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM users must not have inline policies attached directly. Inline policies are harder to audit, cannot be reused, and create per-user policy sprawl that resists central governance.

**Remediation:** Convert inline policies to managed policies and attach via groups or roles. Delete the inline policies from the user.

---

### CTL.IAM.POLICY.INLINE.002

**No Inline Policies on IAM Roles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.16; nist_800_53_r5: AC-2; owasp_nhi: NHI5; soc2: CC6.1;

IAM roles must not have inline policies attached. Inline policies are embedded directly in the role and cannot be versioned, audited, or reused independently. They create shadow permission grants that are invisible to policy-listing tools that only enumerate managed policies. Use managed policies attached to the role instead. CTL.IAM.POLICY.INLINE.001 enforces this for users; this control enforces it for roles.

**Remediation:** Convert inline policies to managed policies. Use aws iam list-role-policies to enumerate inline policies, then aws iam create-policy to create equivalent managed policies, attach them, and delete the inline policies.

---

### CTL.IAM.POLICY.INLINE.003

**No Inline Policies on IAM Groups**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.15; cis_aws_v3.0: 1.15; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM groups must not have inline policies attached. Inline policies on groups are inherited by every member immediately, magnifying the blast radius per policy. They are harder to audit than managed policies, cannot be versioned independently, and create shadow permission grants invisible to tools that only enumerate managed policy attachments. CTL.IAM.POLICY.INLINE.001 enforces this for users; CTL.IAM.POLICY.INLINE.002 enforces it for roles; this control enforces it for groups.

**Remediation:** Convert inline policies to managed policies and attach them to the group. Delete the inline policies using aws iam delete-group-policy --group-name <name> --policy-name <policy>.

---

### CTL.IAM.POLICY.MFA.001

**Destructive Actions Must Require MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.4; fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.4.1; soc2: CC6.1;

IAM policies governing destructive operations (s3:DeleteBucket, iam:CreateUser, ec2:TerminateInstances, etc.) must include an aws:MultiFactorAuthPresent condition. Without policy-level MFA enforcement, a compromised access key alone is sufficient to execute destructive actions — the credential becomes the only barrier between an attacker and data loss.

**Remediation:** Add an aws:MultiFactorAuthPresent condition to IAM policies that permit destructive actions. Example condition block: "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}} Apply to policies covering s3:Delete*, iam:Create*, iam:Delete*, ec2:Terminate*, rds:Delete*, and similar destructive API calls.

---

### CTL.IAM.POLICY.PASSROLE.001

**PassRole Must Be Scoped to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

iam:PassRole permissions must be scoped to specific role ARNs, not wildcard resource *. PassRole allows a principal to assign an IAM role to an AWS service (Lambda, EC2, ECS). With a wildcard resource, an attacker can pass any role — including highly privileged ones — to a service they control, achieving privilege escalation without directly modifying IAM policies.

**Remediation:** Restrict iam:PassRole to specific role ARNs in the Resource field. Example: arn:aws:iam::123456789012:role/my-lambda-role. Use IAM conditions like iam:PassedToService to further limit which services can receive the role.

---

### CTL.IAM.POLICY.PASSROLE.CONDITION.001

**PassRole Must Have iam:PassedToService Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies granting iam:PassRole must include an iam:PassedToService condition restricting which AWS service can receive the passed role. Without this condition, a principal can pass a role to any compute service — Lambda, EC2, Glue, CodeBuild, CloudFormation, SSM — regardless of Resource scope. A role scoped to specific ARNs but passable to any service still enables lateral movement: the principal picks whichever service gives the most convenient execution environment.

**Remediation:** Add an iam:PassedToService condition to the PassRole statement. Example: "Condition": {"StringEquals": {"iam:PassedToService": "lambda.amazonaws.com"}}. Restrict to only the service(s) the principal legitimately uses.

---

### CTL.IAM.POLICY.RESOURCE.WILDCARD.001

**Sensitive Actions Must Not Use Resource Wildcard**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM policies granting sensitive actions (s3:*, kms:Decrypt, dynamodb:*, secretsmanager:GetSecretValue, rds:*, ec2:*, lambda:InvokeFunction, sts:AssumeRole) must scope the Resource element to specific ARNs. Resource "*" on sensitive actions grants the action on every resource in the account, vastly exceeding least privilege. CTL.IAM.POLICY.PASSROLE.001 and CTL.IAM.POLICY.ASSUMEROLE.001 enforce resource scoping for PassRole and AssumeRole specifically; this control generalizes the pattern to all sensitive actions.

**Remediation:** Scope the Resource element to specific ARNs or ARN patterns. For example, restrict s3:* to specific bucket ARNs, kms:Decrypt to specific key ARNs, and lambda:InvokeFunction to specific function ARNs.

---

### CTL.IAM.POLICY.SERVICEWILDCARD.001

**No Service-Wildcard Grants on Denied Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM users and roles must not have any attached policy (inline or customer-managed) that grants `<service>:*` on `Resource: "*"` for services on the denied list. Service-wildcard grants are scoped to a single service but still exceed least-privilege for high-blast-radius services. The default denied list covers three Prowler-flagged services:

  - cloudtrail: enables trail tampering (StopLogging,
    DeleteTrail), log-tamper vector — upstream checks
    `iam_inline_policy_no_full_access_to_cloudtrail` and
    `iam_policy_no_full_access_to_cloudtrail`.
  - kms: enables full key management (ScheduleKeyDeletion,
    ReEncrypt, DisableKey), key-tamper vector — upstream checks
    `iam_inline_policy_no_full_access_to_kms` and
    `iam_policy_no_full_access_to_kms`.
  - aws-marketplace: enables unauthorized resource provisioning
    with direct billing impact — upstream checks
    `iam_inline_policy_no_wildcard_marketplace_subscribe` and
    `iam_policy_no_wildcard_marketplace_subscribe`.
  - sts: enables assumption of any role in the account
    (AssumeRole, AssumeRoleWithSAML, AssumeRoleWithWebIdentity)
    — equivalent to lateral movement across the entire account's
    role graph.

Operators extend the denied list via `params.denied_service_wildcards` as new service-wildcard abuse patterns emerge. The control does not fire on principals with no attached policies — the field `identity.policies.service_wildcards_granted` is `null` in that case and the `present` gate keeps the check silent.

**Remediation:** Replace the `<service>:*` Action with the minimum specific actions the principal actually needs (e.g., `cloudtrail:LookupEvents` for read-only audit, `kms:Decrypt` + `kms:GenerateDataKey` for data access). If the principal legitimately needs broad service authority, narrow `Resource` to specific ARNs rather than `"*"`. For admin personas, use AWS-managed admin policies governed by `CTL.IAM.POLICY.ADMIN.001` instead of per-service wildcard grants.

---

### CTL.IAM.POLICY.SHADOW.001

**IAM Policy Must Not Use NotAction Construct**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

IAM policies using NotAction or NotResource create negative logic that is prone to bypass. A NotAction policy says "allow everything EXCEPT these actions" — but the list of excepted actions rarely covers all dangerous permissions. New AWS services and actions are automatically allowed by the implicit "everything else" grant. Attackers exploit this shadow effect to find actions like iam:PutRolePolicy that fall through the negative logic gap.

**Remediation:** Replace NotAction with an explicit Allow list. Enumerate the specific actions needed and grant only those. Negative logic is prone to bypass as new AWS services and actions are added.

---

### CTL.IAM.POLICY.SHADOW.002

**Negative Logic Must Not Permit IAM Write Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; soc2: CC6.1;

IAM policies using NotAction that allow IAM write actions (iam:PutRolePolicy, iam:CreateUser, iam:AttachRolePolicy) through the negative logic gap are a critical privilege escalation vector. The extractor resolves the effective permissions of NotAction policies and flags when dangerous IAM write actions fall through.

**Remediation:** Replace the NotAction policy with an explicit allow list. Ensure iam:PutRolePolicy, iam:CreateUser, iam:AttachRolePolicy, and iam:CreatePolicyVersion are explicitly denied or absent from the allowed actions.

---

### CTL.IAM.POLICY.SOD.001

**IAM Roles Must Not Combine Data Access and IAM Management**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; iso_27001_2022: A.8.3; nist_800_53_r5: AC-5; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

No single IAM role should have both data access permissions (s3:GetObject, dynamodb:GetItem, rds:*, secretsmanager:GetSecretValue) and IAM management permissions (iam:CreateRole, iam:AttachPolicy, iam:CreateUser, iam:PutRolePolicy). Combining these creates a privilege escalation path — a compromised role with data access can grant itself additional permissions. Separation of privileged access is required by IAM-09 in CCM v4.1.

**Remediation:** Split into two roles: one for data access (application role) and one for IAM management (admin role). Use separate assume-role policies for each. Apply the principle of least privilege — data-path roles should never modify IAM.

---

### CTL.IAM.POLICY.VERSIONS.001

**Policy Has Non-Default Versions with Broader Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A customer-managed IAM policy has non-default versions containing broader permissions than the currently active default version. An attacker with iam:SetDefaultPolicyVersion can switch to a more permissive version without creating a new policy. The escalation path is pre-authored in the policy's version history — the attacker activates it with a single API call.

**Remediation:** Delete non-default policy versions that contain broader permissions than the current default. Use aws iam delete-policy-version to remove dormant escalation paths.

---

### CTL.IAM.RCP.DENY.EXTERNAL.001

**RCP Must Restrict External Principal Access to Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; scs_c02: 1.2; soc2: CC6.1;

Resource Control Policies (RCPs) must include a policy that restricts external principals from accessing organization resources. Unlike SCPs (which constrain what member account principals can do), RCPs constrain who can access resources regardless of resource-based policies. Without an external-access-deny RCP, any S3 bucket policy or IAM role trust policy that grants access to an external account is effective — RCPs are the only mechanism that can override resource-based policies at the organizational level.

**Remediation:** Create an RCP that denies access from principals outside the organization using aws:PrincipalOrgID condition. Attach it to the organization root or target OUs.

---

### CTL.IAM.RCP.TAGAUTH.SESSION.001

**RCP Must Block Exempt Session-Tag Injection (Two Separate Statements)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Principal tags are the union of resource tags AND session tags. Layer 2 locks resource tags, but session tags can be injected via cross-account sts:AssumeRole, OIDC, or SAML — sources OUTSIDE the org that SCPs do not cover. An RCP (which applies to ALL principals, including external) must deny sts:TagSession for the exempt tag keys. Layer 3 of 4.
It must be TWO SEPARATE statements (OR logic), not one (AND logic): (1) Deny sts:TagSession with exempt tag keys unless aws:PrincipalArn is the tagger role; (2) Deny sts:TagSession with exempt tag keys unless aws:ResourceOrgID equals aws:PrincipalOrgID. Combined into one statement the conditions AND, leaving two bypass paths (tagger outside org; non-tagger inside org). The collector emits identity.tag_auth.session_tag_injection_blocked = true only when BOTH statements exist SEPARATELY and BOTH are scoped by the aws:TagKeys exempt-prefix condition (an org-boundary statement missing the tag-keys scope is overly broad — it blocks all session tags, including the trusted tagger's — so it does not count).

**Remediation:** Add an RCP with TWO separate Deny statements on sts:TagSession, both scoped by aws:TagKeys (exempt prefix): one exempting the tagger role (StringNotLike aws:PrincipalArn), one exempting same-org principals (StringNotEquals aws:ResourceOrgID vs aws:PrincipalOrgID). Keep them separate so the conditions OR.

---

### CTL.IAM.RESOURCE.CROSSACCOUNT.001

**Role Must Not Grant Access to External Account Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.3;

IAM role's policy grants access to resources in a different AWS account via a cross-account Resource ARN. The role can read from or write to S3 buckets, DynamoDB tables, or other resources in an external account. This creates a data boundary violation: data can flow between accounts without the receiving account's resource-based policy being the sole gating control. Combined with a compromised principal, cross-account resource grants become exfiltration channels.

**Remediation:** Remove cross-account resource ARNs from identity-based policies. If cross-account access is required, use a resource-based policy on the target resource or an explicit cross-account role assumption via sts:AssumeRole with ExternalId conditions.

---

### CTL.IAM.ROLE.BREAKGLASS.001

**Break-Glass Elevated Roles Must Not Persist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; nist_800_53_r5: AC-2; soc2: CC6.1;

IAM roles granted elevated permissions for incident response (break-glass access) must be revoked within 7 days. Elevated roles that persist beyond the incident become permanent backdoors — they carry admin-level permissions with no active justification. Debug rules, elevated roles, and emergency access must have mandatory time-bounding.

**Remediation:** Revoke the elevated role or revert its permissions to the pre-incident baseline. Implement automated expiry via STS session policies or Lambda-based role revocation. Tag elevated roles with grant timestamp and incident ID for tracking.

---

### CTL.IAM.ROLE.CATEGORYMIX.001

**Roles Must Not Span Incompatible Permission Categories**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; iso_27001_2022: A.8.3; nist_800_53_r5: AC-5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must not combine permissions from structurally incompatible categories. A role with data_read + iam_write can access data AND modify who else can access it. A role with compute_control + iam_write can create compute AND grant it permissions (Shadow Admin escalation). A role with audit_control + data_read can access data AND cover tracks. No single permission is alarming. The combination is catastrophic. The extractor categorizes permissions against a defined taxonomy and flags roles that span incompatible pairs: data+iam_write, data+secrets, compute+iam_write, audit_control+sensitive, crypto_control+data.

**Remediation:** Split the role into separate roles with narrowly scoped permissions. Data access roles must not have IAM write permissions. Compute roles must not have IAM write permissions. Audit control roles must not have data access permissions. Use separate roles with separate trust policies for each function.

---

### CTL.IAM.ROLE.CROSSSERVICE.001

**IAM Role Must Not Be Shared Across Multiple Compute Service Types**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.2; nist_800_53_r5: AC-6; soc2: CC6.1;

An IAM role trusted by three or more distinct compute service principals (lambda.amazonaws.com, ecs-tasks.amazonaws.com, ec2.amazonaws.com, states.amazonaws.com, etc.) is a common mode failure point. If the role's permissions are misconfigured or its credentials compromised, every service type that assumes the role is affected simultaneously — Lambda functions, ECS tasks, EC2 instances, and Step Functions state machines all share the same blast radius. Per-service controls (CTL.LAMBDA.ROLE.SHARED.001, CTL.ECS.TASKROLE.SHARED.001, CTL.EC2.PROFILE.SHARED.001, CTL.STEPFUNCTIONS.ROLE.SHARED.001) detect sharing within a single service type. This control detects sharing across service types, which is the common mode failure: a single dependency point for heterogeneous workloads that should be isolated. The threshold of three is intentional — two service types sharing a role is common in legitimate patterns (Lambda + Step Functions orchestration); three or more indicates the role has become a catch-all that should be split.

**Remediation:** Split the role into per-service roles scoped to each service type's specific needs. Use IaC modules to keep the boilerplate manageable. A Lambda execution role should not also be an EC2 instance profile role and an ECS task role — each service gets its own role with minimum required permissions.

---

### CTL.IAM.ROLE.ENTROPY.INCOMPLETE.001

**Complete Data Required for Entitlement Entropy Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

Access Advisor data, permission policy inventory, or tag inventory is absent from the snapshot. Without this data, permission drift, category mixing, and intent mismatch controls cannot evaluate. Re-run the extractor with iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails, iam:ListAttachedRolePolicies, iam:ListRolePolicies, and iam:ListRoleTags permissions.

**Remediation:** Re-run the extractor with permissions to collect Access Advisor data (iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails), policy inventory (iam:ListAttachedRolePolicies, iam:ListRolePolicies), and tags (iam:ListRoleTags).

---

### CTL.IAM.ROLE.INTENTMISMATCH.001

**Role Permissions Must Match Declared Purpose**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.3;

The permission categories present on a role must be consistent with its declared role-type tag. A role tagged readonly must not have iam_write or compute_control permissions. A role tagged application must not have iam_write or network_control permissions. The extractor computes intent_mismatch by comparing the role's actual permission categories against the compatibility matrix for its declared role-type. Requires CTL.IAM.ROLE.INTENTTAG.001 to pass first — if role-type is absent, this control cannot evaluate.

**Remediation:** Review the forbidden permission categories listed in this finding. Either remove the permissions that contradict the declared purpose, or update the role-type tag to accurately reflect the role's actual function. If the role legitimately needs cross-category permissions, consider splitting it into separate roles.

---

### CTL.IAM.ROLE.INTENTTAG.001

**Roles Must Have a Declared Purpose Tag**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: CM-8; nist_800_53_r5: CM-8; soc2: CC6.3;

All IAM roles must have a role-type tag with a value from the defined taxonomy (application, data-pipeline, readonly, admin, security, ci-cd, break-glass, service-account). Without a declared purpose, access reviews cannot systematically verify whether a role's permissions match its intent. A missing tag means no one has formally declared what this role is supposed to do. The role-type tag is the machine-readable anchor for intent-versus-permissions checking.

**Remediation:** Add a role-type tag with one of: application, data-pipeline, readonly, admin, security, ci-cd, break-glass, service-account. Choose the value that best describes the role's intended function.

---

### CTL.IAM.ROLE.LAMBDA.SCOPING.001

**Lambda Execution Role Assumable by Any Function**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(1); nist_800_53_r5: AC-6(1); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

Lambda execution role trust policy allows lambda.amazonaws.com without a condition restricting which Lambda functions can assume it. Any Lambda function in the account can assume this role. If the role has database access, any function — including one an attacker creates — gets database access by assuming this role.

**Remediation:** Add a condition on aws:SourceFunctionArn or lambda:FunctionArn in the trust policy to restrict which Lambda functions can assume this role.

---

### CTL.IAM.ROLE.PERMISSIONDRIFT.001

**Roles Must Not Accumulate Unused Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.3;

IAM roles must not retain access to services that have never been used or were last used more than 90 days ago, when the role itself has been active for more than 90 days. A role with 30 accessible services where 25 are never used has accumulated permissions far beyond its operational scope. An attacker who compromises this role has access to 30 services but the legitimate owner only uses 5. The unused 25 are the hidden blast radius. Access Advisor data from AWS provides exact timestamps of last permission use — this is an operational fact, not a security assertion.

**Remediation:** Review the unused service namespaces listed in this finding. Remove permissions for services that are no longer needed. For services that are intentionally retained for emergency use, set the stave/permission-drift-threshold tag on the role to document the justified exception (e.g., stave/permission-drift-threshold=0.40).

---

### CTL.IAM.ROLE.UNUSED.001

**IAM Role Not Assumed in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.21; nist_800_53_r5: AC-2(3); owasp_nhi: NHI1; soc2: CC6.2;

IAM role has not been assumed in 90 or more days. The role exists with attached permissions but serves no active purpose. Unused roles are a latent attack surface — if compromised, their permissions are available but not being monitored for anomalous usage because nobody uses them normally.

**Remediation:** Review and delete unused IAM roles. If the role is needed for disaster recovery, document the justification and reduce its permissions to minimum required.

---

### CTL.IAM.ROLESANYWHERE.CRL.001

**IAM Roles Anywhere Trust Anchor Has No CRL Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5(2); scs_c02: 2.8; soc2: CC6.1;

An IAM Roles Anywhere trust anchor has no Certificate Revocation List (CRL) configured. Without a CRL, revoked client certificates can still assume IAM roles through the trust anchor. If a certificate's private key is compromised, there is no mechanism to prevent the compromised certificate from obtaining temporary credentials.

**Remediation:** Import a CRL for the trust anchor: aws rolesanywhere import-crl --trust-anchor-arn <arn> --crl-data fileb://revoked.crl --name my-crl.

---

### CTL.IAM.ROLESANYWHERE.SELFSIGNED.001

**IAM Roles Anywhere Trust Anchor Uses Self-Signed Certificate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5(2); scs_c02: 2.8; soc2: CC6.1;

An IAM Roles Anywhere trust anchor uses a self-signed certificate authority rather than AWS Private CA or an established PKI. Self-signed CAs lack the revocation infrastructure, audit trail, and lifecycle management of a proper PKI. The CA private key is managed outside AWS, increasing the risk of key compromise and making certificate lifecycle tracking difficult.

**Remediation:** Replace with an AWS Private CA trust anchor for integrated revocation, audit logging, and certificate lifecycle management.

---

### CTL.IAM.ROOT.ACCESSKEY.001

**Root Account Must Not Have Access Keys**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.4; cis_aws_v3.0: 1.4; fedramp_moderate: IA-2; hipaa: 164.312(a)(1); nist_800_53_r5: IA-2; owasp_nhi: NHI2; pci_dss_v3.2.1: 2.1; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

The AWS root account must not have active access keys. Root access keys provide unrestricted programmatic access. Use IAM users or roles for programmatic access instead.

**Remediation:** Delete the root access keys. Create IAM users or roles with least-privilege policies for programmatic access.

---

### CTL.IAM.ROOT.HWMFA.001

**Root Account Must Use Hardware MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.6; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The root account must use a hardware MFA device, not a virtual one. Hardware tokens cannot be cloned or phished via device compromise, providing stronger protection for the most privileged identity.

**Remediation:** Replace the virtual MFA with a hardware TOTP device (YubiKey, Gemalto) in the IAM console under Security Credentials.

---

### CTL.IAM.ROOT.MFA.001

**Root Account Must Have MFA Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.5; cis_aws_v3.0: 1.5; fedramp_moderate: IA-2(1); ffiec: CAT-D3; gdpr: Art.32; hipaa: 164.312(d); iso_27001_2022: A.8.5; nist_800_53_r5: IA-2(1); nist_csf_2.0: PR.AA; pci_dss_v3.2.1: 8.3; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

The AWS root account must have multi-factor authentication enabled. Root has unrestricted access to all resources. Compromise without MFA is the highest-severity identity risk.

**Remediation:** Enable MFA on the root account using a hardware MFA device or virtual MFA app. Navigate to IAM > Security credentials > MFA.

---

### CTL.IAM.ROOT.RECUR.001

**Root Account Must Not Be Used Repeatedly**

- **Severity:** critical
- **Type:** unsafe_recurrence
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.7; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.1; soc2: CC7.1;

Root account API activity has occurred more than once in 30 days. A single root usage may be a legitimate break-glass event. Two or more usages within a month requires investigation — either the organization has not addressed the process that led to the first usage, or root credentials have been compromised and are being actively used.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.IAM.ROOT.USAGE.001

**Root Account Must Not Be Used for Daily Tasks**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.7; fedramp_moderate: AC-2; nist_800_53_r5: AC-2; owasp_nhi: NHI5, NHI10; pci_dss_v4.0: 8.1.1; soc2: CC6.2;

The root account must not be used for day-to-day operations. Root activity should be limited to account setup tasks. Recent root usage indicates operational reliance on root credentials.

**Remediation:** Create IAM admin users or roles for daily operations. Lock root credentials and use them only for account-level tasks.

---

### CTL.IAM.S3.WILDCARD.001

**Roles Must Not Grant Wildcard S3 Resource Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

IAM role's S3 actions (s3:*, s3:GetObject, s3:PutObject, etc.) use Resource: * — the role can access every S3 bucket in the account. A compromised principal or compute resource using this role can read or write any object in any bucket: customer data, backups, audit logs, CloudTrail archives, Terraform state. This is distinct from CTL.IAM.POLICY.RESOURCE.WILDCARD.001 which checks all sensitive actions; this control focuses specifically on S3 wildcard scope because S3 is the primary data exfiltration vector and training-data source for ML workloads.

**Remediation:** Scope the S3 actions to specific bucket ARNs. Use arn:aws:s3:::my-bucket and arn:aws:s3:::my-bucket/* to restrict object-level access to specific buckets. For training roles, restrict to the training data bucket only.

---

### CTL.IAM.SCP.ACCESSANALYZER.001

**SCP Does Not Protect Access Analyzer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; soc2: CC6.1;

SCP does not deny IAM Access Analyzer deletion in member accounts. Access Analyzer continuously monitors for resources that grant access to external principals. If the analyzer is deleted, external-access detection stops silently — no alarm fires, no finding is generated, the organization simply loses visibility into cross-account grants. This is the same "blinding" pattern as CloudTrail and EventBridge disruption: the attacker disables the detection system before performing the attack.

**Remediation:** Add an SCP that denies access-analyzer:DeleteAnalyzer for all principals in member accounts. Use a condition to exempt the designated break-glass role.

---

### CTL.IAM.SCP.ACTION.INVALID.001

**SCP References Invalid IAM Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SCP contains action names that do not exist in the IAM authorization reference. Invalid actions silently fail to match — the SCP appears to deny or allow behavior but the misspelled or non-existent action never evaluates. A typo in a deny statement (e.g. s3:Getobject instead of s3:GetObject) leaves the intended restriction unenforced. The IAM authorization reference is the canonical source of valid per-service actions.

**Remediation:** Validate all action names in SCP statements against the IAM authorization reference (servicereference.us-east-1.amazonaws.com). Fix typos, update deprecated action names, and verify service prefixes. Run geniamdata to refresh the local registry, then re-evaluate.

---

### CTL.IAM.SCP.ASSUMEROOT.001

**SCP Does Not Deny sts:AssumeRoot**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SCP does not deny sts:AssumeRoot in the organization. A compromised management account principal can call sts:AssumeRoot to obtain root credentials in any member account, bypassing all IAM controls. This grants unrestricted access to every service and resource in the target account. AWS CIRT identifies this as a recurring technique in real-world incidents — a single compromised management account escalates to org-wide root access.

**Remediation:** Add an SCP that denies sts:AssumeRoot for all principals except a specific break-glass role. Attach to the organization root OU.

---

### CTL.IAM.SCP.CLOSEACCOUNT.001

**SCP Does Not Deny account:CloseAccount**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No SCP in the hierarchy denies account:CloseAccount. An attacker who compromises a member account admin can close the AWS account, permanently destroying all resources — EC2 instances, S3 data, RDS databases, IAM configuration, and audit trails. Account closure is irreversible after a 90-day grace period. Unlike resource deletion, closing the account eliminates the entire control plane in one API call.

**Remediation:** Add an SCP that denies account:CloseAccount for all principals in member accounts. Apply it to the organization root.

---

### CTL.IAM.SCP.CLOUDTRAIL.001

**SCP Does Not Protect CloudTrail**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AU-2; owasp_nhi: NHI6; soc2: CC6.1;

SCP does not deny CloudTrail modification or deletion in member accounts. A member account admin or attacker with admin access can stop logging, delete trails, or modify trail configuration. Without SCP protection, the audit trail can be destroyed and subsequent attacker actions go unrecorded.

**Remediation:** Add an SCP that denies cloudtrail:StopLogging, cloudtrail:DeleteTrail, and cloudtrail:UpdateTrail for all principals in member accounts.

---

### CTL.IAM.SCP.CONFIG.001

**SCP Does Not Protect AWS Config**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AU-2; owasp_nhi: NHI6; soc2: CC6.1;

SCP does not deny AWS Config modification or deletion in member accounts. AWS Config records resource configuration changes. Without SCP protection, a compromised admin can stop Config recording and modify resources without configuration change history.

**Remediation:** Add an SCP that denies config:StopConfigurationRecorder, config:DeleteConfigurationRecorder, and config:DeleteDeliveryChannel for all principals in member accounts.

---

### CTL.IAM.SCP.CONFUSEDDEPUTY.001

**SCP Does Not Prevent Confused Deputy Role Assumption**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; soc2: CC6.1;

Organization SCPs do not deny sts:AssumeRole when an AWS service principal assumes a role on behalf of a resource outside the account. The confused deputy SCP pattern denies sts:AssumeRole when aws:PrincipalIsAWSService is true AND aws:SourceAccount does not match aws:ResourceAccount (the role's account). Without this SCP, each role's trust policy is the sole defense against confused deputy — one misconfigured trust policy equals one exploitable role. The SCP catches confused deputy at the organization level regardless of individual role trust policies, providing defense in depth. This is the organizational complement to per-role confused deputy protection (CTL.IAM.TRUST.CONFUSEDDEPUTY.001, CTL.IAM.TRUST.SOURCEARN.001).

**Remediation:** Add an SCP that denies sts:AssumeRole when the requesting service principal operates on behalf of a resource outside the role's account. SCP statement: {"Effect": "Deny", "Action": "sts:AssumeRole", "Resource": "*", "Condition": {"Bool": {"aws:PrincipalIsAWSService": "true"}, "StringNotEquals": {"aws:SourceAccount": "${aws:ResourceAccount}"}}}.  Add a second statement for the Null case: {"Condition": {"Bool": {"aws:PrincipalIsAWSService": "true"}, "Null": {"aws:SourceAccount": "true"}}}.

---

### CTL.IAM.SCP.CREATEACCOUNT.001

**SCPs Must Restrict Unauthorized IAM User and Account Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); iso_27001_2022: A.8.2; nist_800_53_r5: AC-2; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

AWS Organizations must have an SCP restricting who can create IAM users (iam:CreateUser) and new AWS accounts (organizations:CreateAccount). Without this restriction, any principal with these permissions can create persistent identities that survive credential rotation and incident response. MITRE ATT&CK T1136/T1136.003 documents account creation as a primary persistence technique after initial compromise. An attacker-created IAM user has separate credentials unknown to the incident response team. An attacker-created AWS account starts with no monitoring infrastructure deployed — a fresh environment inside the organization's trust boundary but outside its detection field.

**Remediation:** Attach an SCP to the organization root with Deny statements on iam:CreateUser and organizations:CreateAccount. Use conditions to allow only authorized principals (e.g., a specific CI/CD role or identity management role) to perform these actions. Verify the conditions cannot be trivially satisfied by an attacker's existing permissions.

---

### CTL.IAM.SCP.DANGEROUS.ALLOWS.001

**SCPs Must Not Explicitly Allow Dangerous Administrative Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SCPs must not contain Allow statements for actions that undermine the organization's security posture: audit evasion (DeleteTrail, StopLogging, DeleteDetector), data destruction (DeleteBucket, ScheduleKeyDeletion), boundary removal (DeletePolicy, DetachPolicy), or privilege escalation (CreatePolicyVersion, AttachRolePolicy). An Allow for these actions signals that someone has deliberately removed the organizational-level protection. To determine when the Allow was introduced, run stave bisect with this control against the snapshot archive.

**Remediation:** Remove the Allow statements for dangerous actions from the SCP. If the actions are legitimately needed, scope them to specific resources or conditions rather than blanket Allow. Use stave bisect to determine when the Allow statement was introduced.

---

### CTL.IAM.SCP.DATAPERIMETER.S3.001

**SCP Does Not Enforce S3 Data Perimeter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3, SC-7; soc2: CC6.1, CC6.6;

Organization SCPs do not restrict S3 write operations to buckets within the organization. Without an SCP condition on aws:ResourceOrgID for s3:PutObject, s3:ReplicateObject, and s3:PutObjectAcl, any principal in the organization can write to S3 buckets in any AWS account — including attacker-controlled accounts. This is the enabling condition for bucket hijacking: when a destination bucket is deleted and re-registered under a different account, data streams continue writing because no organizational boundary prevents the cross-account write. A data perimeter SCP is the primary defense against the global namespace bucket hijacking technique documented by Unit 42.

**Remediation:** Add an SCP that denies s3:PutObject, s3:ReplicateObject, and s3:PutObjectAcl unless aws:ResourceOrgID matches the organization ID. Exempt service-linked roles and specific cross-organization integrations with a condition key allowlist.

---

### CTL.IAM.SCP.EBSENCRYPT.001

**SCP Does Not Protect EBS Default Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.1;

SCP does not deny disabling EBS default encryption. If EBS default encryption is enabled at the account level, any identity with ec2:DisableEbsEncryptionByDefault can turn it off, allowing new volumes to be created without encryption. The SCP prevents this setting from being toggled off, maintaining encryption-by-default as an organizational invariant.

**Remediation:** Add an SCP that denies ec2:DisableEbsEncryptionByDefault for all principals in member accounts. This ensures that once EBS default encryption is enabled, it cannot be turned off.

---

### CTL.IAM.SCP.EVENTBRIDGE.001

**SCP Does Not Protect EventBridge Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SI-4; owasp_nhi: NHI6; soc2: CC7.2;

SCP does not deny EventBridge security rule modification in member accounts. GuardDuty findings, Config compliance changes, and other security events are routed through EventBridge rules. If these rules are deleted, disabled, or have their targets removed, security alerts stop flowing even though detection services are still running. This is the alerting-pipeline variant of the "blinding the watchmen" pattern — CloudTrail destination hijacking blinds log collection, EventBridge rule deletion blinds alert delivery.

**Remediation:** Add an SCP that denies events:DeleteRule, events:DisableRule, and events:RemoveTargets on security-critical rule resources. All three actions must be denied — an attacker who can delete the rule OR disable it OR remove its targets achieves the same result: alerts stop flowing.

---

### CTL.IAM.SCP.FULLACCESS.001

**Organizations Must Not Rely Solely on FullAWSAccess SCP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

AWS Organizations must have restrictive Service Control Policies beyond the default FullAWSAccess SCP. An organization that only has FullAWSAccess applied has no organizational guardrails — any IAM permission granted within a member account is allowed, including access to unused services that expand the attack surface.

**Remediation:** Create restrictive SCPs that deny unused services and dangerous actions. Apply them to organizational units. Keep FullAWSAccess on the root but add deny-based SCPs to OUs that restrict the effective permissions.

---

### CTL.IAM.SCP.GUARDDUTY.001

**SCP Does Not Protect GuardDuty**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SI-4; owasp_nhi: NHI6; soc2: CC6.6;

SCP does not deny GuardDuty disablement in member accounts. A compromised account admin can disable GuardDuty threat detection, eliminating runtime threat monitoring. Without SCP protection, the attacker can disable GuardDuty and operate without threat alerts.

**Remediation:** Add an SCP that denies guardduty:DeleteDetector, guardduty:DisassociateFromMasterAccount, and guardduty:UpdateDetector for all principals in member accounts.

---

### CTL.IAM.SCP.IAM.001

**SCP Does Not Restrict Critical IAM Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SCP does not deny known privilege escalation actions in member accounts. Actions like iam:CreatePolicyVersion, iam:AttachRolePolicy, iam:PutRolePolicy, and iam:UpdateAssumeRolePolicy are the core escalation primitives. SCPs are the only control that prevents an account admin from self-escalating — IAM policies can be modified by anyone with iam:*, and permission boundaries can be removed.

**Remediation:** Add an SCP that denies iam:CreatePolicyVersion, iam:AttachRolePolicy, iam:PutRolePolicy, and iam:UpdateAssumeRolePolicy for non-admin principals in member accounts. Use condition keys to exempt designated break-glass roles.

---

### CTL.IAM.SCP.IGW.001

**SCP Does Not Deny Internet Gateway Creation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

SCP does not deny internet gateway creation in member accounts. Without this SCP, any identity in the organization can attach an internet gateway to a VPC, enabling direct internet access from accounts intended to be private (dev, sandbox, internal workloads). The SCP must deny ec2:AttachInternetGateway, ec2:CreateInternetGateway, and ec2:CreateEgressOnlyInternetGateway to enforce the "private-by-default" network posture.

**Remediation:** Add an SCP that denies ec2:AttachInternetGateway, ec2:CreateInternetGateway, and ec2:CreateEgressOnlyInternetGateway for accounts that should be private. Apply to OUs containing dev, sandbox, or internal-workload accounts. All three actions must be denied — CreateInternetGateway without Attach is partial, and CreateEgressOnlyInternetGateway is a separate path often missed.

---

### CTL.IAM.SCP.IMDSV2.001

**SCP Does Not Enforce IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-7; owasp_nhi: NHI9; soc2: CC6.1;

SCP does not deny EC2 instance launches without IMDSv2 required. Without this SCP, any identity in the organization can launch instances with IMDSv1 enabled. IMDSv1 is the primary credential-theft vector via SSRF — an attacker who compromises a web application on an EC2 instance can query the metadata service at 169.254.169.254 to steal IAM role credentials. The SCP denies ec2:RunInstances when ec2:MetadataHttpTokens is not "required", preventing IMDSv1 instances at the organizational boundary.

**Remediation:** Add an SCP that denies ec2:RunInstances with condition ec2:MetadataHttpTokens != "required". This prevents any identity from launching instances without IMDSv2 enforced. Optionally also deny ec2:ModifyInstanceMetadataOptions to prevent downgrade of existing instances, and deny all actions when ec2:RoleDelivery < 2.0 for defense in depth.

---

### CTL.IAM.SCP.LEAVEORG.001

**SCP Does Not Deny organizations:LeaveOrganization**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Member accounts can exit the organization via organizations:LeaveOrganization. When an account leaves, ALL SCPs are immediately removed — every organizational guardrail drops instantly. The account becomes completely ungoverned with no region restrictions, no service restrictions, and no escalation prevention. An attacker who compromises a member account admin can remove every organizational control with one API call.

**Remediation:** Add an SCP that denies organizations:LeaveOrganization for all principals in member accounts. Apply it to the organization root or all OUs.

---

### CTL.IAM.SCP.OU.COVERAGE.001

**Production OUs Must Have Restrictive SCPs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.22; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Safety mechanism integrity control. Checks that security guardrails are actively enforcing, not just present.

**Remediation:** Review the specific guardrail identified in this finding and restore it to an enforcing state.

---

### CTL.IAM.SCP.REGIONS.001

**SCP Does Not Restrict AWS Regions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

SCP does not restrict which AWS regions member accounts can use. Resources can be created in any region including regions without organizational monitoring, CloudTrail, or Config. An attacker deploys resources in an unmonitored region to evade detection.

**Remediation:** Add an SCP with an aws:RequestedRegion condition that denies all actions in non-approved regions. Allow only the regions where organizational monitoring is deployed.

---

### CTL.IAM.SCP.RESERVEDINSTANCE.001

**SCP Does Not Deny Reserved Instance Purchases**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

SCP does not deny ec2:PurchaseReservedInstancesOffering in member accounts. This is the most expensive single API call in AWS — one call can commit up to $3M per instance, and with the default limit of 20 instances, a single compromised credential can commit $62M in irrecoverable spend. Unlike most API actions, Reserved Instance purchases cannot be reversed, cancelled, or refunded. The SCP is the only preventive control; IAM policies are insufficient because any admin can grant themselves the permission.

**Remediation:** Add an SCP that denies ec2:PurchaseReservedInstancesOffering for all principals in member accounts. Exempt only the billing break-glass role via a condition on aws:PrincipalArn.

---

### CTL.IAM.SCP.ROOT.001

**SCP Does Not Deny Root Access Key Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; soc2: CC6.1;

SCP does not deny iam:CreateAccessKey for root users in member accounts. Root access keys provide unrestricted API access to the entire AWS account — every service, every resource, every action. They bypass IAM policies and permission boundaries. Once created, root access keys persist until explicitly deleted.

**Remediation:** Add an SCP that denies iam:CreateAccessKey when the principal is root. Apply via condition aws:PrincipalArn matching the root ARN pattern.

---

### CTL.IAM.SCP.SAVINGSPLAN.001

**SCP Does Not Deny Savings Plan Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

SCP does not deny savingsplans:CreateSavingsPlan in member accounts. A single API call can commit up to $26M in irrecoverable spend over a 1-year or 3-year term. Like Reserved Instance purchases, Savings Plan commitments cannot be cancelled or refunded — the spend is locked the moment the API call succeeds. Combined with RI purchases, these two API calls represent the highest-value denial-of-wallet attack surface in AWS.

**Remediation:** Add an SCP that denies savingsplans:CreateSavingsPlan for all principals in member accounts. Exempt only the billing break-glass role via a condition on aws:PrincipalArn.

---

### CTL.IAM.SCP.STRATEGY.001

**SCPs Use Deny-List Strategy Instead of Allow-List**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Organization SCPs use individual Deny statements for specific services (deny-list strategy) rather than a Deny with NotAction listing permitted services (allow-list strategy). An allow-list strategy is structurally stronger — new AWS services are denied by default until explicitly permitted, preventing exposure from newly launched services that bypass existing guardrails. A deny-list must be updated every time AWS launches a service that could be abused.

**Remediation:** Consider migrating to an allow-list SCP strategy using Deny with NotAction. List only the services your organization uses; everything else is denied by default. This prevents exposure from newly launched AWS services.

---

### CTL.IAM.SCP.TAGAUTH.ENFORCE.001

**Sensitive-Action SCP Must Gate on a Principal-Tag Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Tag-based authorization only works if an SCP denies the organization's declared sensitive actions for principals WITHOUT the exempt tag. Without it the tags exist but nothing checks them. Layer 1 of 4 in the tag-auth scheme (see CTL.IAM.TAGAUTH.COMPLETE.001).
The collector parses the organization's SCPs against the declared sensitive actions (param sensitive_actions; default iam:CreateAccessKey, iam:UpdateAccessKey, iam:CreateLoginProfile, iam:UpdateLoginProfile) and emits identity.tag_auth.sensitive_actions_tag_gated = true only when every declared action is covered by a Deny statement whose Condition uses aws:PrincipalTag/<prefix> (StringNotEquals). A statement that uses aws:RequestTag instead of aws:PrincipalTag does NOT count — it checks what the caller is tagging a resource with, not whether the caller is authorized — so the collector reports gated=false (correctness, not mere existence).

**Remediation:** Add an SCP Deny statement covering the sensitive actions with a Condition StringNotEquals on aws:PrincipalTag/<exempt-tag-key>. Use aws:PrincipalTag (who the caller is), never aws:RequestTag (what the caller is tagging).

---

### CTL.IAM.SCP.TAGAUTH.MUTATION.001

**Exempt-Tag Mutation Must Be Locked to the Designated Tagger Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

If any principal can add the exempt tag to its own role, the enforcement SCP (CTL.IAM.SCP.TAGAUTH.ENFORCE.001) is bypassable: tag self, act, untag. An SCP must deny the tag-mutation actions (iam:TagRole, iam:TagUser, iam:UntagRole, iam:UntagUser, iam:CreateRole, iam:CreateUser) when the tag keys include the exempt prefix, UNLESS the caller is the designated tagger role. Layer 2 of 4.
The collector emits identity.tag_auth.tag_mutation_locked = true only when an SCP covers ALL SIX actions with a ForAnyValue:StringLike condition on aws:TagKeys (exempt prefix) AND a StringNotLike exemption on aws:PrincipalArn for the tagger role. StringNotLike (wildcard) is required, not StringNotEquals — the tagger ARN's account id varies per account, so an exact-match exemption fails cross-account; the collector reports locked=false for the wrong operator and for incomplete action coverage (missing iam:CreateRole lets a principal create a NEW role pre-tagged).

**Remediation:** Add an SCP denying iam:TagRole/TagUser/UntagRole/UntagUser/CreateRole/ CreateUser when aws:TagKeys matches the exempt prefix (ForAnyValue:StringLike), with a StringNotLike exemption on aws:PrincipalArn for the tagger role (wildcard ARN for cross-account).

---

### CTL.IAM.SCP.TAGAUTH.TAGGER.001

**Tagger Role and Its Deployment Role Must Be Protected From Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

If developers have admin in their accounts (common), they can modify or recreate the tagger role to assume it and self-exempt. An SCP must deny all IAM mutation actions on the tagger role AND on the deployment role that manages it (e.g. stacksets-exec-*), exempting only the deployment role. Layer 4 of 4.
The collector emits identity.tag_auth.tagger_role_protected = true only when an SCP denies all 13 IAM mutation actions (AttachRolePolicy, CreateRole, DeleteRole, DeleteRolePermissionsBoundary, DeleteRolePolicy, DetachRolePolicy, PutRolePermissionsBoundary, PutRolePolicy, TagRole, UntagRole, UpdateAssumeRolePolicy, UpdateRole, UpdateRoleDescription) on BOTH the tagger role and the deployment role, exempting only the deployment role. Missing iam:UpdateAssumeRolePolicy lets a dev rewrite the trust policy and assume the tagger; not protecting the deployment role lets a dev pivot through it — both make the collector report protected=false.

**Remediation:** Add an SCP denying all 13 IAM role-mutation actions on both the tagger role ARN and the deployment role ARN, exempting only the deployment role. Include iam:UpdateAssumeRolePolicy (trust-policy rewrite) explicitly.

---

### CTL.IAM.SCP.TRAIL.PROTECT.001

**SCPs Must Deny CloudTrail Disruption Actions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-9; nist_800_53_r5: AU-9; soc2: CC7.1;

Service Control Policies must deny cloudtrail:StopLogging, cloudtrail:DeleteTrail, and cloudtrail:UpdateTrail to non- breakglass roles. Without these protective denies, any IAM principal with sufficient permissions can disrupt logging.

**Remediation:** Create an SCP with Effect Deny on cloudtrail:StopLogging, cloudtrail:DeleteTrail, and cloudtrail:UpdateTrail. Add a Condition excluding the breakglass role ARN.

---

### CTL.IAM.SEMANTICS.ACTION.RESOURCE.MISMATCH.001

**Action-Resource Service Mismatch in Policy Statement**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy statement lists actions from one AWS service and resources from a different service. IAM evaluates actions against resources by matching the resource ARN's service namespace to the action's service namespace. When they don't match, the action cannot operate on the resource — the statement is effectively dead code for that action-resource pair. For example, a statement with Action "s3:GetObject" and Resource "arn:aws:ec2:*:*:instance/*" grants nothing: s3:GetObject only operates on S3 resources. The policy author either (1) copied the wrong resource ARN, (2) intended a different action, or (3) has a wildcard Resource ("*") that masks the mismatch. This control fires only on explicit non-wildcard Resource ARNs that don't match the action's service. Detection requires parsing the ARN service field and comparing to the action's service prefix. The iam-dataset provides the canonical action-to-resource-type mapping for validation.

**Remediation:** Align the Resource ARN service with the Action service. If the statement needs to cover multiple services, use separate statements with matching action-resource pairs. Cross-reference the iam-dataset action-to-resource-type mapping to verify which resource types each action supports.

---

### CTL.IAM.SEMANTICS.CONDKEY.INAPPLICABLE.001

**Condition Key Inapplicable to Statement Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy statement uses a condition key that is not applicable to any of the statement's actions. IAM condition keys are per-service and per-action — each action only recognizes specific condition keys. When a condition uses a key that none of the statement's actions support, IAM silently ignores the condition: the key is absent from the request context, and the condition evaluates based on its absent-key semantics (true for IfExists/ForAllValues, false for standard operators/ForAnyValue). The policy author intended the condition to restrict the action, but it has no effect. For example, using s3:prefix as a condition key on ec2:RunInstances — s3:prefix is only populated by S3 API calls and is absent from EC2 requests. The condition is dead code that provides a false sense of restriction. Detection requires cross-referencing the policy's Action list against the IAM service authorization reference (iann0036/iam-dataset) to verify each condition key is recognized by at least one listed action.

**Remediation:** Verify the condition key is applicable to the statement's actions using the IAM service authorization reference. Either replace the condition key with one the actions support, or split the statement so each action has conditions it recognizes. Use the iam-dataset action-to-condition-key mapping for programmatic validation.

---

### CTL.IAM.SEMANTICS.DENY.ANDNARROW.001

**Deny with Multiple Negated Conditions AND-Narrows the Deny Domain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A Deny statement has two or more negated conditions (StringNotEquals, ArnNotLike, NotIpAddress) on different keys in the same Condition block. IAM evaluates multiple conditions within a block using AND logic — ALL must be true for the statement to apply. With negated operators, this means the deny fires only when NONE of the values match. Example: Deny unless tag env=prod AND team=security. If env=prod but team=engineering, the deny does not fire because the first condition (env ≠ prod) is false. The author intended OR logic (deny unless env=prod OR team=security) which requires SEPARATE Deny statements. This is De Morgan's law in IAM: ¬(A∧B) ≡ ¬A∨¬B but the policy evaluates ¬A∧¬B. The deny domain is the INTERSECTION of exclusion sets, not the UNION.

**Remediation:** Split the Deny into separate statements, one per negated condition. Each statement independently denies when its condition is true. This achieves OR logic across the conditions — the deny fires when ANY condition is met.

---

### CTL.IAM.SEMANTICS.DENY.CONTRADICTED.001

**Resource Policy Deny Is Contradicted by Allow in Same Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A resource policy contains a Deny statement, but another statement in the same policy document has an Allow that matches the same principal, action, and resource scope. In AWS policy evaluation, an explicit Deny always wins over an Allow — but only for the EXACT principal/action/resource triple. When the Allow uses a broader wildcard than the Deny, requests outside the Deny's narrow scope are still permitted. The author likely intended the Deny to block all matching access, but the accompanying Allow re-opens a path that the Deny does not cover. This extends the S3-specific shadow-allow detection to all resource policy types: KMS, SNS, SQS, Lambda, Secrets Manager, OpenSearch, ECR.

**Remediation:** Review the policy document for overlapping Deny and Allow statements. Either narrow the Allow to exclude the Deny's scope, or broaden the Deny to cover all principals, actions, and resources matched by the Allow.

---

### CTL.IAM.SEMANTICS.DENY.POSITIVE.001

**Deny with Positive Condition Narrows Instead of Excepts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A Deny statement uses a positive condition operator (StringEquals, IpAddress, ArnEquals, Bool) where the author almost certainly intended the negative counterpart. "Deny if aws:SourceIp = 10.0.0.0/8" denies ONLY requests from 10.0.0.0/8. The author usually means "deny UNLESS from 10.0.0.0/8" — which requires NotIpAddress. The positive operator narrows the deny to a specific set of requests rather than creating an exception. The deny fires on a SUBSET of requests when the author intended it to fire on the COMPLEMENT. This is formally provable: the deny domain is |D ∩ C| when the intent was |D \ C|. SMT proves the actual deny set ≠ intended deny set. No competitor tool detects this pattern — it requires understanding the interaction between Effect and condition operator polarity.

**Remediation:** Replace the positive operator with its negative counterpart: StringEquals → StringNotEquals, IpAddress → NotIpAddress, ArnEquals → ArnNotEquals. This inverts the condition so the deny fires for everything EXCEPT the specified values, which matches the typical intent of "deny unless."

---

### CTL.IAM.SEMANTICS.FORALLVALUES.001

**ForAllValues Without Null Check Permits Vacuous Satisfaction**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

An Allow statement using the ForAllValues set operator without a companion Null condition check on the same key is vacuously satisfied when the key is absent from the request. ForAllValues tests whether every value in the request set matches the policy set — but "every value in an empty set matches" is true by definition (vacuous truth in set theory: ∀x∈∅.P(x) ≡ true). A request that omits the condition key entirely satisfies the condition unconditionally. The fix is a companion Null check (Null: {key: "false"}) that fails the condition when the key is absent. AWS documents this hazard but Access Analyzer only warns — it does not block. No competitor tool detects this as a posture property of deployed policies. This is the single strongest example of evaluation-model semantics diverging from author intent, and the headline pitfall for Z3 satisfiability analysis (FM-060).

**Remediation:** Add a Null condition check for the same key with value "false" alongside the ForAllValues condition. This ensures the condition fails when the key is absent from the request.

---

### CTL.IAM.SEMANTICS.FORANYVALUE.DENY.001

**ForAnyValue in Deny Bypassed When Key Is Absent**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A Deny statement uses ForAnyValue on a condition key that may be absent from the request context. ForAnyValue tests whether ANY value in the request set matches the policy set — but when the key is absent the request set is empty, and the existential quantifier over an empty set is false (∃x∈∅.P(x) ≡ false). A false condition in a Deny statement means the deny does not fire. The deny is completely bypassed for every request that omits the key. This is the dual of Pitfall 1 (ForAllValues vacuous truth): where ForAllValues universally satisfies on empty sets, ForAnyValue universally fails. In an Allow context, ForAnyValue failing is conservative (access denied). In a Deny context, ForAnyValue failing is dangerous — the deny that was supposed to block certain values never fires. Formally: the intended deny domain is |{r : ∃v∈r.key. v∈P}| but the actual domain is |{r : r.key ∈ dom(r) ∧ ∃v∈r.key. v∈P}|, excluding all requests where the key is absent. For service-specific keys absent from most request types, this exclusion can be enormous.

**Remediation:** Replace ForAnyValue with the scalar operator and add explicit handling for key absence. Use a Null condition check (Null: {key: "true"}) in a separate Deny statement to also block requests where the key is absent, or restructure as an Allow-with-ForAnyValue pattern where the conservative failure mode (deny access on empty set) is desirable.

---

### CTL.IAM.SEMANTICS.IFEXISTS.SCOPE.001

**IfExists on Service-Specific Key Is Vacuously Satisfied**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy condition uses an IfExists operator suffix on a service-specific condition key (any key not prefixed with aws:*). IfExists makes the condition evaluate to true when the key is absent from the request context. For global keys (aws:SourceIp, aws:PrincipalArn), absence is unusual — most requests include them. For service-specific keys (ec2:InstanceType, s3:prefix, rds:DatabaseEngine), the key is absent from most request types because it only applies to that service's API calls. The condition is vacuously satisfied for every request that doesn't involve the specific service action. AWS documents this pitfall with the ec2:RunInstances example: InstanceType IfExists passes for images, key pairs, and security groups checked during the same API call. An Allow with IfExists on a service-specific key provides less restriction than intended.

**Remediation:** Split the statement into two: one for actions that produce the condition key (with the standard operator, not IfExists), and one for actions that do not. Alternatively, scope the Resource element to only the resource types that carry the key.

---

### CTL.IAM.SEMANTICS.MFA.INVERTED.001

**Allow with MFA-False Condition Grants Access Without MFA**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); pci_dss_v4.0: 8.4.1; soc2: CC6.1;

An IAM Allow statement includes a condition on aws:MultiFactorAuthPresent set to "false". This grants access specifically when MFA is NOT used — the semantic opposite of requiring MFA. The policy reads as if it enforces MFA but actually permits access to any caller who has NOT authenticated with a second factor. When the condition operator is BoolIfExists, the inversion is compounded: programmatic callers whose requests carry no MFA context key at all also satisfy the condition. This is formally provable: Z3 shows the policy permits access for the exact set of requests that lack MFA, which is the complement of the intended set. No competitor tool detects this — it requires correlating Effect polarity, condition key semantics, and condition value.

**Remediation:** Either change the condition value to "true" (Allow only with MFA), or restructure as a Deny statement: Deny + MFA=false is the standard MFA enforcement pattern that blocks all non-MFA requests.

---

### CTL.IAM.SEMANTICS.NEGOP.ABSENT.001

**Negative Operator on Potentially Absent Key Fires Unconditionally**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A Deny statement uses a negative condition operator (StringNotEquals, ArnNotLike, StringNotLike, NotIpAddress) on a condition key that may be absent from the request context, without an IfExists suffix or companion Null check. When a key is absent, AWS evaluates negative operators as TRUE — "the key's value is not equal to the policy value" is vacuously true when there is no value. The deny fires for ALL requests missing the key, which is far broader than intended. This is the mirror image of ForAllValues vacuous satisfaction (Pitfall 1) — where that pitfall makes an Allow too broad, this makes a Deny too broad. Formally: the deny domain expands from |{r : r.key ≠ v}| to |{r : r.key ≠ v} ∪ {r : r.key ∉ dom(r)}|. The second set can be enormous for service- specific keys that most requests don't include.

**Remediation:** Use the IfExists suffix (e.g., StringNotEqualsIfExists) to make the condition pass when the key is absent, or add a companion Null check to explicitly handle key absence. The IfExists suffix evaluates to true when the key is absent, which means the deny still fires — so for deny-unless patterns, use the positive operator instead (StringEquals + IfExists, or rethink the logic).

---

### CTL.IAM.SEMANTICS.NOTPRINCIPAL.001

**NotPrincipal with Deny Breaks Permissions Boundary Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A resource-based policy uses NotPrincipal in a Deny statement. AWS documents that NotPrincipal with Deny "will always deny any IAM principal that has a permissions boundary policy attached, regardless of the values specified in the NotPrincipal element." The mechanism: NotPrincipal excludes the role ARN, but the assumed-role session ARN is a different string. The Deny matches the session (which is not the role), so the deny fires. Principals with permissions boundaries are always denied, even when explicitly listed in the NotPrincipal exclusion. AWS recommends using ArnNotEquals with aws:PrincipalArn in the Condition block instead. This is an evaluation-model interaction that no syntax-level linter can detect — it requires understanding the relationship between role ARNs and session ARNs in the principal matching function.

**Remediation:** Replace NotPrincipal with a Condition block using ArnNotEquals on aws:PrincipalArn. This correctly excludes both the role ARN and its derived session ARNs.

---

### CTL.IAM.SEMANTICS.SETOP.IFEXISTS.001

**Set Operator With IfExists Produces Counterintuitive Evaluation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy condition combines a set operator (ForAllValues or ForAnyValue) with an IfExists operator suffix (e.g., ForAnyValue:StringEqualsIfExists). These two modifiers have conflicting absent-key semantics that produce surprising behavior. IfExists alone evaluates to true when the key is absent (the condition is vacuously satisfied). ForAnyValue alone evaluates to false when the key is absent (∃x∈∅.P(x) ≡ false). Combined, the ForAnyValue set qualifier resolves first: missing key yields an empty request set, so ForAnyValue returns false. The IfExists modifier does not override this — it applies to the individual value comparisons, not to the set evaluation. The result: ForAnyValue:*IfExists behaves like ForAnyValue alone (false on absent key), not like *IfExists alone (true on absent key). Policy authors who add IfExists expecting it to handle the absent-key case are wrong — ForAnyValue already decided the result before IfExists applied. ForAllValues:*IfExists is similarly misleading: ForAllValues already returns true on absent keys (vacuous satisfaction), so IfExists is redundant but signals the author is confused about which modifier controls absent-key behavior. In either combination the IfExists suffix is either inert or overridden, indicating confusion about the evaluation model.

**Remediation:** Separate the intent. If you want to check present values: use ForAnyValue:StringEquals (without IfExists). If you want to handle absent keys: add an explicit Null condition check. Don't combine set qualifiers with IfExists — the interaction is not what either modifier alone would suggest.

---

### CTL.IAM.SEMANTICS.SETOP.SINGLEVALUE.001

**Set Operator on Single-Valued Condition Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy condition uses a set operator (ForAllValues or ForAnyValue) on a condition key documented as single-valued (e.g., aws:SourceIp, aws:PrincipalAccount, aws:SourceVpc, ec2:ResourceTag/*). Set operators are designed for multi-valued keys — they iterate over the request-side value set and test each element against the policy value set. On a single-valued key the request set always has exactly one element, so ForAllValues degenerates to the scalar operator and ForAnyValue degenerates identically — neither adds restriction beyond the base operator. The set qualifier carries one critical hidden cost: ForAllValues on a single-valued key still inherits the vacuous satisfaction trap (Pitfall 1) when the key is absent (∀x∈∅.P(x) ≡ true). The set operator masks this risk because the author sees "ForAllValues:StringEquals" and may not realize that absent-key semantics differ from "StringEquals." AWS docs explicitly recommend avoiding set operators on single-valued keys because (1) the semantics are confusing to reviewers, (2) behavior changes silently if AWS later makes the key multi-valued, and (3) the vacuous-truth hazard applies to ForAllValues even though the key currently has exactly one value.

**Remediation:** Replace ForAllValues:StringEquals with StringEquals (or the appropriate base operator). If the intent is to handle absent keys, use StringEqualsIfExists explicitly rather than relying on ForAllValues vacuous behavior.

---

### CTL.IAM.SEMANTICS.STRINGLIKE.ARN.001

**StringLike on ARN-Valued Keys Produces Wrong Matching Semantics**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

A policy condition uses StringLike or StringNotLike on an ARN-valued condition key (aws:SourceArn, aws:PrincipalArn, aws:ResourceArn, or any key documented as ARN type). StringLike treats the entire value as one string for pattern matching. ArnLike checks each of the six colon-delimited ARN components separately, with per-component wildcard expansion. The operators produce different match results on the same input. A wildcard in one ARN component can accidentally match characters in an adjacent component under StringLike but not ArnLike. AWS explicitly recommends ARN operators for ARN comparisons. This is distinct from CTL.IAM.POLICY.CONDITION.STRINGLIKE.001 which catches StringLike on identity-valued keys (account IDs) — this control catches operator/type mismatch on ARN-valued keys.

**Remediation:** Replace StringLike with ArnLike and StringNotLike with ArnNotLike for all ARN-valued condition keys. ArnLike enforces per-component matching that prevents cross-component wildcard leakage.

---

### CTL.IAM.SESSION.DURATION.001

**Role MaxSessionDuration Exceeds 4 Hours**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-12; nist_800_53_r5: AC-12; owasp_nhi: NHI4; pci_dss_v4.0: 8.2.8; soc2: CC6.1;

IAM role allows sessions up to 12 hours (the AWS maximum). For most roles, 1-4 hours is sufficient. Long sessions persist after credential compromise is detected — revocation requires waiting for session expiry or deleting the role entirely. MaxSessionDuration controls the upper bound of temporary credentials issued via AssumeRole.

**Remediation:** Set MaxSessionDuration to 14400 seconds (4 hours) or less via aws iam update-role --role-name ROLE --max-session-duration 14400. For CI/CD and automation roles, use 3600 seconds (1 hour).

---

### CTL.IAM.SESSION.NAME.001

**Trust Policy Does Not Require RoleSessionName**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-3; nist_800_53_r5: AU-3; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Role trust policy does not include a condition on sts:RoleSessionName. Assumed sessions have generic, unattributable names in CloudTrail (e.g., botocore-session-1234567890). When multiple principals can assume the same role, CloudTrail cannot distinguish who assumed it. RoleSessionName appears in the assumed role ARN: arn:aws:sts::ACCOUNT:assumed-role/ROLE/SESSION_NAME.

**Remediation:** Add a StringLike or StringEquals condition on sts:RoleSessionName in the trust policy to require callers to provide a meaningful session name (e.g., the caller's username or pipeline ID).

---

### CTL.IAM.SESSION.SOURCE.001

**Trust Policy Does Not Set SourceIdentity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-3(1); nist_800_53_r5: AU-3(1); owasp_nhi: NHI10; pci_dss_v4.0: 10.2.1; soc2: CC7.2;

Role trust policy does not require sts:SourceIdentity. In role chaining (A assumes B assumes C), the original caller's identity is lost at each hop. SourceIdentity propagates the original caller through the entire chain — CloudTrail shows who started the chain, not just the last role in it. Once set, SourceIdentity cannot be changed by subsequent AssumeRole calls.

**Remediation:** Add a condition on sts:SourceIdentity in the trust policy to require callers to set a source identity that propagates through role chains. The condition should require a non-empty value matching the caller's identity.

---

### CTL.IAM.SSO.APP.ACCOUNTACCESS.001

**Identity Center Application Must Not Have Account Access Scope**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI5, NHI6; soc2: CC6.1;

An IAM Identity Center application has the sso:account:access scope enabled. This grants the application the ability to call ListAccounts, ListAccountRoles, and GetRoleCredentials on behalf of any authenticated user — effectively impersonating users into any account and role they have access to. The application's effective permissions become the union of every authenticated user's permissions across the entire organization. A Lambda function with a minimal execution role that has this scope can assume AdministratorAccess in every account — on behalf of any user who signs in. One misconfigured application creates organization-wide privilege escalation.

**Remediation:** Review whether this application requires account access scope. If the application only needs to authenticate users (not assume roles on their behalf), remove the sso:account:access scope. AWS currently provides no mechanism to scope which accounts or roles an application can impersonate into — the access is all-or- nothing. Restrict which users can authenticate to the application via assignment configuration.

---

### CTL.IAM.SSO.APP.ASSIGNMENT.001

**Identity Center Application Must Require User Assignment**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2, AC-6; soc2: CC6.1;

An IAM Identity Center application does not require user assignment — any user in the Identity Center directory can authenticate to it. When assignment is not required, the application is accessible to the entire directory population. Combined with sso:account:access scope, this means any user in the organization can trigger user impersonation through the application. Even without account access scope, an unassigned application expands the attack surface by allowing any compromised directory account to access the application's resources.

**Remediation:** Enable assignment required on the application via PutApplicationAssignmentConfiguration. Then explicitly assign only the users and groups that need access to the application.

---

### CTL.IAM.SSO.APP.SPRAWL.001

**Identity Center Must Not Have Excessive Applications With Account Access**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CM-7; soc2: CC6.1;

Multiple IAM Identity Center applications have sso:account:access scope enabled. Each application is a separate impersonation vector — a distinct entry point for credential brokering into any account and role. More applications with account access means more code paths to audit, more Lambda functions or services that can trigger impersonation, and more governance surface area. A single application with account access is a deliberate architectural choice; multiple applications with account access is sprawl.

**Remediation:** Consolidate account access scope to the minimum number of applications that genuinely need to assume roles on behalf of users. Remove sso:account:access from applications that only need authentication. Audit each application's purpose and whether it requires credential brokering.

---

### CTL.IAM.SSO.DELEGATED.ADMIN.001

**Identity Center Must Use Delegated Administration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); scs_c02: 3.1; soc2: CC6.1;

IAM Identity Center should be administered from a delegated administrator account, not the management account. Running IC from the management account means IC administrators also have implicit access to organizational management operations. Delegating IC administration to a dedicated security account follows least- privilege and reduces the blast radius of compromised IC admin credentials.

**Remediation:** Register a delegated administrator account for IAM Identity Center using aws organizations register-delegated-administrator --account-id <security-account> --service-principal sso.amazonaws.com.

---

### CTL.IAM.SSO.LEGACY.001

**Legacy IAM Users Must Not Coexist with SSO**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2; soc2: CC6.1;

AWS IAM Identity Center is configured but IAM users with console access still exist. Two authentication paths: SSO (controlled by IdP, MFA enforced, session bounded) and IAM users (password-based, MFA optional, no IdP governance). An attacker who targets IAM user credentials bypasses every SSO security control.

**Remediation:** Migrate all console IAM users to AWS IAM Identity Center. Create corresponding user accounts in the identity provider. After verifying SSO access works, delete the IAM console passwords. Retain IAM users only for programmatic access where SSO is not applicable.

---

### CTL.IAM.SSO.MFA.001

**SSO Must Enforce MFA at Identity Center Level**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

MFA is not enforced at the AWS Identity Center level. MFA enforcement may be delegated to the external IdP but if the IdP is configured without MFA for some users, those users access AWS without MFA. Identity Center should enforce MFA independently as defense-in-depth.

**Remediation:** Enable MFA enforcement in AWS IAM Identity Center authentication settings. Configure MFA to be required for all users, not just recommended. Set the MFA type to require hardware or authenticator app tokens — SMS is not sufficient.

---

### CTL.IAM.SSO.PERMSET.ADMIN.001

**SSO Permission Set Must Not Include AdministratorAccess**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

An AWS IAM Identity Center permission set includes AdministratorAccess. Any user or group assigned this permission set gets full admin access to the assigned accounts. SSO makes this easy to configure and hard to notice — one permission set, one group assignment, organization-wide admin.

**Remediation:** Replace the AdministratorAccess policy with scoped permission sets that grant only the permissions needed for the role. Use separate permission sets for different job functions. Reserve admin access for break-glass scenarios with time-limited elevation.

---

### CTL.IAM.SSO.PERMSET.SESSION.001

**SSO Permission Set Session Duration Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-12; soc2: CC6.1;

An IAM Identity Center permission set has a session duration exceeding the recommended threshold. Long session durations extend the window during which credentials are valid — including credentials obtained through the CreateTokenWithIAM impersonation flow. The Identity Center default is 1 hour but permission sets can be configured up to 12 hours. A 12-hour session on a permission set flagged by CTL.IAM.SSO.PERMSET.ADMIN.001 (AdministratorAccess) means impersonated admin credentials remain valid for 12 hours after the initial token exchange.

**Remediation:** Reduce session duration to 4 hours or less. For permission sets with AdministratorAccess or broad privileges, consider 1 hour. Shorter sessions force re-authentication, limiting the blast radius of credential theft through the impersonation feature.

---

### CTL.IAM.SUPPORT.001

**AWS Support Role Must Exist**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.17;

At least one IAM entity must have the AWSSupportAccess managed policy attached. This ensures someone can open support cases during security incidents without using root.

**Remediation:** Create an IAM role with the AWSSupportAccess policy: aws iam attach-role-policy --role-name SupportRole --policy-arn arn:aws:iam::aws:policy/AWSSupportAccess

---

### CTL.IAM.TAGAUTH.COMPLETE.001

**Tag-Based Authorization Scheme Must Be Complete (All Four Layers)**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

COMPOUND. The tag-based authorization scheme has four layers: enforcement (CTL.IAM.SCP.TAGAUTH.ENFORCE.001), tag-mutation lock (CTL.IAM.SCP.TAGAUTH.MUTATION.001), session-tag block (CTL.IAM.RCP.TAGAUTH.SESSION.001), and tagger protection (CTL.IAM.SCP.TAGAUTH.TAGGER.001). All four must hold SIMULTANEOUSLY — if any layer is missing OR present-but-incorrect, the scheme is bypassable, and the bypass path depends on which layer fails.
This control reads the four per-layer derived booleans (each encoding correctness, not mere existence — a layer that exists with the wrong condition operator reports its boolean as false) and fires if ANY is not true. The reasoning spec examples/scp-tag-authorization/ proves the per-layer derivation and the four-way conjunction two ways (Soufflé enumerates the specific bypass path; Z3 proves scheme-complete = AND of the four).

**Remediation:** Fix whichever layer's control is failing: ENFORCE (no enforcement), MUTATION (self-tag exemption), SESSION (session-tag injection), or TAGGER (tagger-role hijack). All four must hold simultaneously.

---

### CTL.IAM.TRUST.CONFUSEDDEPUTY.001

**Account-Root Third-Party Trust Must Have Confused Deputy Protection**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC9.2;

IAM roles trusting a third-party account root principal (arn:aws:iam::X:root from outside the organization) without sts:ExternalId or aws:SourceAccount conditions are maximally exposed to the confused deputy problem. Any customer of the same third-party vendor can assume your role through the vendor's IAM system — because the trust grants access to ALL principals in the account, not just one specific role. The Microsoft Midnight Blizzard 2024 breach exploited a legacy cross-tenant trust without per-customer binding to pivot from a test tenant to production Exchange mailboxes. Account-root trust is critical because the blast radius is the entire third-party account's principal population.

**Remediation:** Add an sts:ExternalId condition with a unique per-relationship value to the role trust policy. Alternatively, add aws:SourceAccount scoped to the specific account that should be permitted. Do not use wildcard values — ExternalId set to * provides no protection.

---

### CTL.IAM.TRUST.CONFUSEDDEPUTY.SCOPED.001

**Scoped Third-Party Trust Should Have Confused Deputy Protection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC9.2;

IAM roles trusting a specific third-party role ARN (arn:aws:iam::X:role/Name from outside the organization) without sts:ExternalId or aws:SourceAccount conditions are exposed to the confused deputy problem. While narrower than account-root trust (only the named role can assume), the missing protection still means a compromise of that specific role in the vendor's account grants immediate access to your resources. ExternalId binds the trust to a specific customer relationship so that the vendor cannot accidentally (or maliciously) route one customer's requests through another customer's role.

**Remediation:** Add an sts:ExternalId condition with a unique per-relationship value to the role trust policy. Alternatively, add aws:SourceAccount scoped to the specific account that should be permitted. Do not use wildcard values — ExternalId set to * provides no protection.

---

### CTL.IAM.TRUST.DUAL.001

**IAM Role Trust Must Not Combine Compute and Identity Federation Without Scoping**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles must not simultaneously trust a compute service principal (lambda.amazonaws.com, ec2.amazonaws.com, ecs-tasks.amazonaws.com, apigateway.amazonaws.com) AND an identity federation principal (cognito-identity.amazonaws.com, sts.amazonaws.com via SAML/OIDC, accounts.google.com) when the identity federation trust carries no condition restricting which identity pool, audience, or external ID can assume the role. The dual-trust pattern is the Capital One pre-condition: the role exists for a Lambda integration; a Cognito trust gets added later for a mobile app and the developer forgets to scope it to the specific identity pool. Any identity pool in the account — including pools that allow unauthenticated access — can obtain credentials for a role intended for a single backend service.

**Remediation:** Either (a) remove the identity federation principal from the trust policy if the role only needs the compute service, or (b) add a Condition that scopes the identity federation trust to the specific pool: for Cognito, "cognito-identity.amazonaws.com:aud" = "<region>:<pool-id>"; for SAML, "saml:aud" = "<application-id>"; for OIDC, "oidc:aud" = "<client-id>". Wildcard audience values provide no protection.

---

### CTL.IAM.TRUST.EXTERNALID.001

**Account-Root Cross-Account Trust Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles trusting an account root principal (arn:aws:iam::X:root) without an sts:ExternalId condition allow ANY principal in the trusted account to assume the role. This is the most dangerous cross-account trust pattern — a compromised service account, OAuth app, or test tenant in the trusted account can assume the role. The Microsoft Midnight Blizzard 2024 breach exploited a legacy test OAuth app to assume a role with full_access_as_app permissions, pivoting from a test tenant to production Exchange mailboxes. Account-root trust without ExternalId is critical because the blast radius is the entire trusted account's principal population.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Generate a unique external ID per trust relationship. Verify the assuming application passes the correct external ID.

---

### CTL.IAM.TRUST.EXTERNALID.SCOPED.001

**Scoped Cross-Account Trust Should Require External ID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles trusting a specific role or user ARN (arn:aws:iam::X:role/Name) without an sts:ExternalId condition still allow that named principal to assume the role without a shared secret. While narrower than account-root trust (only one principal can assume), the missing ExternalId means a compromise of the named role in the trusted account grants immediate lateral movement without any additional credential. ExternalId adds a binding token that limits assumption even if the remote role's credentials are extracted.

**Remediation:** Add an sts:ExternalId condition to the role trust policy. Generate a unique external ID per trust relationship. Verify the assuming application passes the correct external ID.

---

### CTL.IAM.TRUST.GHOST.ACCOUNT.001

**IAM Trust Must Not Reference Unknown External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role trust policies must not allow assumption by principals in external AWS accounts that are not recognized as known partners or organization members. Unknown external trust creates lateral access paths outside the organization's control. AWS does not notify the trusting account when a trusted account changes ownership, is decommissioned, or is compromised.

**Remediation:** Verify the external account relationship. Remove trust if the account is no longer a partner. Add the account to the known-partners configuration if trust is intentional.

---

### CTL.IAM.TRUST.GHOST.ORG.001

**Trust Policy Conditions Must Not Reference Removed OUs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; owasp_nhi: NHI1; soc2: CC6.1;

Trust policies and SCPs using aws:PrincipalOrgPaths conditions must not reference Organizational Units that have been removed from the AWS Organization. A condition referencing a non-existent OU produces unpredictable access behavior — either blocking all access (availability failure) or broadening access (security failure).

**Remediation:** Update the condition to reference active OUs in the organization.

---

### CTL.IAM.TRUST.GHOST.SAML.001

**SAML/OIDC Trust Must Not Reference Stale Identity Providers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM SAML and OIDC provider configurations must not reference identity provider endpoints that are decommissioned, unreachable, or unrecognized. If the provider's endpoint domain is reclaimable (expired domain, abandoned subdomain), an attacker who claims the domain can issue federation tokens accepted by AWS — gaining access to every role trusting the provider. This is the identity equivalent of subdomain takeover.

**Remediation:** Verify the provider endpoint is still active and controlled by the organization. Remove or update the provider if the endpoint is decommissioned.

---

### CTL.IAM.TRUST.OIDC.001

**OIDC Federation Trust Must Be Scoped to Specific Repository**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; owasp_nhi: NHI3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles that trust OIDC identity providers (GitHub Actions, GitLab CI, Bitbucket Pipelines) must restrict the subject claim to a specific repository and branch. A trust policy that accepts any repository from the provider allows any project in the provider's namespace to assume the role — a compromised or malicious repository becomes a production ingress path.

**Remediation:** Add a StringEquals or StringLike condition on the sub claim to restrict to specific repositories and branches. Example for GitHub Actions: "token.actions.githubusercontent.com:sub": "repo:org/repo:ref:refs/heads/main"

---

### CTL.IAM.TRUST.OIDC.002

**OIDC Federation Must Not Use Wildcard Subject Claim**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI3; soc2: CC6.1;

IAM roles with OIDC federation must use exact or prefix-scoped subject claims. A wildcard sub condition ("*") defeats the purpose of OIDC federation — it accepts any identity from the provider, including pull request workflows from forks, ephemeral runners, and compromised pipelines. This is the supply chain equivalent of s3:* on Resource "*".

**Remediation:** Replace the wildcard with an exact subject match. For GitHub Actions: "repo:myorg/myrepo:ref:refs/heads/main". For GitLab CI: "project_path:mygroup/myproject:ref_type:branch:ref:main".

---

### CTL.IAM.TRUST.OIDC.003

**OIDC Federation Role Must Have Scoped Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); owasp_nhi: NHI3; soc2: CC6.1;

IAM roles assumed via OIDC federation (CI/CD pipelines) must have scoped permissions appropriate for their deployment task. A CI/CD role with AdministratorAccess or broad wildcard actions creates a supply chain blast radius — any compromise of the CI/CD pipeline grants full account access. The extractor checks if the role's effective permissions exceed a deployment-appropriate scope.

**Remediation:** Scope the role's permissions to the minimum required for the deployment task. Replace AdministratorAccess with task-specific policies (e.g., s3:PutObject on the deployment bucket, ecs:UpdateService on the target cluster).

---

### CTL.IAM.TRUST.ORGBOUNDARY.001

**Cross-Account Trust Must Restrict to Organization via PrincipalOrgID**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include an aws:PrincipalOrgID condition restricting assumption to principals within the AWS Organization. Without this condition, any external AWS account — including attacker-controlled accounts — can attempt role assumption. PrincipalOrgID is the broadest safe boundary for multi-account organizations: it permits all org members while denying all outsiders.

**Remediation:** Add an aws:PrincipalOrgID condition to the trust policy: "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxxxxxxxxxx"}}. This restricts assumption to principals within the organization.

---

### CTL.IAM.TRUST.SESSION.001

**Cross-Account Trust Must Have Session-Limiting Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles with cross-account trust policies must include at least one session-limiting condition beyond principal identity binding. Without constraints on session duration, source network, or MFA, an assumed-role session is usable from any IP address, without MFA, for the maximum default duration (up to 12 hours). Existing controls verify principal binding (ExternalId, SourceArn, ConfusedDeputy). This control verifies that the trust policy also constrains the assumption context — how long, from where, and with what authentication strength.

**Remediation:** Add at least one of the following conditions to the trust policy: aws:MultiFactorAuthPresent (require MFA), aws:SourceIp or aws:SourceVpc (restrict network origin), or set MaxSessionDuration on the role to limit session lifetime. For cross-account CI/CD roles, combine OIDC subject scoping (covered by CTL.IAM.TRUST.OIDC.*) with a short MaxSessionDuration.

---

### CTL.IAM.TRUST.SOURCEARN.001

**AWS Service Principal Trust Must Have SourceArn or SourceAccount Condition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM roles trusted by AWS service principals (*.amazonaws.com) must include aws:SourceArn or aws:SourceAccount conditions. Without these conditions, the service can assume the role when acting on behalf of any resource in any account — including attacker-controlled resources. AWS Lambda execution roles without aws:SourceArn allow any Lambda function in any account to assume the role. SNS/S3 notification roles without SourceArn allow any bucket or topic in any account to trigger the role assumption.

**Remediation:** Add aws:SourceArn scoped to the specific resource ARN that should trigger the role assumption. If the resource ARN is not known at deploy time, add aws:SourceAccount scoped to your account ID.

---

### CTL.IAM.TRUST.WILDCARD.001

**Trust Policy Must Not Use Wildcard Principal**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role trust policies must not use Principal "*" or Principal: {AWS: "*"}. A wildcard principal allows any AWS principal in any account to attempt role assumption. This is the most dangerous trust configuration — the role is effectively public to the entire AWS ecosystem.

**Remediation:** Replace Principal "*" with specific account ARNs or role ARNs. Add aws:PrincipalOrgID to restrict to the organization. Add sts:ExternalId for third-party integrations.

---

### CTL.IAM.USER.PERMISSIONDRIFT.001

**Users Must Not Accumulate Unused Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; pci_dss_v4.0: 8.1.4; soc2: CC6.3;

IAM users must not retain access to services that have never been used or were last used more than 90 days ago, when the user itself has existed for more than 90 days. A user with 30 accessible services where 25 are never used has accumulated permissions far beyond their operational scope. An attacker who compromises this user's credentials has access to 30 services but the legitimate person only uses 5. The unused 25 are the hidden blast radius. Access Advisor data from AWS provides exact timestamps of last permission use — this is an operational fact, not a security assertion.
User-scoped sibling of CTL.IAM.ROLE.PERMISSIONDRIFT.001 — same Access Advisor drift signal, age guard, and configurable threshold, applied to long-lived IAM users (and their attached/inline/group-inherited policies).

**Remediation:** Review the unused service namespaces listed in this finding. Remove permissions for services that are no longer needed (from attached, inline, and group-inherited policies). For services intentionally retained for emergency use, set the stave/permission-drift-threshold tag on the user to document the justified exception (e.g., stave/permission-drift-threshold=0.40). Prefer migrating humans to federated short-lived roles over long-lived IAM users.

---

### CTL.IAM.VENDOR.DORMANT.001

**Vendor Cross-Account Role Must Not Be Dormant**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

Cross-account roles granted to external vendors (SaaS providers, auditors, consultants) must be actively used or decommissioned. A vendor role unused for more than 90 days is "ghost access" — the vendor may no longer need it, the contract may have ended, but the access persists. Each dormant vendor role is an unmonitored ingress path that can be exploited if the vendor is compromised.

**Remediation:** Review the vendor relationship. If the contract has ended or the vendor no longer needs access, delete the cross-account role. If access is still needed, re-verify the trust policy and scope permissions to current requirements.

---

### CTL.IAM.VENDOR.OVERPRIVILEGED.001

**Vendor Role Must Not Reach Excessive Sensitive Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); pci_dss_v4.0: 7.2.2; soc2: CC6.1;

External vendor roles must have scoped access to sensitive resources. A vendor that can reach more than 10 sensitive resources (PHI, PII, confidential) has a disproportionate blast radius — if the vendor is compromised, the attacker gains broad access to your most sensitive data through a third-party trust relationship.

**Remediation:** Scope the vendor role permissions to the minimum required resources. Create per-function roles for different vendor tasks. Use resource-based policies to restrict vendor access to specific non-sensitive resources.

---

### CTL.IAM.ZT.PERIMETER.001

**Sensitive Resources Must Use Identity-Based Access Not Network Perimeter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; nist_csf_2.0: PR.AA; owasp_nhi: NHI5;

Access to sensitive resources must be governed by identity-based controls (IAM policies, conditions, session tags) rather than relying solely on network perimeter (VPC, security groups, NACLs). Network-only access control fails when the perimeter is bypassed — via VPN compromise, lateral movement, or insider threat. Zero Trust requires every access decision to verify identity, device, and context.

**Remediation:** Add IAM-based access controls (resource policies with principal constraints, IAM conditions for aws:PrincipalTag, VPC endpoint policies with principal scoping). Use AWS Verified Access or IAM Roles Anywhere for workload identity.

---

### CTL.IAM.ZT.SHORTLIVED.001

**Service Access Must Use Short-Lived Credentials**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-5; nist_800_53_r5: IA-5; nist_csf_2.0: PR.AA; owasp_nhi: NHI5;

Service-to-service access must use short-lived credentials (STS temporary tokens, IAM Roles Anywhere certificates, OIDC federation) rather than long-lived access keys. Short-lived credentials limit the blast radius of compromise — a stolen token expires automatically. This is a core Zero Trust principle: never trust a credential longer than necessary.

**Remediation:** Replace long-lived access keys with IAM roles (for EC2, ECS, Lambda), IAM Roles Anywhere (for on-premises), or OIDC federation (for CI/CD). Use STS AssumeRole with session duration limits.

---

