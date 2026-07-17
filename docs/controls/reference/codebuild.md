# Control Reference — CODEBUILD

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CODEBUILD.BUILDSPEC.USERCONTROLLED.001

**CodeBuild Projects Must Not Use User-Controlled Buildspecs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC8.1;

CodeBuild projects should use centrally managed buildspec definitions, not user-controlled buildspec files from the source repository. Repository-controlled buildspecs allow unreviewed pull request changes to execute arbitrary commands in the CI environment under the project's IAM role.

**Remediation:** Use an inline buildspec or a buildspec stored in a separate, access-controlled location. If repository buildspecs are required, enforce branch protection and require approvals before builds execute on PR changes.

---

### CTL.CODEBUILD.ENCRYPT.REPORTS.001

**CodeBuild Report Group Exports Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

CodeBuild report groups exporting to S3 must encrypt exported test results at rest with a KMS key. Unencrypted reports may contain test data, code coverage metrics, and build artifacts.

**Remediation:** Enable KMS encryption on the report group S3 export configuration.

---

### CTL.CODEBUILD.ENCRYPT.S3LOGS.001

**CodeBuild S3 Build Logs Must Be Encrypted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28;

CodeBuild projects delivering logs to S3 must encrypt log objects at rest. Unencrypted build logs can expose source structure, dependency versions, test results, and secrets leaked during build.

**Remediation:** Enable encryption on S3 log delivery in the build project configuration.

---

### CTL.CODEBUILD.GITHUB.TRUST.001

**CodeBuild GitHub Source Must Not Allow Untrusted PR Triggers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC8.1;

CodeBuild projects with GitHub source must not allow builds triggered by pull requests from any contributor without an approval gate. An attacker creates a pull request that triggers a CodeBuild run, gaining access to the build environment's IAM role and any secrets in environment variables. Extends CTL.CODEBUILD.WEBHOOK.ANCHORED.001 (regex anchoring) and CTL.CODEBUILD.BUILDSPEC.USERCONTROLLED.001 (buildspec source) with explicit PR trigger trust validation. Technique: hackingthe.cloud CodeBuild GitHub runner persistence.

**Remediation:** Configure webhook filters to restrict PULL_REQUEST_CREATED events to trusted actors. Use ACTOR_ACCOUNT_ID filters with anchored patterns. Enable build approval for external contributions.

---

### CTL.CODEBUILD.INACTIVE.001

**CodeBuild Projects Must Not Be Inactive for Over 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-8; soc2: CC6.1;

CodeBuild projects not invoked in over 90 days should be reviewed and decommissioned. Inactive projects retain webhooks, source credentials, and IAM roles — dormant attack surface with stale permissions.

**Remediation:** Review the project. If no longer needed, delete it and its associated IAM role and webhooks. If still needed, document the justification.

---

### CTL.CODEBUILD.LOG.001

**CodeBuild Projects Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

CodeBuild projects must have at least one log destination enabled (CloudWatch Logs or S3). Without logging, build execution details, errors, and security events are invisible — a compromised build leaves no forensic trail.

**Remediation:** Enable CloudWatch Logs or S3 log delivery in the project configuration.

---

### CTL.CODEBUILD.PRIVILEGED.001

**CodeBuild Projects Must Not Use Docker Privileged Mode**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

CodeBuild projects must not enable Docker privileged mode unless building Docker images is required. Privileged mode grants the build container full access to the host, enabling container escape. A compromised build with privileged mode gains the build role's permissions on the underlying host.

**Remediation:** Disable privileged mode unless building Docker images. If Docker-in-Docker is required, use a dedicated project with a narrowly scoped IAM role.

---

### CTL.CODEBUILD.PUBLIC.001

**CodeBuild Projects Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

CodeBuild project visibility must be PRIVATE. Projects with PUBLIC_READ visibility allow anyone to access build results, logs, and artifacts — exposing source code structure, dependency versions, deployment targets, and potentially secrets leaked in build output.

**Remediation:** Set project visibility to PRIVATE via aws codebuild update-project-visibility.

---

### CTL.CODEBUILD.ROLE.001

**CodeBuild Project Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

CodeBuild project service roles must be scoped to the minimum permissions required for the build. Overprivileged build roles allow a compromised build to access resources beyond what the build needs — reading secrets, deploying to production, or modifying IAM policies.

**Remediation:** Scope the service role to the minimum permissions: source pull, artifact push, log write. Remove permissions for services the build does not interact with.

---

### CTL.CODEBUILD.SECRETS.001

**CodeBuild Projects Must Not Store Secrets in Plaintext Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); pci_dss_v4.0: 3.4.1; soc2: CC6.1;

CodeBuild project environment variables of type PLAINTEXT must not contain secrets (API keys, tokens, passwords). Plaintext env vars are visible in the AWS console, CLI output, and CloudTrail logs. Use SECRETS_MANAGER or PARAMETER_STORE environment variable types instead.

**Remediation:** Change environment variable types from PLAINTEXT to SECRETS_MANAGER or PARAMETER_STORE. Store secrets in AWS Secrets Manager or SSM Parameter Store and reference them by name in the environment variable configuration.

---

### CTL.CODEBUILD.SOURCE.CREDS.001

**CodeBuild Source Repository URLs Must Not Embed Credentials**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

CodeBuild project source repository URLs must not contain embedded authentication tokens or username:password patterns. Embedded credentials in URLs are logged in CloudTrail, visible in the console, and persist in project configuration.

**Remediation:** Remove credentials from the URL. Use CodeBuild source credentials (OAuth, personal access token, or CodeConnections) configured separately from the repository URL.

---

### CTL.CODEBUILD.SOURCE.ORG.001

**CodeBuild GitHub Source Must Use Allowed Organizations**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SA-12; soc2: CC6.1;

CodeBuild projects sourcing from GitHub must reference repositories in approved organizations. Repos from untrusted organizations can let external contributors trigger builds that execute under the project's IAM role.

**Remediation:** Restrict source repositories to approved organizations. Configure an organization allowlist and validate source URLs against it.

---

### CTL.CODEBUILD.WEBHOOK.ANCHORED.001

**CodeBuild Webhook Filters Must Use Anchored Regex Patterns**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

CodeBuild webhook filters using ACTOR_ACCOUNT_ID, HEAD_REF, or BASE_REF must anchor regex patterns with ^ and $ for exact matching. Unanchored patterns allow substring bypass — an attacker creates a GitHub account whose ID contains the trusted value as a substring. This is the "CodeBreach" vulnerability disclosed by Wiz Research.

**Remediation:** Update all ACTOR_ACCOUNT_ID, HEAD_REF, and BASE_REF filter patterns to use ^ (start anchor) and $ (end anchor) for exact matching. Example: change "12345" to "^12345$".

---

