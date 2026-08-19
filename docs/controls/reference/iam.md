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
- **Compliance:** cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; owasp_nhi: NHI1; owasp_subtractive: S07; pci_dss_v4.0: 8.1.4; soc2: CC6.2; subtractive_tier: deletion;

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

### CTL.IAM.AGENT.SESSION.DURATION.001

**Agent Role MaxSessionDuration Exceeds 1 Hour**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-12; owasp_nhi: NHI4; soc2: CC6.1;

An agent-identified IAM role allows session durations above 1 hour. Agent roles — identified by trust policy service principals (bedrock/sagemaker/lambda/states), name patterns (*agent*, *bot*, *automation*, *pipeline*), or workload-type tags — should use the shortest practical session duration. If an agent is compromised through prompt injection or tool abuse, longer sessions give the attacker more time to operate with the agent's credentials before they expire. The general-purpose CTL.IAM.SESSION.DURATION.001 fires at 4 hours; this control tightens the threshold to 1 hour for agent workloads specifically, following the CSA/SANS recommendation from the Hugging Face autonomous agent breach post-mortem (2026).

**Remediation:** Set MaxSessionDuration to 3600 seconds (1 hour) via aws iam update-role --role-name ROLE --max-session-duration 3600. If the agent's task genuinely requires longer sessions, document the justification and use CTL.IAM.SESSION.DURATION.001 (4-hour threshold) as the fallback control.

---

### CTL.IAM.AMPLIFY.ADMIN.001

**IAM Policy Grants Amplify App Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting amplify:CreateApp. Amplify apps provision CloudFront distributions, S3 buckets, Lambda@Edge functions, and IAM roles — internet-facing infrastructure invisible to the standard CloudFront, S3, and Lambda management APIs.

**Remediation:** Remove amplify:CreateApp from the principal's policies.

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
- **Compliance:** nist_800_53_r5: AC-6(3); owasp_subtractive: S07; scs_c02: 12.5; soc2: CC6.1; subtractive_tier: deletion;

No IAM Access Analyzer of type UNUSED_ACCESS exists. The unused access analyzer identifies IAM roles and users with permissions they have not used within a specified period, plus unused access keys and passwords. Without it, over-privileged identities accumulate permissions that expand the blast radius of credential compromise.

**Remediation:** Create an unused access analyzer: aws accessanalyzer create-analyzer --analyzer-name unused-access --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess": {"unusedAccessAge": 90}}'.

---

### CTL.IAM.APPRUNNER.ADMIN.001

**IAM Policy Grants App Runner Service Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting apprunner:CreateService. App Runner services have public HTTPS endpoints by default and execute with an IAM role. The created compute is invisible to ec2:DescribeInstances and runs in an AWS-managed VPC outside standard network security monitoring.

**Remediation:** Remove apprunner:CreateService from the principal's policies unless App Runner usage is explicitly governed.

---

### CTL.IAM.BEANSTALK.ADMIN.001

**IAM Policy Grants Elastic Beanstalk Environment Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting elasticbeanstalk:CreateEnvironment. Beanstalk environments provision EC2 instances, Auto Scaling groups, Elastic Load Balancers, security groups, and optionally RDS databases — internet-facing infrastructure with Beanstalk-managed defaults that may not match organizational security baselines.

**Remediation:** Remove elasticbeanstalk:CreateEnvironment from the principal's policies.

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

### CTL.IAM.BOUNDARY.PAYER.ASSUMEROOT.001

**Payer Permission Boundary Must Deny sts:AssumeRoot**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny sts:AssumeRoot for non-admin principals. AssumeRoot allows a principal to obtain temporary credentials with root-level privileges in a member account. If the management account is compromised and the boundary doesn't deny AssumeRoot, the attacker can escalate to root in any member account.

**Remediation:** Add an explicit Deny for sts:AssumeRoot to the permission boundary policy. Only the break-glass admin role should be exempt.

---

### CTL.IAM.BOUNDARY.PAYER.CONTROLTOWER.001

**Payer Permission Boundary Must Deny Control Tower Configuration Changes**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny controltower:DeregisterOrganizationalUnit, controltower:DisableControl, controltower:DeleteLandingZone, and controltower:UpdateLandingZone. Control Tower enforces guardrails across the organization via managed SCPs and Config rules. If the management account is compromised, an attacker can deregister OUs (removing all managed guardrails), disable individual controls, or delete the landing zone entirely — undermining all governance without touching the SCPs directly. The drift check (CTL.ORG.CONTROLTOWER.DRIFT.001) detects after-the-fact drift but does not prevent the mutation.

**Remediation:** Add an explicit Deny for controltower:DeregisterOrganizationalUnit, controltower:DisableControl, controltower:DeleteLandingZone, and controltower:UpdateLandingZone to the permission boundary. Only the governance-admin break-glass role should have these permissions.

---

### CTL.IAM.BOUNDARY.PAYER.IDENTITYCENTER.001

**Payer Permission Boundary Must Deny IAM Identity Center Configuration Changes**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny sso:CreateInstance, sso:DeleteInstance, sso-directory:*, and sso:UpdateInstanceAccessControlAttributeConfiguration. IAM Identity Center is the primary identity federation surface for AWS Organizations. If the management account is compromised, an attacker can create a new Identity Center instance with their own identity store, provision admin access to every member account, and delete the original instance — replacing the entire identity plane. The enablement check (CTL.ORG.IDENTITYCENTER.ENABLED.001) verifies Identity Center is ON, but does not prevent unauthorized reconfiguration.

**Remediation:** Add an explicit Deny for sso:CreateInstance, sso:DeleteInstance, sso-directory:*, and sso:UpdateInstanceAccessControlAttributeConfiguration to the permission boundary. Only the identity-admin break-glass role should have these permissions.

---

### CTL.IAM.BOUNDARY.PAYER.ORGMUTATION.001

**Payer Permission Boundary Must Deny Organization Mutation Actions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny organizations mutation actions (organizations:Create*, organizations:Delete*, organizations:Update*, organizations:Move*, organizations:Leave*). If the management account is compromised, the attacker can restructure the organization — moving accounts between OUs to escape SCPs, removing accounts from the org, or creating new OUs without governance.

**Remediation:** Add an explicit Deny for organizations:Create*, organizations:Delete*, organizations:Update*, organizations:Move*, organizations:Leave* to the permission boundary. Only the org-admin break-glass role should have these permissions.

---

### CTL.IAM.BOUNDARY.PAYER.SELFMODIFY.001

**Payer Permission Boundary Must Deny Self-Modification of Boundary Policies**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny iam:CreatePolicy, iam:CreatePolicyVersion, and iam:DeletePolicyVersion on its own boundary policy ARN. A boundary that allows self-modification is advisory — the bounded principal can rewrite the boundary to remove all restrictions while keeping it attached. Unlike boundary removal (CTL.IAM.BOUNDARY.PAYER.SELFREMOVAL.001), this attack leaves the boundary attached but hollow, evading detection that monitors for boundary detachment events.

**Remediation:** Add an explicit Deny for iam:CreatePolicyVersion and iam:DeletePolicyVersion to the boundary policy, scoped to the boundary policy's own ARN. This prevents the bounded principal from rewriting the boundary while it remains attached.

---

### CTL.IAM.BOUNDARY.PAYER.SELFREMOVAL.001

**Payer Permission Boundary Must Deny Its Own Removal**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

Permission boundary in the management account does not deny iam:DeleteRolePermissionsBoundary and iam:PutRolePermissionsBoundary on its own role. A boundary that doesn't prevent self-removal is advisory — the bounded principal can remove the boundary and instantly gain all permissions granted by its identity policies. This is the boundary escape vector specific to management account roles where the blast radius is the entire organization.

**Remediation:** Add an explicit Deny for iam:DeleteRolePermissionsBoundary and iam:PutRolePermissionsBoundary to the boundary policy, scoped to the role's own ARN.

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

### CTL.IAM.CICD.SCOPE.001

**CI/CD IAM Role Has Overly Broad Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.1;

IAM role assumed by a CI/CD system via OIDC federation has AdministratorAccess or permissions spanning more than five service namespaces. Even with OIDC federation eliminating long-lived credentials, an overpermissioned CI/CD role gives an attacker who compromises the pipeline everything they need. Drizly's attacker reconfigured AWS security settings — implying admin-level access from the CI/CD credential. CI/CD roles should have the minimum permissions needed for deployment.

**Remediation:** Replace AdministratorAccess with a scoped policy that grants only the permissions the CI/CD pipeline needs. Typical CI/CD roles need: S3 for artifacts, ECR for container images, CloudFormation or CDK for deployments, and the specific services being deployed. Use separate roles for separate pipeline stages (build vs deploy).

---

### CTL.IAM.CLOUD9.ADMIN.001

**IAM Policy Grants Cloud9 Environment Creation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting cloud9:CreateEnvironmentEC2. Cloud9 environments create EC2 instances with security groups and inherit the creating principal's credentials. Environments can have direct SSH access from the internet.

**Remediation:** Remove cloud9:CreateEnvironmentEC2 from the principal's policies.

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
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; owasp_subtractive: S07; pci_dss_v4.0: 8.1.4; soc2: CC7.1; subtractive_tier: deletion;

IAM user console password has been disabled and re-enabled more than once in 30 days. Password lifecycle manipulation — disable, re-enable, repeat — is the pattern of an attacker maintaining persistence through credential lifecycle events that would otherwise revoke access.

**Remediation:** Investigate the root cause of the repeated oscillation. Determine whether the pattern indicates a broken process, operational workaround, or active compromise. Review CloudTrail for the API calls that triggered each transition.

---

### CTL.IAM.CRED.ROTATION.001

**Access Keys Must Be Rotated Within 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.14; cis_aws_v3.0: 1.14; fedramp_moderate: IA-5(1); hipaa: 164.312(a)(2)(i); nist_800_53_r5: IA-5(1); owasp_nhi: NHI7; owasp_subtractive: S07; pci_dss_v3.2.1: 8.2.4; pci_dss_v4.0: 8.3.9; soc2: CC6.1; subtractive_tier: deletion;

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
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(d); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, AC-2; owasp_nhi: NHI7; owasp_subtractive: S07; pci_dss_v4.0: 8.3.5; soc2: CC6.1; subtractive_tier: deletion;

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
- **Compliance:** cis_aws_v1.4.0: 1.12; cis_aws_v3.0: 1.12; fedramp_moderate: AC-2; hipaa: 164.312(a)(2)(i); nist_800_53_r5: AC-2; owasp_nhi: NHI1; owasp_subtractive: S07; pci_dss_v4.0: 8.1.4; soc2: CC6.2; subtractive_tier: deletion;

IAM credentials unused for 90 days or more must be disabled. Dormant credentials are a persistent attack surface that provides access without triggering normal usage patterns.

**Remediation:** Disable or delete unused credentials. Review the user's need for access and remove the IAM user if no longer required.

---

### CTL.IAM.CRED.UNUSED45.001

**Disable Credentials Unused for 45 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.12; owasp_nhi: NHI1; owasp_subtractive: S07; subtractive_tier: deletion;

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

### CTL.IAM.CROSSCLOUD.MFA.001

**MFA Must Be Enforced Across All Cloud Providers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; soc2: CC6.1;

All privileged accounts across all cloud providers must have MFA enforced. This control extends AWS MFA controls to Azure AD (Conditional Access requiring MFA) and GCP (2-Step Verification enforcement). A single cloud account without MFA is a breach vector regardless of how well other clouds are protected.

**Remediation:** Enforce MFA at the identity provider level. AWS: IAM MFA policy conditions. Azure: Conditional Access policies. GCP: 2-Step Verification enforcement in Workspace/Cloud Identity.

---

### CTL.IAM.EMR.ADMIN.001

**IAM Policy Grants EMR Job Flow Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting elasticmapreduce:RunJobFlow. EMR clusters provision EC2 instances with overpermissioned default security groups (ElasticMapReduce-master and ElasticMapReduce-slave) and IAM roles with S3 and KMS access for data processing.

**Remediation:** Remove elasticmapreduce:RunJobFlow from the principal's policies.

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

### CTL.IAM.ESCALATE.ATTACHGROUPPOLICY.NOCONDITION.001

**Principal Has Unrestricted iam:AttachGroupPolicy Without Policy ARN Condition**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:AttachGroupPolicy` but the granting statement lacks a `Condition` restricting which policy ARNs can be attached. Without a `StringEquals`, `StringLike`, or `ArnEquals` condition on the `iam:PolicyARN` key, the principal can attach any of AWS's 1,000+ managed policies — including `AdministratorAccess` and `SecretsManagerReadWrite` — to any group it can target. If the principal belongs to the targeted group, every member (including the principal) inherits the attached policy. The safe pattern scopes attachment to a whitelist of approved policy ARNs via `iam:PolicyARN` condition. Absence of this condition converts a scoped delegation into a full privilege-escalation path with group-wide blast radius.
Scope: gated on `identity.kind == "user"`. Fires only when `attach_group_policy.present` is true AND `has_policy_arn_condition` is false — i.e., the grant exists and is unrestricted.

**Remediation:** Add a `Condition` block with `ArnEquals` or `StringEquals` on `iam:PolicyARN` to restrict which managed policies can be attached. Example: `"Condition": {"ArnEquals": {"iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}}`. If the principal should not attach group policies at all, remove `iam:AttachGroupPolicy` entirely.

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

### CTL.IAM.ESCALATE.ATTACHROLEPOLICY.NOCONDITION.001

**Principal Has Unrestricted iam:AttachRolePolicy Without Policy ARN Condition**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:AttachRolePolicy` but the granting statement lacks a `Condition` restricting which policy ARNs can be attached. Without a `StringEquals`, `StringLike`, or `ArnEquals` condition on the `iam:PolicyARN` key, the principal can attach any of AWS's 1,000+ managed policies — including `AdministratorAccess` and `AmazonS3FullAccess` — to any role it can target. Combined with `sts:AssumeRole` trust on the target role, this creates a two-stage escalation: modify the role's permissions, then assume it. The safe pattern scopes attachment to a whitelist of approved policy ARNs via `iam:PolicyARN` condition and restricts the Resource field to specific role ARNs. Absence of the condition converts a scoped delegation into a full privilege-escalation path.
Scope: applies to both users and roles (matching `CTL.IAM.ESCALATE.ATTACHROLEPOLICY.001`). Fires when `attach_role_policy.present` is true AND `has_policy_arn_condition` is false — i.e., the grant exists and is unrestricted.

**Remediation:** Add a `Condition` block with `ArnEquals` or `StringEquals` on `iam:PolicyARN` to restrict which managed policies can be attached. Example: `"Condition": {"ArnEquals": {"iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}}`. Also scope the Resource to specific role ARNs. If the principal should not attach role policies at all, remove `iam:AttachRolePolicy` entirely.

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

### CTL.IAM.ESCALATE.ATTACHUSERPOLICY.NOCONDITION.001

**Principal Has Unrestricted iam:AttachUserPolicy Without Policy ARN Condition**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:AttachUserPolicy` but the granting statement lacks a `Condition` restricting which policy ARNs can be attached. Without a `StringEquals`, `StringLike`, or `ArnEquals` condition on the `iam:PolicyARN` key, the principal can attach any of AWS's 1,000+ managed policies — including `AdministratorAccess` and `SecretsManagerReadWrite` — to any user it can target. The safe pattern scopes attachment to a whitelist of approved policy ARNs via `iam:PolicyARN` condition. Absence of this condition converts a scoped delegation into a full privilege-escalation path.
Scope: gated on `identity.kind == "user"`. Fires only when `attach_user_policy_self.present` is true AND `has_policy_arn_condition` is false — i.e., the grant exists and is unrestricted.

**Remediation:** Add a `Condition` block with `ArnEquals` or `StringEquals` on `iam:PolicyARN` to restrict which managed policies can be attached. Example: `"Condition": {"ArnEquals": {"iam:PolicyARN": "arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess"}}`. If the principal should not attach policies at all, remove `iam:AttachUserPolicy` entirely.

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

### CTL.IAM.ESCALATE.CREATEINVESTIGATION.NOCONDITION.001

**Principal Has guardduty:CreateInvestigation Without Restriction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

A principal has guardduty:CreateInvestigation in its effective permissions with Resource "*" and no condition keys. This action triggers AI-powered investigation agents that analyze findings, correlate events across CloudTrail, VPC Flow Logs, and DNS logs, and produce automated root cause analysis. An unrestricted grant allows any holder to trigger investigations across the entire account — consuming GuardDuty investigation credits and potentially accessing correlated security event data that exceeds the principal's intended scope.

**Remediation:** Scope the guardduty:CreateInvestigation grant to specific detector ARNs via the Resource field. Add condition keys (aws:SourceAccount, aws:RequestedRegion) to limit where investigations can be triggered. Consider restricting to a dedicated security operations role.

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

### CTL.IAM.ESCALATE.PUTGROUPPOLICY.NOCONDITION.001

**Principal Has iam:PutGroupPolicy With Resource Covering Belonging Group**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:PutGroupPolicy` and the Resource field covers a group the principal belongs to. Unlike `iam:AttachGroupPolicy` which can be condition-restricted via `iam:PolicyARN`, there is no IAM Condition key that restricts the *content* of an inline policy written via PutGroupPolicy. Every PutGroupPolicy grant is inherently unrestricted in what policy document the caller can write — the only available defense is restricting the Resource field to groups the principal does not belong to. When the Resource covers a belonging group, the principal can author an arbitrary inline policy document (including `"Action": "*"` on `"Resource": "*"`) and inject it onto that group, elevating every member — including the principal — with a single API call. This combines the worst properties of PutUserPolicy (attacker-authored payload) and AttachGroupPolicy (group-wide blast radius).
Scope: gated on `identity.kind == "user"`. Fires when the principal has `iam:PutGroupPolicy` and the Resource scope includes a group the principal belongs to. The capability-only variant is detected by `CTL.IAM.ESCALATE.PUTGROUPPOLICY.001`.

**Remediation:** Scope `iam:PutGroupPolicy` Resource to groups the principal does not belong to, or remove the permission entirely. SCP-level deny on `iam:PutGroupPolicy` where the target group contains the calling principal closes the path.

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

### CTL.IAM.ESCALATE.PUTROLEPOLICY.NOCONDITION.001

**Principal Has iam:PutRolePolicy Without Content Restriction**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:PutRolePolicy` in its effective permissions. Unlike `iam:AttachRolePolicy` which can be condition-restricted via `iam:PolicyARN`, there is no IAM Condition key that restricts the *content* of an inline policy written via PutRolePolicy. Every PutRolePolicy grant is inherently unrestricted in what policy document the caller can write — the only available defense is restricting the Resource field (which roles can be targeted). This makes PutRolePolicy structurally more dangerous than AttachRolePolicy: the attacker authors the payload (arbitrary Action/Resource/Effect JSON) rather than selecting from existing managed policies. Combined with `sts:AssumeRole` trust on the target role, this creates a two-stage escalation: write an admin inline policy onto the role, then assume it.
Scope: applies to both users and roles (matching `CTL.IAM.ESCALATE.PUTROLEPOLICY.001`). Fires when the principal has `iam:PutRolePolicy` in its effective permissions regardless of resource scope. The self-targeting variant (role writing to its own ARN) is also detected by `CTL.IAM.ESCALATE.PUTROLEPOLICY.001`.

**Remediation:** Remove `iam:PutRolePolicy` from the principal. If the principal must manage inline policies for service roles, scope the Resource field to specific role ARNs that do not include the principal itself or any role it can assume. Deny at the organization boundary with an SCP.

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

### CTL.IAM.ESCALATE.PUTUSERPOLICY.NOCONDITION.001

**Principal Has iam:PutUserPolicy Without Content Restriction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A principal has `iam:PutUserPolicy` in its effective permissions. Unlike `iam:AttachUserPolicy` which can be condition-restricted via `iam:PolicyARN`, there is no IAM Condition key that restricts the *content* of an inline policy written via PutUserPolicy. Every PutUserPolicy grant is inherently unrestricted in what policy document the caller can write — the only available defense is restricting the Resource field (which users can be targeted). This makes PutUserPolicy structurally more dangerous than AttachUserPolicy: the attacker authors the payload (arbitrary Action/Resource/Effect JSON) rather than selecting from existing managed policies.
Scope: gated on `identity.kind == "user"`. Fires when the principal has `iam:PutUserPolicy` in its effective permissions regardless of whether the Resource includes the principal's own ARN. The self-targeting variant is detected by `CTL.IAM.ESCALATE.PUTUSERPOLICY.001`.

**Remediation:** Remove `iam:PutUserPolicy` from the principal. If the principal must manage inline policies for service accounts, scope the Resource field to specific user ARNs that do not include the principal itself. Deny at the organization boundary with an SCP.

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

### CTL.IAM.EVS.CREATE.001

**IAM Policy Grants EVS Environment Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting evs:CreateEnvironment. This allows provisioning a full VMware SDDC in an AWS-managed account — the resulting infrastructure runs outside the customer's VPC, is not inventoried by AWS Config, and creates a VMware management plane invisible to CloudWatch, GuardDuty, and Security Hub. This is both a resource-sprawl and a detection-evasion vector.

**Remediation:** Remove evs:CreateEnvironment from the principal's policies.

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

### CTL.IAM.FEDERATION.SAML.SOURCE.001

**SAML Provider Must Be From Recognized Identity Source**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-8; owasp_nhi: NHI3; soc2: CC6.1;

IAM SAML provider's metadata references an identity provider that is not in the recognized provider list. Same risk as unrecognized OIDC providers: a SAML provider from an unknown source is either shadow federation or compromise. The collector parses the entityID from the SAML metadata document and checks it against the approved IdP list.

**Remediation:** Verify the SAML provider entityID is intentional and from a trusted identity source. If the provider is legitimate, add it to the recognized provider list. If not, delete the provider and audit all roles that reference it.

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

### CTL.IAM.FOOTHOLD.CICD.ECR.001

**CI/CD Role Can Push Container Images to ECR**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

A CI/CD-identified role has effective permissions to push container images to ECR (ecr:PutImage, ecr:BatchPutImage, ecr:CompleteLayerUpload). If the pipeline is compromised through a supply chain attack on a dependency, the attacker can publish backdoored container images that production services pull. This is the artifact-poisoning leg of the supply chain propagation compound.

**Remediation:** Scope ECR push permissions to specific repositories. Use ECR repository policies to restrict which roles can push, and enable image scanning on push to detect known vulnerabilities in published images.

---

### CTL.IAM.FOOTHOLD.CICD.S3.001

**CI/CD Role Can Write Deployment Artifacts to S3**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

A CI/CD-identified role has effective permissions to write objects to S3 (s3:PutObject). S3 buckets are the standard artifact store for Lambda deployment zips, CloudFormation templates, Terraform state, and Helm charts. If the pipeline is compromised through a supply chain attack, the attacker modifies deployment artifacts — injecting backdoors into Lambda functions, CloudFormation templates, or Terraform state files that execute on next deploy.

**Remediation:** Scope S3 write permissions to specific bucket ARNs and key prefixes. Use S3 Object Lock on artifact buckets to prevent overwrite of released artifacts. Enable S3 versioning so tampered artifacts are detectable.

---

### CTL.IAM.FOOTHOLD.CICD.SECRETS.001

**CI/CD Role Can Read Production Secrets**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

A CI/CD-identified role has effective permissions to read secrets from Secrets Manager (secretsmanager:GetSecretValue) or SSM Parameter Store SecureStrings (ssm:GetParameter). If the pipeline is compromised through a supply chain attack, the attacker harvests database credentials, API keys, and service tokens. The TeamPCP/Trivy attack (March 2026) stole the BerriAI/LiteLLM PyPI publishing token from Secrets Manager through exactly this path.

**Remediation:** Restrict secrets access to only the specific secrets the pipeline needs. Use resource-based conditions to scope secretsmanager:GetSecretValue to named secret ARNs. If the pipeline only needs secrets at deploy time, use a separate deploy-phase role with time-limited access.

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

### CTL.IAM.GROUP.SENSITIVE.ACCESS.001

**IAM Group Grants Access to Sensitive Services**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

IAM group has policies granting access to sensitive services (SecretsManager, KMS Decrypt, S3 object read, RDS data access). Alone this is informational — groups should grant what their members need. Combined with AddUserToGroup on a principal that is not a current member, the group becomes a one-call escalation target to data-plane access. The extractor evaluates the group's effective policy set and flags groups where the union of attached and inline policies includes data-access actions.

**Remediation:** Review whether the group needs broad data-service access. Prefer task-specific groups with scoped resource ARNs over groups granting service-wide access. Restrict AddUserToGroup to prevent unauthorized group joins.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.001

**Role Blast Radius Must Not Exceed Resource Threshold**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_subtractive: S05; soc2: CC6.1; subtractive_tier: deletion;

IAM roles must not be able to reach more than 50 resources through direct permissions and transitive role assumption chains. A role with wide blast radius means a single credential compromise gives an attacker access to a large surface area. The extractor computes reachable resources by traversing sts:AssumeRole edges and collecting data access permissions per reachable role.

**Remediation:** Reduce the role's permissions to the minimum set of resources required. Split broad roles into per-service roles with scoped Resource ARNs. Use IAM Access Analyzer to identify unused permissions for removal.

---

### CTL.IAM.IDENTITY.BLASTRADIUS.002

**Cross-Account Role Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; owasp_subtractive: S05; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

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

### CTL.IAM.IDENTITY.RATIO.001

**Excessive Machine-to-Human Identity Ratio**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI1; soc2: CC6.1;

IAM role count exceeds 200 times the IAM user count, indicating a high machine-to-human identity ratio. A high ratio signals potential NHI governance gaps: unused service-linked roles, orphaned automation roles, or unconstrained role provisioning. This is a governance indicator, not a security finding — accounts with heavy automation may legitimately have many roles.

**Remediation:** Review IAM roles with IAM Access Analyzer to identify unused roles. Remove orphaned service-linked roles for services no longer in use. Consolidate Lambda execution roles where functions share the same permission boundary.

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

### CTL.IAM.MANAGED.ACCOUNTMGMT.001

**Account Management Policy Must Not Be Attached Outside Management Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1098; nist_800_53_r5: AC-6(1); soc2: CC6.3;

The AWSManagedAccountManagementAccess policy grants full IAM lifecycle actions including iam:CreateRole, iam:DeleteRole, iam:AttachRolePolicy, iam:PutRolePolicy, and iam:UpdateAssumeRolePolicy. This policy is intended for management account principals performing account setup automation. Attachment to a principal in a member account grants that principal unrestricted IAM policy management — a direct privilege escalation vector. The policy also grants iam:PutRolePermissionsBoundary, making boundary enforcement ineffective because the principal can remove its own boundary.

**Remediation:** Remove the AWSManagedAccountManagementAccess policy from member account principals. If account setup automation is needed in member accounts, create a scoped policy with only the specific IAM actions required, constrained by permission boundaries and resource-level conditions.

---

### CTL.IAM.MANAGED.ACCOUNTMGMT.BOUNDARY.001

**Roles Created Via Account Management Must Have Permission Boundaries**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); pci_dss_v4.0: 7.2.2; soc2: CC6.3;

Roles created through account management workflows (using AWSManagedAccountManagementAccess or equivalent) must have a permission boundary attached. The account management policy grants both iam:CreateRole and iam:PutRolePermissionsBoundary. If the workflow creates roles without boundaries, those roles have no upper bound on their effective permissions — the management policy becomes an unrestricted role factory. The boundary is the only mechanism that constrains what the created roles can do.

**Remediation:** Attach a permission boundary to the role that limits its effective permissions to the intended scope. Modify the account management workflow to require iam:PermissionsBoundary as a condition on iam:CreateRole calls.

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

### CTL.IAM.MWAA.ADMIN.001

**IAM Policy Grants MWAA Environment Creation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting airflow:CreateEnvironment. MWAA environments provision Fargate compute, S3 buckets for DAG storage, and CloudWatch log groups. DAGs execute arbitrary Python code with the MWAA execution role's permissions, and the web server can be configured for public internet access.

**Remediation:** Remove airflow:CreateEnvironment from the principal's policies.

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
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

An IAM identity has OAuth MCP Server permissions via a wildcard action (signin:* or *). This is likely an unintentional grant — the signin:AuthorizeOAuth2Access and signin:CreateOAuth2Token actions were introduced on July 9, 2026. Any policy with signin:* or * in the Action field now implicitly grants OAuth agent authorization.
The wildcard grant is dangerous because the identity owner may not know they have OAuth permissions. Unlike explicit grants, wildcards are not reviewed when new actions are added to a namespace.

**Remediation:** Replace the wildcard action with explicit action grants. If OAuth access is intended, grant signin:AuthorizeOAuth2Access and signin:CreateOAuth2Token explicitly with appropriate condition keys. If not intended, narrow the Action field to exclude the signin: namespace.

---

### CTL.IAM.OIDC.GITHUB.SUBJECT.001

**GitHub Actions OIDC Trust Does Not Restrict Subject Claim**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

IAM role trusts the GitHub Actions OIDC provider (token.actions.githubusercontent.com) but does not restrict the subject claim to specific repositories and branches. Without a subject restriction, ANY GitHub repository — including attacker-controlled repos — can assume the role. The trust policy should restrict the sub claim to specific org/repo:ref patterns like "repo:myorg/myrepo:ref:refs/heads/main".

**Remediation:** Add a StringLike condition on token.actions.githubusercontent.com:sub in the trust policy to restrict which repositories and branches can assume the role. Example condition value: "repo:myorg/myrepo:ref:refs/heads/main".

---

### CTL.IAM.OIDC.GITLAB.SUBJECT.001

**GitLab OIDC Roles Must Restrict Subject Claim**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

IAM roles trusting GitLab OIDC must restrict the sub claim to specific projects and branches. Without a subject restriction, ANY GitLab project — including attacker-controlled — can assume the role. The AWS Console creates this misconfiguration by default. The trust policy says "I trust GitLab" when it should say "I trust myorg/myproject on the main branch." Technique: hackingthe.cloud exploiting misconfigured GitLab OIDC AWS IAM roles.

**Remediation:** Add a StringLike condition on gitlab.com:sub in the trust policy restricting to specific project paths and ref types. Example: "project_path:myorg/myproject:ref_type:branch:ref:main"

---

### CTL.IAM.OIDC.PROVIDER.AUDIENCE.001

**OIDC Provider Audience Must Be Scoped**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-8; owasp_nhi: NHI3; soc2: CC6.1;

IAM OIDC provider has an overly broad or unrecognized audience (client ID list). A scoped audience restricts which applications from the identity provider can assume roles in the account. An unscoped or wildcard audience allows any application authenticated by the IdP to request tokens, expanding the trust surface beyond what was intended.

**Remediation:** Restrict the client ID list to only the specific application IDs that should be able to assume roles via this OIDC provider. Remove any wildcard or overly broad client IDs.

---

### CTL.IAM.OIDC.PROVIDER.AUDIT.001

**OIDC Provider Must Be From Recognized Identity Source**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-8; owasp_nhi: NHI3; soc2: CC6.1;

IAM OIDC provider references an identity provider URL that is not in the recognized provider list. Farris describes shadow cloud usage where engineers unknowingly create cross-cloud federation. An OIDC provider pointing to an unknown URL is either forgotten federation (pollution) or an attacker-controlled IdP (compromise). Both warrant investigation. Default recognized providers: accounts.google.com, login.microsoftonline.com, token.actions.githubusercontent.com. Organization-specific IdPs must be added to the collector allowlist.

**Remediation:** Verify the OIDC provider URL is intentional and from a trusted identity source. If the provider is legitimate, add it to the recognized provider allowlist. If not, delete the OIDC provider and audit all roles that reference it.

---

### CTL.IAM.OIDC.ROGUE.001

**No Unapproved OIDC Identity Providers**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Every OIDC identity provider in the account must have a provider URL on the approved list. Rogue OIDC providers are a persistence mechanism: an attacker creates a provider pointing to infrastructure they control, then creates a role trusting that provider. The provider appears legitimate because the trust is via standard OIDC federation. Extends CTL.IAM.OIDC.PROVIDER.AUDIT.001 with explicit focus on persistence detection. Technique: hackingthe.cloud IAM rogue OIDC identity provider.

**Remediation:** Review the OIDC provider. If it was not intentionally created, delete it and revoke any roles that trust it. If legitimate, add the provider URL to the approved list.

---

### CTL.IAM.OIDC.TFC.SUBJECT.001

**Terraform Cloud OIDC Roles Must Restrict Subject Claim**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

IAM roles trusting Terraform Cloud OIDC must restrict the sub claim to specific organizations and workspaces. Without a subject restriction, any Terraform Cloud workspace can assume the role. Same pattern as GitLab OIDC misconfiguration. Technique: hackingthe.cloud exploiting misconfigured Terraform Cloud OIDC.

**Remediation:** Add a StringLike condition on app.terraform.io:sub in the trust policy restricting to specific org:workspace patterns.

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

### CTL.IAM.POLICY.ABAC.UNSUPPORTED.001

**ABAC Condition Used on Service That Does Not Support It**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3, AC-6; soc2: CC6.1;

IAM policy uses tag-based condition keys (aws:ResourceTag, aws:RequestTag, aws:TagKeys) on actions for an AWS service that does not support ABAC. When the service ignores tag conditions, the policy silently grants broader access than intended — the condition is syntactically valid but semantically inert. AWS documents which services support ABAC; policies referencing tag conditions on non-supporting services must use resource ARN restrictions instead.

**Remediation:** Replace ABAC conditions with resource ARN restrictions for services that do not support tag-based authorization. Consult the AWS ABAC support matrix for each service in the policy.

---

### CTL.IAM.POLICY.ADMIN.001

**No Full Admin Policies Attached**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

No IAM policy with Effect Allow on Action "*" and Resource "*" should be attached to any IAM entity. Full admin policies violate least privilege and grant unrestricted access to all services.

**Remediation:** Replace wildcard admin policies with scoped policies granting only the specific permissions required. Use AWS Access Analyzer to generate least-privilege policies from CloudTrail activity.

---

### CTL.IAM.POLICY.ADMIN.002

**No Full Admin Policies on IAM Groups**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.16; fedramp_moderate: AC-6; ffiec: CAT-D3; gdpr: Art.32; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; nist_csf_2.0: PR.AA; owasp_nhi: NHI5; owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

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
- **Compliance:** nist_800_53_r5: AC-3; owasp_subtractive: S02; soc2: CC6.1; subtractive_tier: deletion;

A resource-based policy grants cross-account access without the aws:PrincipalOrgID condition. Without this condition, access can be granted to principals from any AWS account — not just accounts in the organization. aws:PrincipalOrgID restricts access to principals whose accounts are members of the specified organization, preventing access from accounts that have left the org or were never members.

**Remediation:** Add an aws:PrincipalOrgID condition to all cross-account grants in resource-based policies. This restricts access to principals whose accounts are members of the organization.

---

### CTL.IAM.POLICY.CONDITION.REGION.001

**Policy Does Not Restrict AWS Regions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_subtractive: S09; soc2: CC6.1; subtractive_tier: constraint;

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

### CTL.IAM.POLICY.CREDENTIALEXPOSURE.001

**Policy Grants Credential-Exposure Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6, IA-5; owasp_nhi: NHI1; soc2: CC6.1;

IAM policy grants actions classified as credential-exposure in the AWS sensitive action registry: sts:GetFederationToken, sts:GetSessionToken, iam:CreateAccessKey, iam:CreateLoginProfile, ssm:GetParameter (SecureString), secretsmanager:GetSecretValue, and similar. These actions let an attacker mint or extract credentials from within the account, enabling persistence and lateral movement that survives credential rotation. Principals should only have credential-exposure actions when their function explicitly requires them.

**Remediation:** Remove credential-exposure actions from the policy or scope them with resource and condition constraints. Use the sensitive action registry to audit which credential-exposure actions the principal actually invokes.

---

### CTL.IAM.POLICY.DEPRECATED.MANAGED.001

**IAM Roles Must Not Use Deprecated AWS-Managed Policies**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SA-22; soc2: CC8.1;

No IAM role should have a deprecated AWS-managed policy attached. AWS deprecates managed policies when they are superseded by updated versions or when the underlying service is discontinued. Roles using deprecated policies reference abandoned infrastructure that AWS no longer updates with new service actions or security fixes. Examples: AWSCloudTrailFullAccess (deprecated 2021, replaced by CloudTrailFullAccess), AWSLambdaFullAccess (deprecated 2021, overpermissive with no replacement), AnthropicInferenceAccess (deprecated May 2026). The authoritative list is maintained in data/deprecation-calendar.yaml under managed_policies.

**Remediation:** Replace the deprecated managed policy with its documented replacement (see data/deprecation-calendar.yaml). If no replacement exists, create a scoped customer-managed policy granting only the actions the workload requires.

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

### CTL.IAM.POLICY.OBFUSCATED.ADMIN.001

**No IAM Policy Grants Admin via Wildcard Obfuscation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_subtractive: S02; soc2: CC6.1; subtractive_tier: deletion;

IAM policies must not grant effective administrative access via wildcard obfuscation patterns. Instead of "Action": "*" or "iam:*", an attacker uses patterns like "iam:Creat*" which match CreateAccessKey, CreateUser, etc. via IAM wildcard matching rules but evade string-comparison detection. The control must evaluate the EXPANDED action set against the sensitive action registry. Implementation requires wildcard expansion against the IAM action namespace. Technique: hackingthe.cloud obfuscated admin policy.

**Remediation:** Review the policy's Action patterns by expanding wildcards against the IAM action namespace. Replace broad wildcard patterns with explicit action lists. Use the IAM Access Analyzer to identify effective permissions.

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

### CTL.IAM.POLICY.READONLYACCESS.001

**ReadOnlyAccess Managed Policy Grants Excessive Read Scope**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM entity has the AWS-managed ReadOnlyAccess policy attached. ReadOnlyAccess grants Get/List/Describe on every AWS service, exposing secrets (Secrets Manager GetSecretValue), credentials (SSM GetParameter for SecureString), database contents (DynamoDB GetItem, S3 GetObject), and billing data. It is routinely treated as "safe" but functionally grants read access to every data store in the account. Principals needing read access should use scoped policies limited to their operational services.

**Remediation:** Replace ReadOnlyAccess with scoped read-only policies for the specific services the principal needs. Use Access Analyzer to generate least-privilege policies from CloudTrail activity.

---

### CTL.IAM.POLICY.RESOURCE.WILDCARD.001

**Sensitive Actions Must Not Use Resource Wildcard**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI5; owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

IAM policies granting sensitive actions (s3:*, kms:Decrypt, dynamodb:*, secretsmanager:GetSecretValue, rds:*, ec2:*, lambda:InvokeFunction, sts:AssumeRole) must scope the Resource element to specific ARNs. Resource "*" on sensitive actions grants the action on every resource in the account, vastly exceeding least privilege. CTL.IAM.POLICY.PASSROLE.001 and CTL.IAM.POLICY.ASSUMEROLE.001 enforce resource scoping for PassRole and AssumeRole specifically; this control generalizes the pattern to all sensitive actions.

**Remediation:** Scope the Resource element to specific ARNs or ARN patterns. For example, restrict s3:* to specific bucket ARNs, kms:Decrypt to specific key ARNs, and lambda:InvokeFunction to specific function ARNs.

---

### CTL.IAM.POLICY.SENSITIVE.GRANTS.001

**IAM Principal Must Not Have Unreviewed Sensitive Action Grants**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.3;

IAM principal has policies granting actions from the sensitive action registry without compensating controls. Sensitive actions include iam:CreateUser, iam:AttachRolePolicy, sts:AssumeRole with broad scope, kms:Decrypt on shared keys, and similar privilege-escalation vectors. The sensitive action registry cross-references granted actions against known escalation patterns.

**Remediation:** Review attached policies and remove sensitive action grants. Use permission boundaries to restrict access to sensitive actions. Prefer task-specific roles over broadly-scoped principals.

---

### CTL.IAM.POLICY.SERVICEWILDCARD.001

**No Service-Wildcard Grants on Denied Services**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.3; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

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

### CTL.IAM.POLICY.SHADOW.DENY.001

**Policy Deny Statement Shadowed by Broader Allow**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.1;

A Deny statement is bypassed by an Allow statement with non-overlapping conditions. The Deny appears protective but does not fully block the action. Detected by the Z3 shadow query which asserts Allow(request) ∧ ¬Deny(request) and produces a concrete witness when satisfiable.

**Remediation:** Extend the Deny statement's condition keys to cover the same scope as the Allow, or narrow the Allow to respect the Deny's intended restriction.

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

### CTL.IAM.POLICY.THIRDPARTY.DATAACCESS.001

**Third-Party Role Has Data-Plane Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6, AC-17; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role assumed by a third-party principal (cross-account trust outside the organization) has policies granting data-plane access to S3 (GetObject, PutObject), DynamoDB (GetItem, PutItem, Query), Secrets Manager (GetSecretValue), or similar data-reading actions. Third-party integrations should use scoped read-only access to metadata (ListBuckets, DescribeTable) unless data access is an explicit, documented requirement. Unintentional data-plane grants to vendor roles are a common root cause of data breaches via supply-chain compromise.

**Remediation:** Restrict the role's policies to metadata-only actions unless data access is an explicit integration requirement. Document the business justification and apply conditions (source IP, VPC endpoint, external ID) to limit scope.

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

### CTL.IAM.POLICY.VERSIONS.ACCUMULATION.001

**Managed Policy Has Multiple Versions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

A customer-managed IAM policy has more than one version. Dormant versions may contain broader permissions that can be activated via iam:SetDefaultPolicyVersion — a single-API-call escalation path. Policies should be cleaned to a single version after changes are verified.

**Remediation:** Delete non-default policy versions after verifying the current default version is correct. Use aws iam delete-policy-version to remove dormant versions. Alternatively, enable an SCP that denies iam:SetDefaultPolicyVersion in workload accounts.

---

### CTL.IAM.POLICY.VERSIONS.ATCAPACITY.001

**Managed Policy at Version Capacity**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

A customer-managed IAM policy has 5 versions (AWS maximum). iam:CreatePolicyVersion requires deleting a version first, but iam:SetDefaultPolicyVersion can still activate any existing dormant version without deletion. At capacity, the attack surface is frozen — the set of potentially-exploitable versions is fixed.

**Remediation:** Review and delete unneeded policy versions to free capacity. If all 5 versions are intentional, verify that none contains broader permissions than the current default. Use aws iam delete-policy-version to remove unnecessary versions.

---

### CTL.IAM.POLLUTION.STALEADMIN.001

**Stale IAM Credential Has Administrative Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; owasp_nhi: NHI1; owasp_subtractive: S07; soc2: CC6.2; subtractive_tier: deletion;

IAM user has credentials unused for 90+ days AND has administrative permissions. A stale credential with admin access is the highest-risk pollution pattern: the key has no active operational purpose (unused), maximum blast radius (admin), and is likely unmonitored (no one watches for its use because no one remembers it exists). This is the compound of CTL.IAM.CRED.UNUSED.001 (stale credential) and CTL.IAM.POLICY.ADMIN.001 (admin access) — neither alone captures the distinct risk class of an abandoned admin key. Farris: "access keys that are who knows where, waiting to be exposed."

**Remediation:** Immediately disable or delete the stale credentials. Remove administrative permissions. If the user is no longer needed, delete the IAM user entirely.

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

### CTL.IAM.RECON.SIMULATE.001

**Principal Has iam:SimulatePrincipalPolicy Capability**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1087.004; nist_800_53_r5: AC-6;

A principal with iam:SimulatePrincipalPolicy can programmatically test what any other principal in the account can do — one API call per target reveals the complete effective permission set without performing the action. This is the most efficient victim selection tool: the attacker iterates over ListUsers output and calls SimulatePrincipalPolicy for each user to find the one with the highest privileges. Combined with any escalation vector, this enables optimal target selection.

**Remediation:** Remove iam:SimulatePrincipalPolicy from non-admin principals. Deny via SCP in workload accounts where policy simulation is not required for automation.

---

### CTL.IAM.RECON.VICTIM.SELECTION.001

**Principal Has Victim Selection Capability for Privilege Escalation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1087.004; nist_800_53_r5: AC-6;

A principal that can enumerate all IAM principals (iam:ListUsers/ListRoles), read their attached policies (iam:GetUserPolicy/GetPolicyVersion/ListAttachedUserPolicies), and optionally simulate their permissions (iam:SimulatePrincipalPolicy) has the reconnaissance capability to surgically select the highest-privilege target before executing an escalation vector. Combined with any escalation control, this transforms blind exploitation into targeted privilege escalation — the attacker identifies the programmatic-only admin account with no MFA and acts on it specifically.

**Remediation:** Scope iam:ListUsers, iam:ListRoles, and policy-reading actions (iam:GetUserPolicy, iam:GetPolicyVersion, iam:ListAttachedUserPolicies) to specific resource ARNs or remove them from non-admin principals. Deny iam:SimulatePrincipalPolicy via SCP for workload accounts.

---

### CTL.IAM.RESOURCE.CROSSACCOUNT.001

**Role Must Not Grant Access to External Account Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; owasp_subtractive: S05; soc2: CC6.3; subtractive_tier: deletion;

IAM role's policy grants access to resources in a different AWS account via a cross-account Resource ARN. The role can read from or write to S3 buckets, DynamoDB tables, or other resources in an external account. This creates a data boundary violation: data can flow between accounts without the receiving account's resource-based policy being the sole gating control. Combined with a compromised principal, cross-account resource grants become exfiltration channels.

**Remediation:** Remove cross-account resource ARNs from identity-based policies. If cross-account access is required, use a resource-based policy on the target resource or an explicit cross-account role assumption via sts:AssumeRole with ExternalId conditions.

---

### CTL.IAM.RESOURCE.POLICY.CROSS.ENV.001

**Resource Policy Grants Cross-Environment Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-4; iso_27001_2022: A.8.22; nist_800_53_r5: AC-4; owasp_nhi: NHI6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Production resource policy (S3, KMS, SQS, SNS, Lambda) grants access to a principal from a different environment tier. An enclave or sandbox account principal can access production data without assuming a production role — bypassing AssumeRole controls, MFA requirements, and session logging. This is the resource-policy leg of cross- environment pivot that CTL.IAM.CROSS.ENV.001 covers on the IAM side. The OpenAI ExploitGym incident (July 2026) demonstrated this pattern: stolen enclave credentials accessed production resources through resource policy grants that did not require role assumption.

**Remediation:** Remove cross-environment principal grants from resource policies. Cross-environment access should route through AssumeRole with ExternalId and MFA conditions so that session logging, duration limits, and conditional access apply. If direct resource-policy access is required, scope it to specific actions and add aws:PrincipalOrgID and aws:PrincipalTag/Environment conditions.

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

### CTL.IAM.ROLE.CREDENTIALEXPOSURE.001

**Non-Security Roles Must Not Have CredentialExposure Actions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.3;

IAM role outside the security admin set has CredentialExposure-classified actions (sts:GetFederationToken, iam:CreateAccessKey, iam:CreateLoginProfile, sts:AssumeRole on *, iam:UpdateAccessKey, etc.). These actions create or modify credentials — they should be restricted to security admin roles and automated credential rotation tooling. The sensitive action registry classifies these as CredentialExposure; any non-security role with them is an escalation vector.

**Remediation:** Remove CredentialExposure actions from the role's permissions. If the role needs iam:CreateAccessKey for service account rotation, scope it to the specific user ARN and add a condition key.

---

### CTL.IAM.ROLE.CROSSACCOUNT.READONLYACCESS.001

**Cross-Account Roles Must Not Use ReadOnlyAccess Managed Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); owasp_subtractive: S05; soc2: CC6.3; subtractive_tier: deletion;

IAM role that allows external account assume has the AWS-managed ReadOnlyAccess policy attached. ReadOnlyAccess includes DataAccess actions — s3:GetObject, dynamodb:GetItem, secretsmanager:GetSecretValue, and others that read sensitive data. On a cross-account role, ReadOnlyAccess means the external account can read all data in the account. Use a scoped policy that grants only the specific read actions the external party needs.

**Remediation:** Replace ReadOnlyAccess with a scoped policy granting only the specific read actions the external party needs. Use resource-level permissions to limit which resources they can access.

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

### CTL.IAM.ROLE.DANGEROUS.MANAGED.001

**IAM Roles Must Not Use Managed Policies Granting Dangerous Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.3;

No IAM role should have a managed policy that grants actions classified as dangerous in the sensitive action registry. Unlike FULLACCESS.MANAGED.001 (which matches policy names ending in *FullAccess), this control matches policy ACTIONS against the registry — catching dangerous policies with innocuous names like AWSManagedBudgetsSpendLimitManagementAccess (which grants organizations:AttachPolicy/DetachPolicy for SCP mutation). The name check is a fast heuristic; this action check is the ground truth.

**Remediation:** Replace the managed policy with a scoped policy that does not grant dangerous actions. If the workload genuinely requires organizations:AttachPolicy or similar, document the exception and scope it to the minimum required resources.

---

### CTL.IAM.ROLE.ENTROPY.INCOMPLETE.001

**Complete Data Required for Entitlement Entropy Assessment**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity

Access Advisor data, permission policy inventory, or tag inventory is absent from the snapshot. Without this data, permission drift, category mixing, and intent mismatch controls cannot evaluate. Re-run the extractor with iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails, iam:ListAttachedRolePolicies, iam:ListRolePolicies, and iam:ListRoleTags permissions.

**Remediation:** Re-run the extractor with permissions to collect Access Advisor data (iam:GenerateServiceLastAccessedDetails, iam:GetServiceLastAccessedDetails), policy inventory (iam:ListAttachedRolePolicies, iam:ListRolePolicies), and tags (iam:ListRoleTags).

---

### CTL.IAM.ROLE.FULLACCESS.MANAGED.001

**IAM Roles Must Not Use AWS-Managed FullAccess Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.3;

No IAM role should have an AWS-managed *FullAccess policy attached (AmazonS3FullAccess, AmazonEC2FullAccess, AdministratorAccess, etc.). These managed policies grant blanket permissions across an entire service. When attached to service roles, they create lateral movement paths — a compromised SageMaker notebook with AmazonS3FullAccess reaches every bucket in the account. Default service roles created by SageMaker, Glue, EMR, and CloudFormation ship with AmazonS3FullAccess attached. Source: open-cvdb/aws-default-roles-service-takeover (Aqua Security "Shadow Roles" research, April 2025). SageMaker, Glue, EMR, and CloudFormation default roles all ship with AmazonS3FullAccess. Customer mitigation: audit existing IAM roles and replace overly permissive policies with least-privilege scoped policies.

**Remediation:** Replace the FullAccess managed policy with a scoped policy granting only the actions and resources the workload actually needs. For default service roles (SageMaker, Glue, EMR), create custom roles with least-privilege policies instead of using the service-created defaults.

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

### CTL.IAM.ROLE.THIRDPARTY.DATAACCESS.001

**Third-Party Roles Must Not Have DataAccess Actions Without Explicit Deny**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(1); soc2: CC6.3;

IAM role assumed by external parties has effective permissions that include DataAccess-classified actions (s3:GetObject, dynamodb:GetItem, rds:DownloadDBLogFile, etc.) without an explicit deny. Third-party access roles should not have blanket data-read permissions — they should be restricted to the specific API actions and resources the third party needs. The sensitive action registry classifies actions by risk; DataAccess is the category for actions that read customer data.

**Remediation:** Add explicit Deny statements for DataAccess-classified actions to the role's identity policy, or replace broad read permissions with specific actions scoped to the resources the third party needs.

---

### CTL.IAM.ROLE.UNUSED.001

**IAM Role Not Assumed in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.21; nist_800_53_r5: AC-2(3); owasp_nhi: NHI1; owasp_subtractive: S07; soc2: CC6.2; subtractive_tier: deletion;

IAM role has not been assumed in 90 or more days. The role exists with attached permissions but serves no active purpose. Unused roles are a latent attack surface — if compromised, their permissions are available but not being monitored for anomalous usage because nobody uses them normally.

**Remediation:** Review and delete unused IAM roles. If the role is needed for disaster recovery, document the justification and reduce its permissions to minimum required.

---

### CTL.IAM.ROLECHAIN.DEPTH.001

**Role Chain Depth Exceeds Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6, AU-3; owasp_subtractive: S05; soc2: CC6.1; subtractive_tier: deletion;

IAM role participates in an assume-role chain deeper than the recommended threshold. AWS allows role chaining up to the session duration limit, but deep chains (3+ hops) obscure the original principal's identity in CloudTrail, complicate access reviews, and create fragile dependency chains where revoking one role breaks downstream automation. Each hop reduces the maximum session duration (capped at 1 hour for chained sessions), signaling that the architecture relies on transitive trust rather than direct grants.

**Remediation:** Flatten the role chain by granting direct trust relationships where possible. If chaining is required for cross-account patterns, limit depth to 2 hops and ensure each hop is logged and auditable.

---

### CTL.IAM.ROLEMANAGER.ENABLED.PROD.001

**IAM Role Manager Must Not Be Enabled in Production Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(1); nist_800_53_r5: AC-6(1); owasp_nhi: NHI5; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

IAM Role Manager auto-provisions execution roles with PowerUserAccess for new Lambda functions when it cannot determine the required permissions from the code. Role Manager is designed for development — AWS documentation explicitly says "disable role manager and refine roles before going live." Leaving Role Manager enabled in a production account means every new Lambda function starts with near-admin permissions automatically. This inverts least privilege: instead of starting with nothing and granting what's needed, every function starts with everything and (maybe) gets scoped later.

**Remediation:** Disable Role Manager in production and staging accounts. Refine any existing Role Manager-provisioned roles using IAM Access Analyzer unused access findings to generate scoped policies. Role Manager should only be enabled in development or sandbox accounts.

---

### CTL.IAM.ROLEMANAGER.UNREFINED.001

**Role Manager-Provisioned Role Still Has PowerUserAccess**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6(1); nist_800_53_r5: AC-6(1), AC-2; owasp_nhi: NHI5; owasp_subtractive: S07; pci_dss_v4.0: 7.2.2; soc2: CC6.3; subtractive_tier: refinement;

IAM role created by Role Manager still has the original PowerUserAccess policy attached after 30+ days. Role Manager auto-provisions execution roles with broad permissions for rapid development — the intended workflow is "start broad, use Access Analyzer to identify actual usage, then scope down." A role that still has PowerUserAccess after a month was never refined: the temporary broad access became permanent. This is credential scope creep — the role was intended to be narrow but the scoping step never happened. Distinct from CTL.IAM.ROLE.FULLACCESS.MANAGED.001 (which detects any *FullAccess policy) because this specifically targets the Role Manager lifecycle failure: auto-provisioned roles that missed the mandatory refinement step.

**Remediation:** Use IAM Access Analyzer unused access findings to generate a scoped policy based on the role's actual usage. Replace PowerUserAccess with the generated policy. If the role is unused, delete it.

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

### CTL.IAM.ROLESANYWHERE.PROFILE.SCOPE.001

**Roles Anywhere Profiles Must Map to Least-Privilege Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM Roles Anywhere profiles must map to roles with scoped permissions, not roles with AdministratorAccess or permissions spanning more than 5 service namespaces. Overprivileged Roles Anywhere profiles amplify the blast radius of certificate compromise — a stolen certificate grants the full privileges of the mapped role from outside AWS. Technique: hackingthe.cloud IAM Roles Anywhere persistence.

**Remediation:** Scope the mapped role to the minimum permissions required. Use session policies in the profile to further restrict effective permissions.

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

### CTL.IAM.ROLESANYWHERE.TRUSTANCHOR.001

**Roles Anywhere Trust Anchors Must Use Approved CAs**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5(2); soc2: CC6.1;

IAM Roles Anywhere trust anchors must reference only approved certificate authorities (ACM-PCA managed or on the approved CA list). An attacker creates a trust anchor with their own CA, then uses certificates from that CA to assume roles from outside AWS. This bypasses all IAM access key controls because authentication uses X.509 certificates, not access keys. Extends CTL.IAM.ROLESANYWHERE.SELFSIGNED.001 (self-signed CA detection) with explicit approved-CA-list enforcement. Technique: hackingthe.cloud IAM Roles Anywhere persistence.

**Remediation:** Replace the trust anchor with one backed by ACM Private CA or add the CA to the approved list after verification. Review all profiles and roles associated with this trust anchor.

---

### CTL.IAM.ROOT.ACCESSKEY.001

**Root Account Must Not Have Access Keys**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v1.4.0: 1.4; cis_aws_v3.0: 1.4; fedramp_moderate: IA-2; hipaa: 164.312(a)(1); nist_800_53_r5: IA-2; owasp_nhi: NHI2; owasp_subtractive: S07; pci_dss_v3.2.1: 2.1; pci_dss_v4.0: 8.3.4; soc2: CC6.1; subtractive_tier: deletion;

The AWS root account must not have active access keys. Root access keys provide unrestricted programmatic access. Use IAM users or roles for programmatic access instead.

**Remediation:** Delete the root access keys. Create IAM users or roles with least-privilege policies for programmatic access.

---

### CTL.IAM.ROOT.CENTRALIZED.001

**Centralized Root Management Not Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.1; fedramp_moderate: AC-6(5); nist_800_53_r5: AC-6(5); soc2: CC6.1;

AWS Organizations centralized root management (AssumeRoot) is not enabled. Without centralized root management, each member account retains its own root credentials that must be individually secured with MFA, password rotation, and access key removal. Centralized root management eliminates member-account root credentials entirely — the management account uses sts:AssumeRoot to perform root-privileged operations in member accounts on demand, creating an auditable, time-limited session instead of a persistent credential. This is the strongest root security posture available in AWS Organizations.

**Remediation:** Enable centralized root management in the Organizations console or via the EnableRoot API. Then remove root credentials (access keys, passwords, MFA) from member accounts — they are no longer needed.

---

### CTL.IAM.ROOT.EMAIL.DOMAIN.001

**Root Email Must Use Organization-Controlled Domain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.1; nist_800_53_r5: AC-6(5); soc2: CC6.1;

Account root email uses a consumer or personal email domain. Farris: "the account is owned by the root email address, regardless of the organization or who pays for it." A root email on a consumer domain (gmail.com, outlook.com, etc.) means the organization does not control the email inbox, cannot enforce MFA on the email provider, and cannot recover the account if the email holder leaves. The collector extracts the domain portion of the root email and checks it against a consumer domain list. Only the domain is evaluated — the full email address is not stored in the observation to avoid PII exposure.

**Remediation:** Change the root email to an organization-controlled domain (e.g., aws-root+accountid@company.com). Use a distribution list or shared mailbox so the email is not tied to a single person. Enable MFA on the email provider.

---

### CTL.IAM.ROOT.EMAIL.LOCALZONE.001

**Root Email Domain DNS Hosted in Same Account**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CP-2; soc2: CC9.1;

The account's root email domain has its DNS hosted in a Route 53 public hosted zone within the same AWS account. If this account is closed, domain suspension begins on day 5 — the hosted zone stops resolving, which prevents delivery of AWS notification emails about the closure itself. This creates a circular failure: the recovery mechanism (email notification) is destroyed by the event it should warn about. The account owner cannot receive the 90-day closure warning and may miss the recovery window entirely.

**Remediation:** Move the root email domain's hosted zone to a separate account (the management account or a dedicated DNS account), or change the root email to a domain hosted externally. The root email inbox must remain reachable even if this account is closed.

---

### CTL.IAM.ROOT.EMAIL.SHARED.001

**Root Email Must Not Be Shared Across Accounts**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6(5); soc2: CC6.1;

Multiple accounts share the same root email address. A shared root email means a single email compromise affects multiple accounts. Each account should have a unique root email, typically using plus-addressing (admin+accountid@company.com) or per-account distribution lists. The collector flags accounts whose root email domain+local part match another account in the organization.

**Remediation:** Change the root email to a unique address per account. Use plus-addressing (aws-root+111122223333@company.com) or per-account distribution lists. Ensure each account's root email resolves to a distinct inbox or alias.

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

### CTL.IAM.S3.ACCESSPOINT.BYPASS.001

**IAM Policy Grants S3 Access on Bucket ARN Bypassing Access Points**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policy grants S3 write actions directly on a bucket ARN when S3 access points are configured for that bucket. Access points enforce network-origin and IAM restrictions at a narrower scope than the bucket policy. A role that writes via the bucket ARN bypasses access-point restrictions entirely — the access-point VPC restriction, principal constraints, and action scope do not apply to direct bucket operations. The has_s3_bucket_arn_bypassing_ap property is derived by the collector by cross-referencing the IAM policy's S3 resource ARNs with the bucket's access-point configuration.

**Remediation:** Replace the bucket ARN in the IAM policy Resource element with the access point ARN. Use arn:aws:s3:region:account:accesspoint/name to enforce access-point restrictions.

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

### CTL.IAM.SAGEMAKER.ADMIN.001

**IAM Policy Grants SageMaker Notebook and Domain Creation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

An IAM principal has a policy granting sagemaker:CreateNotebookInstance or sagemaker:CreateDomain. SageMaker notebook instances and Studio domains provision EC2 compute with EBS storage, optional internet access, and IAM execution roles that typically have broad S3 and KMS permissions for training data access.

**Remediation:** Remove sagemaker:CreateNotebookInstance and sagemaker:CreateDomain from the principal's policies.

---

### CTL.IAM.SAML.ENTITYID.001

**SAML Provider Must Have Tracked Entity ID**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-8; soc2: CC6.1;

IAM SAML provider has no tracked entity ID (Issuer). The entity ID identifies which external identity provider is federated into the AWS account. Without tracking the entity ID, changes to the SAML metadata (provider replacement, IdP migration, entity ID rotation) go undetected. An attacker who replaces the SAML metadata with their own IdP gains federated access to the account.

**Remediation:** Record the SAML entity ID and monitor for changes. Set up CloudTrail alerts for iam:UpdateSAMLProvider events.

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

### CTL.IAM.SCP.ACCESSKEY.SOURCEIP.001

**SCP Does Not Restrict Access Key Usage to Known Source IPs**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.3;

SCP does not deny IAM User actions from unknown source IPs. Compensating control for organizations that cannot yet eliminate IAM Users with long-term access keys. Farris demonstrated this as his safety net when deliberately leaking eight access keys: an SCP-based source IP restriction limits key usability to known networks, so an attacker with a stolen key from a different IP gets denied. This is defense-in-depth, not primary prevention — the primary prevention is eliminating IAM Users with access keys (CTL.IAM.CRED.UNUSED.001, CTL.IAM.SCP.CREATEUSER.001). Use this control for organizations still migrating off access keys. Note: aws:SourceIp conditions do not apply to calls made through VPC endpoints or by AWS services on behalf of the principal.

**Remediation:** Add an SCP that denies all actions for IAM User principals when aws:SourceIp is not in the organization's known CIDR list. Scope the Deny to principal types that use access keys (IAM Users), not roles (which are used by services and VPC endpoints where SourceIp doesn't apply).

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

### CTL.IAM.SCP.CLOSEACCOUNT.002

**SCP Does Not Deny CloseAccount for Domain-Tagged Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No SCP denies account:CloseAccount with a condition scoped to accounts tagged HasRegisteredDomains. The unconditional deny (CTL.IAM.SCP.CLOSEACCOUNT.001) prevents all account closures, but organizations that allow controlled account decommissioning need a tag-conditional deny that protects only accounts holding Route 53 domain registrations. Without this, an account closure workflow can close a domain-holding account, triggering domain suspension on day 5 and permanent loss after 30 days.

**Remediation:** Add an SCP that denies organizations:CloseAccount and account:CloseAccount with a Condition requiring aws:ResourceTag/HasRegisteredDomains equals true. Apply it to the organization root or the OU containing domain- holding accounts.

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

### CTL.IAM.SCP.CLOUDTRAIL.EVENTSELECTOR.001

**SCP Does Not Prevent CloudTrail Event Selector Modification**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3, AU-9, AU-12; soc2: CC6.1, CC7.1;

No SCP denies cloudtrail:PutEventSelectors or cloudtrail:PutAdvancedEventSelector in member accounts. A member account admin can narrow CloudTrail event scope — excluding specific event types, data sources, or UserIdentity principals — without organizational prevention. This is an A5 (Separation of Duties) violation: the principal can both perform actions through VPC endpoints and suppress the record of those actions by modifying event selectors. Incident precedent: Ubiquiti (2020), FTX, CodeSpaces, Halcyon Codefinger — all cases where an actor could act and suppress.

**Remediation:** Add an SCP that denies cloudtrail:PutEventSelectors and cloudtrail:PutAdvancedEventSelector for all principals in member accounts, excluding a break-glass security-admin role. This is the scope-narrowing analog of the existing SCP that denies StopLogging and DeleteTrail.

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

### CTL.IAM.SCP.CREATEUSER.001

**SCP Does Not Deny iam:CreateUser**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI4; soc2: CC6.1;

No SCP in the hierarchy denies iam:CreateUser. IAM Users have permanent long-lived credentials (access keys) that persist until explicitly rotated or deleted. In a mature organization where all human and service access uses IAM Roles with session credentials, CreateUser is a privilege escalation vector — an attacker creates a new IAM User, generates access keys, and establishes persistent access that survives role session revocation. Denying CreateUser by SCP forces all new service access through IAM Roles, which use short-lived session credentials with automatic expiration. This is an aspirational control for organizations that have fully adopted role-based access — organizations that still legitimately use IAM Users should treat this as a migration target, not a current requirement.

**Remediation:** Add an SCP that denies iam:CreateUser for all principals. Exempt specific automation accounts if legacy IAM User creation is still required during migration. Plan to remove the exemption once all services use IAM Roles.

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

### CTL.IAM.SCP.EC2.MODIFYEBSDEFAULTKEY.001

**SCP Does Not Deny ec2:ModifyEbsDefaultKmsKeyId**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

No SCP in the hierarchy denies ec2:ModifyEbsDefaultKmsKeyId. This is the weaponization step in the BYOKM ransomware kill chain — the attacker changes the default EBS encryption key to their BYOKM key so all new volumes and snapshots in that region are encrypted under attacker-controlled material. Changing the default EBS encryption key is rarely needed after initial account setup. Denying it by SCP prevents an attacker from redirecting encryption to an attacker-controlled key without affecting normal EBS operations (which use whatever key is already set as default).

**Remediation:** Add an SCP that denies ec2:ModifyEbsDefaultKmsKeyId for all principals. Exempt the infrastructure automation role if default key changes are part of account provisioning.

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
- **Compliance:** nist_800_53_r5: SC-7; owasp_nhi: NHI9; owasp_subtractive: S01; soc2: CC6.1; subtractive_tier: deletion;

SCP does not deny EC2 instance launches without IMDSv2 required. Without this SCP, any identity in the organization can launch instances with IMDSv1 enabled. IMDSv1 is the primary credential-theft vector via SSRF — an attacker who compromises a web application on an EC2 instance can query the metadata service at 169.254.169.254 to steal IAM role credentials. The SCP denies ec2:RunInstances when ec2:MetadataHttpTokens is not "required", preventing IMDSv1 instances at the organizational boundary.

**Remediation:** Add an SCP that denies ec2:RunInstances with condition ec2:MetadataHttpTokens != "required". This prevents any identity from launching instances without IMDSv2 enforced. Optionally also deny ec2:ModifyInstanceMetadataOptions to prevent downgrade of existing instances, and deny all actions when ec2:RoleDelivery < 2.0 for defense in depth.

---

### CTL.IAM.SCP.KMS.CREATEKEY.EXTERNAL.001

**SCP Does Not Deny kms:CreateKey with EXTERNAL Origin**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

No SCP in the hierarchy denies creating KMS keys with origin=EXTERNAL. This is the earliest prevention point in the BYOKM ransomware kill chain — if the attacker cannot create a KMS key with EXTERNAL origin, no subsequent phase (import key material, replicate, re-encrypt, rug pull) is possible. The SCP should use a condition key (kms:KeyOrigin) to deny only EXTERNAL-origin key creation while permitting normal AWS_KMS-origin keys. If the kms:KeyOrigin condition key is not available in the SCP context, the broader approach is to deny kms:CreateKey entirely and grant it only to approved automation roles — but this blocks all key creation, not just BYOKM keys.

**Remediation:** Add an SCP that denies kms:CreateKey with condition StringEquals kms:KeyOrigin EXTERNAL. This blocks BYOKM key creation while allowing normal AWS-generated keys. If the organization legitimately uses BYOKM keys, exempt specific approved accounts via condition.

---

### CTL.IAM.SCP.KMS.DELETEKEYMATERIAL.001

**SCP Does Not Deny kms:DeleteImportedKeyMaterial**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

No SCP in the hierarchy denies kms:DeleteImportedKeyMaterial. This is the "rug pull" action in the BYOKM ransomware kill chain — the attacker deletes the imported key material, rendering all data encrypted under the key permanently irrecoverable. Unlike ScheduleKeyDeletion (which has a 7-30 day waiting period), DeleteImportedKeyMaterial takes effect immediately: the key transitions to PendingImport state and all cryptographic operations fail instantly. Every EBS volume, RDS database, S3 object, and Secrets Manager value encrypted under that key becomes unreadable. There is no undo — the key material was externally generated and never held by AWS. Farris identifies this as the single most important action to block: "kms:DeleteImportedKeyMaterial is what you need to look for and block."

**Remediation:** Add an SCP that denies kms:DeleteImportedKeyMaterial for all principals. This is the single highest-impact ransomware prevention SCP. If the organization uses BYOKM keys legitimately, restrict deletion to a specific approved role via SCP condition.

---

### CTL.IAM.SCP.KMS.IMPORTKEY.001

**SCP Does Not Deny kms:ImportKeyMaterial**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

No SCP in the hierarchy denies kms:ImportKeyMaterial. An attacker who can import key material into a KMS key controls the cryptographic backing of that key. The attack sequence: create a customer-managed KMS key with EXTERNAL origin, import attacker-controlled key material, re-encrypt target data under the new key, delete the original key. The data is now encrypted with material only the attacker possesses. AWS cannot recover the data — there is no AWS-managed backing key to fall back to. This is the foundational enabler for KMS-based ransomware. Most organizations never need ImportKeyMaterial (AWS-managed key material is the correct default). Denying it by SCP eliminates the attack surface entirely.

**Remediation:** Add an SCP that denies kms:ImportKeyMaterial for all principals. If a specific account legitimately needs to import key material (hardware security module integration, regulatory requirement), exclude that account with an SCP condition on aws:PrincipalAccount.

---

### CTL.IAM.SCP.KMS.KEYDELETION.001

**SCP Does Not Deny kms:ScheduleKeyDeletion**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.1;

No SCP in the hierarchy denies kms:ScheduleKeyDeletion. Key deletion permanently destroys the key material — all data encrypted under that key becomes irrecoverable after the waiting period (minimum 7 days, default 30). An attacker who can schedule key deletion can destroy all data encrypted under every customer-managed KMS key in every member account. The waiting period provides a detection window, but only if CloudTrail alarms are configured for ScheduleKeyDeletion events (CTL.KMS.ALARM.KEYDELETION.001). Without both the SCP deny and the alarm, key deletion is a low-noise, high-impact destruction path. Denying ScheduleKeyDeletion by SCP and requiring an approval workflow through the management account ensures key deletion is a deliberate, audited process.

**Remediation:** Add an SCP that denies kms:ScheduleKeyDeletion for all principals. Require key deletion requests to go through a management account workflow with approval from a security team member.

---

### CTL.IAM.SCP.KMS.REPLICATEKEY.001

**SCP Does Not Deny kms:ReplicateKey**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: SC-12; soc2: CC6.6;

No SCP in the hierarchy denies kms:ReplicateKey. Key replication copies a multi-region primary key to additional regions. In the BYOKM ransomware kill chain, the attacker replicates the externally-keyed KMS key to every region, expanding the blast radius from one region to the entire account. Once replicated, the attacker can set EBS default encryption in every region to the BYOKM key replica. Denying ReplicateKey by SCP limits the attack to the single region where the key was created. Some organizations legitimately replicate KMS keys for multi-region encryption — this control is a blast-radius limiter, not a primary prevention.

**Remediation:** Add an SCP that denies kms:ReplicateKey for all principals. Exempt specific roles if multi-region key replication is a documented requirement.

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
- **Compliance:** nist_800_53_r5: AC-6; owasp_subtractive: S09; soc2: CC6.1; subtractive_tier: constraint;

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
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI6; owasp_subtractive: S07; soc2: CC6.1; subtractive_tier: deletion;

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

### CTL.IAM.SCP.TAGAUTH.DOMAINS.001

**SCP Does Not Protect HasRegisteredDomains Tag from Removal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

No SCP denies organizations:UntagResource for the HasRegisteredDomains tag key. Without this protection, any principal with organizations:UntagResource permission can remove the governance tag from a domain-holding account, bypassing the tag-conditional CloseAccount deny (CTL.IAM.SCP.CLOSEACCOUNT.002). The tag is the only signal that prevents account closure for domain-holding accounts — removing it silently disarms the protection.

**Remediation:** Add an SCP that denies organizations:UntagResource when aws:TagKeys contains HasRegisteredDomains. Exempt only the designated tagger role via aws:PrincipalArn condition.

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

### CTL.IAM.SSO.ACCOUNT.ACCESS.DISABLED.001

**Identity Center Account Access Management Must Be Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

IAM Identity Center has AWS account access management disabled — permission sets cannot be assigned and the Identity Center service-linked role is not provisioned in member accounts. AWS account access is not governed through Identity Center. If application-only SSO is intentional, apply an exemption. If unintentional, enable account access management through instance settings or the UpdateInstance API.

**Remediation:** If account access is needed: enable it via Identity Center instance settings or the UpdateInstance API. If application-only is intentional: apply an exemption for this control on the instance.

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

### CTL.IAM.SSO.ENCRYPT.CMK.001

**IAM Identity Center Must Use a Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

IAM Identity Center instance is encrypted with an AWS-managed key instead of a customer-managed KMS key — the organization cannot control key rotation schedule, key policy, or key deletion. Identity Center stores workforce identity data including group memberships and permission set assignments that may be subject to compliance requirements mandating customer-controlled encryption.

**Remediation:** Configure a customer-managed KMS key for the Identity Center instance. For multi-Region instances, use a multi-Region KMS key so the key replicates alongside the instance.

---

### CTL.IAM.SSO.ENCRYPT.MULTIREGIONKEY.001

**Multi-Region Identity Center Must Use a Multi-Region KMS Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

IAM Identity Center instance is configured for multi-Region replication but the encryption KMS key is single-region — the instance replicates to the secondary Region but decryption fails because the key does not exist there. Authentication in the failover Region fails silently. This is a ghost failover: multi-Region is configured but the encryption dependency prevents it from functioning.

**Remediation:** Replace the single-region KMS key with a multi-Region KMS key. Create a multi-Region key with aws kms create-key --multi-region, then update the Identity Center instance to use the new key. The key must replicate to every Region the instance is replicated to.

---

### CTL.IAM.SSO.GOVERNANCE.FALLBACK.001

**Identity Center Disabled With Local IAM Console Users Present**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-2; soc2: CC6.1;

IAM Identity Center has account access management disabled AND member accounts have local IAM users with console access — AWS account access has fallen back to per-account IAM management instead of centralized SSO governance. This is less auditable, harder to revoke, and creates credential sprawl across accounts. The combination of both mechanisms with neither providing complete governance is worse than either alone.

**Remediation:** Enable account access management in Identity Center and migrate local IAM console users to SSO-based access. This centralizes authentication, enables MFA enforcement from one place, and provides a single point of revocation.

---

### CTL.IAM.SSO.IDENTITYSOURCE.GHOST.001

**SSO Identity Source References Deleted External IdP**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-2, CM-2; owasp_nhi: NHI1; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

IAM Identity Center is configured with an external identity source (SAML IdP, OIDC provider, or Active Directory Connector) that no longer exists. SSO authentication depends on the external identity source to validate user credentials. When the referenced provider is deleted or disconnected, authentication fails — users cannot sign in to AWS accounts via SSO. The Identity Center console shows an identity source configured. An auditor checking "is SSO configured with an external IdP?" sees the configuration and marks it compliant. The IdP doesn't exist — SSO authentication is broken while appearing configured. Same ghost-reference archetype as CTL.VERIFIEDPERMISSIONS.IDENTITYSOURCE.GHOST.001 and CTL.EVENTBRIDGE.TARGET.GHOST.001.

**Remediation:** Either reconnect the external identity source (recreate the SAML provider, OIDC configuration, or AD Connector) or reconfigure Identity Center to use a different identity source. Verify that SSO authentication succeeds after the fix by testing a sign-in flow end-to-end. Audit the gap window — users who could not authenticate during the outage may have used alternative access paths (IAM users, direct role assumption) that bypass SSO security controls.

---

### CTL.IAM.SSO.INSTANCE.SINGLEREGION.001

**IAM Identity Center Must Not Be Single-Region**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** availability
- **Compliance:** nist_800_53_r5: CP-7; soc2: A1.2;

IAM Identity Center is configured as a single-Region instance — a disruption in the primary Region prevents all workforce authentication across the organization. Every AWS account accessible through Identity Center becomes unreachable until the primary Region recovers. Multi-Region instances replicate to a secondary Region for resilient authentication.

**Remediation:** Enable multi-Region support for the IAM Identity Center instance. For new instances: select "Multi-Region instance" during setup. For existing instances: follow the Region replication guide to add a secondary Region. Standard KMS charges apply for the auto-created multi-Region key.

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
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.8.3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; owasp_subtractive: S05; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC9.2; subtractive_tier: deletion;

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

### CTL.IAM.TRUST.CROSSENV.ELEVATION.001

**Cross-Environment Role Has Administrative Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-4; owasp_nhi: NHI6; owasp_subtractive: S05; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

IAM role has cross-environment production access AND administrative permissions. This is the Midnight Blizzard compound: a role that bridges environments is dangerous; a role that bridges environments with admin permissions is catastrophic. The Microsoft breach (2024) demonstrated this exact shape — a test OAuth application with production-scope grants and elevated permissions enabled a nation-state actor to read executive email across the organization. Neither cross-env access alone (CTL.IAM.CROSS.ENV.001) nor admin access alone (CTL.IAM.POLICY.ADMIN.001) captures the distinct risk of an environment-crossing principal with unrestricted permissions. The compound fires only when both conditions hold on the same role.

**Remediation:** Remove administrative permissions from the cross-environment role. If cross-environment access is required, scope permissions to the minimum set needed. Prefer separate roles per environment with no cross-account trust. Enforce least privilege via permission boundaries.

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

### CTL.IAM.TRUST.EXTERNAL.CLOUD.001

**No Unapproved External Cloud Provider Principals in Trust Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-4; owasp_nhi: NHI6; soc2: CC6.1;

IAM role trust policy references a principal from an external cloud provider (GCP service account, Azure managed identity, or unrecognized external account). Cross-cloud trust is legitimate when intentional (cross-cloud pipeline) and dangerous when accidental (developer's personal GCP project). Farris: "You are multi-cloud whether you like it or not." The collector identifies external cloud principals by matching trust policy principal patterns against known GCP, Azure, and non-org AWS account formats.

**Remediation:** Verify the cross-cloud trust is intentional and approved. If legitimate, document the trust relationship and ensure the external principal follows least privilege. If not, remove the external principal from the trust policy.

---

### CTL.IAM.TRUST.EXTERNALID.001

**Account-Root Cross-Account Trust Must Require External ID**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; owasp_subtractive: S05; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

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
- **Compliance:** nist_800_53_r5: AC-3; owasp_nhi: NHI1; owasp_subtractive: S05; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

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

### CTL.IAM.TRUST.MFA.001

**Cross-Account Trust Policy Must Require MFA**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2(1); hipaa: 164.312(d); nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.4.1; soc2: CC6.1;

An IAM role with a cross-account trust policy does not include an aws:MultiFactorAuthPresent condition. The trust policy may have other session-limiting constraints (SourceIp, MaxSessionDuration, ExternalId) but none require MFA. A compromised access key in the trusted account can assume the role without a second factor — network or time constraints alone do not substitute for authentication strength. This is the AWS equivalent of Azure Conditional Access scoped to named apps but missing ROPC: the enforcement exists on some paths but not the one the attacker uses.

**Remediation:** Add an aws:MultiFactorAuthPresent condition to the trust policy: "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}. For CI/CD roles that cannot use MFA (OIDC federation), scope the trust to a specific OIDC subject and keep MaxSessionDuration short — those roles should not have cross-account trust with IAM principals.

---

### CTL.IAM.TRUST.MFA.AUTHAGE.001

**Trust Policy MFA Lacks Time-Bound Re-Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-2(1); owasp_nhi: NHI4; pci_dss_v4.0: 8.4.1; soc2: CC6.1;

An IAM role trust policy requires MFA (aws:MultiFactorAuthPresent) but does not use aws:MultiFactorAuthAge to enforce MFA freshness. MultiFactorAuthPresent is a boolean checked once at session start — it has no time dimension. Once the session is established, the MFA assurance decays over the session lifetime. A 12-hour session from a single TOTP code is indistinguishable from a non-MFA session after minute one. MultiFactorAuthAge checks seconds since the last MFA authentication, enabling re-authentication requirements within a session. Without it, the MFA condition provides no ongoing assurance.

**Remediation:** Add an aws:MultiFactorAuthAge condition to the trust policy. Example: "Condition": {"NumericLessThan": {"aws:MultiFactorAuthAge": "3600"}}. This requires the MFA authentication to have occurred within the last 3600 seconds (1 hour). Combine with a matching MaxSessionDuration for defense in depth.

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

### CTL.IAM.TRUST.OIDC.AUDIENCE.001

**OIDC Federation Trust Must Restrict Audience Claim**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3; owasp_nhi: NHI3; soc2: CC6.1;

IAM roles that trust OIDC identity providers must include an audience (aud) condition in the trust policy. Without an audience restriction, any OIDC token issued by the provider — regardless of the intended relying party — can be used to assume the role. An attacker who obtains a token meant for a different AWS account or a non-AWS service can replay it against this role.

**Remediation:** Add a StringEquals condition on the aud claim in the trust policy. For GitHub Actions use "token.actions.githubusercontent.com:aud": "sts.amazonaws.com".

---

### CTL.IAM.TRUST.OIDC.MUTABLE.SUBJECT.001

**OIDC Trust Subject Claim Uses Mutable Name-Based Identifiers**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

IAM role trust policy accepts OIDC tokens with a subject claim that uses name-based identifiers (repo:owner/repo-name) without immutable numeric anchors (repo:owner@ID/repo-name@ID). An attacker who renames, recreates, or claims a deleted repository (or project, or pipeline) matching the name in the subject claim can assume this IAM role and access every resource the role permits. GitHub repos created after July 15, 2026 use immutable numeric IDs in the subject claim. GitLab project_path claims are similarly mutable — use project_id with the numeric ID instead. Any OIDC provider using human-readable names without numeric anchors in the subject condition has the same vulnerability class.

**Remediation:** Update the subject condition to use immutable numeric identifiers. For GitHub Actions: change repo:owner/repo-name to repo:owner@<owner_id>/repo-name@<repo_id>. Get the IDs from the GitHub API: GET /repos/{owner}/{repo} returns the numeric id and owner.id fields. For GitLab: change project_path:group/project to project_id:<numeric_id>. For other OIDC providers: use immutable identifiers (project IDs, pipeline GUIDs) instead of names in the subject condition.

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
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.3; nist_800_53_r5: AC-3; owasp_nhi: NHI4; owasp_subtractive: S02; pci_dss_v4.0: 7.2.1; soc2: CC6.1; subtractive_tier: deletion;

IAM role trust policies must not use Principal "*" or Principal: {AWS: "*"}. A wildcard principal allows any AWS principal in any account to attempt role assumption. This is the most dangerous trust configuration — the role is effectively public to the entire AWS ecosystem.

**Remediation:** Replace Principal "*" with specific account ARNs or role ARNs. Add aws:PrincipalOrgID to restrict to the organization. Add sts:ExternalId for third-party integrations.

---

### CTL.IAM.USER.NEWSERVICE.001

**IAM User Created Instead of Federated Identity**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** cis_aws_v3.0: 1.1; nist_800_53_r5: AC-2, IA-2; soc2: CC6.1;

A new IAM user was created in an account that uses federated identity (SSO/Identity Center). IAM users in federated environments indicate shadow access paths: they bypass MFA enforcement, session policies, and central identity governance. New IAM users should not be created when Identity Center is the designated identity provider — all human access should route through federation.

**Remediation:** Delete the IAM user and provision access through Identity Center instead. If the user is for automation, convert to an IAM role with a service trust policy.

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
- **Compliance:** nist_800_53_r5: AC-2; owasp_subtractive: S07; soc2: CC6.1; subtractive_tier: deletion;

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

