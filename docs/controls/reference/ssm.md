# Control Reference — SSM

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SSM.DOCUMENT.PUBLIC.001

**SSM Documents Must Not Be Publicly Shared**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SSM documents must not be shared publicly or with untrusted accounts. Public documents expose internal automation procedures, infrastructure configuration, and potentially embedded credentials.

**Remediation:** Remove public sharing from the document permissions.

---

### CTL.SSM.DOCUMENT.SECRETS.001

**SSM Documents Must Not Contain Embedded Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

SSM documents must not contain hardcoded passwords, access keys, tokens, or private keys. Use Secrets Manager or Parameter Store references instead.

**Remediation:** Replace hardcoded credentials with Secrets Manager or Parameter Store references.

---

### CTL.SSM.INVENTORY.RESTRICT.001

**SSM Inventory Access Must Be Restricted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1592; nist_800_53_r5: AC-3;

SSM inventory data must not be publicly shared or broadly accessible. SSM inventory contains detailed information about managed instances including installed software, running services, network configuration, and Windows registry data. Attackers use this information to identify vulnerable software versions, exposed services, and network paths for exploitation planning.

**Remediation:** Remove public sharing from SSM inventory resource data syncs. Restrict ssm:GetInventory and ssm:GetInventorySummary to administrative roles only. Review and scope down any resource data sync configurations that share inventory across accounts.

---

### CTL.SSM.PARAMETER.COLLECT.001

**SSM Parameter Store Must Restrict Bulk Parameter Listing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** mitre_attack: T1552; nist_800_53_r5: AC-6;

SSM Parameter Store holds database passwords, API keys, certificates, and other secrets. ssm:GetParametersByPath allows bulk retrieval of all parameters under a path prefix in a single API call — collecting all secrets at once. ssm:DescribeParameters lists all parameter names and metadata — enabling an attacker to map all stored secrets before extracting them. These permissions should be scoped to specific parameter paths needed by each application, not granted broadly.

**Remediation:** Replace ssm:GetParametersByPath with resource-scoped ssm:GetParameter grants on specific parameter ARNs. Restrict ssm:DescribeParameters to administrative roles.

---

### CTL.SSM.PATCH.BASELINE.001

**SSM Patch Manager Must Use a Custom Patch Baseline**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; scs_c02: 8.1; soc2: CC7.1;

SSM Patch Manager should use a custom patch baseline, not the AWS default. The default baseline auto-approves Critical and Important patches after 7 days but excludes all other classifications. A custom baseline lets the organization define which patches to approve, set approval delays per severity, and include patches the default baseline ignores (e.g., Moderate, Low, application- level patches).

**Remediation:** Create a custom patch baseline with approval rules matching your patching policy. Set it as the default for the relevant patch group. Define maintenance windows for automated patching.

---

### CTL.SSM.PATCH.COMPLIANCE.001

**SSM Managed Instances Must Be Patch Compliant**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC7.1;

SSM-managed instances must report patch compliance against defined baselines. Non-compliant instances are missing required security patches.

**Remediation:** Apply missing patches via SSM Patch Manager.

---

### CTL.SSM.PATCH.WINDOW.001

**SSM Patch Manager Must Use Maintenance Windows**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-2; soc2: CC8.1;

SSM Patch Manager operations must be scheduled through maintenance windows to prevent uncoordinated patching. Without maintenance windows, patches can be applied at arbitrary times — potentially during peak traffic, during change freezes, or simultaneously across all instances without rolling deployment.

**Remediation:** Create a maintenance window: aws ssm create-maintenance-window --name "patch-window" --schedule "cron(0 2 ? * SUN *)" --duration 4 --cutoff 1

---

### CTL.SSM.RUNCOMMAND.APPROVE.001

**SSM Run Command Must Require Change Manager Approval for Production**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1059.004; nist_800_53_r5: CM-3;

AWS Systems Manager Run Command allows executing arbitrary shell commands on any managed EC2 instance. An attacker with ssm:SendCommand permission can run commands on all production instances simultaneously — installing backdoors, exfiltrating data, or destroying files. Change Manager adds an approval workflow to SSM automation and Run Command. Without approval workflows, a single compromised IAM principal with ssm:SendCommand can achieve arbitrary code execution on every managed instance in the account.

**Remediation:** Enable Systems Manager Change Manager and configure approval templates requiring two or more approvers for production targets. Restrict ssm:SendCommand directly to Change Manager service role via IAM policy condition.

---

### CTL.SSM.RUNCOMMAND.RESTRICT.001

**SSM Run Command Must Be Restricted to Approved Documents**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.2.1; mitre_attack: T1059.009; nist_800_53_r5: AC-6;

SSM Run Command allows executing arbitrary commands on managed EC2 instances. Without restricting which command documents can be used, any principal with ssm:SendCommand can execute AWS-RunShellScript or AWS-RunPowerShellScript on any managed instance — providing remote code execution equivalent to SSH/RDP access without requiring key management or network-level access. This is MITRE ATT&CK T1059.009 (Cloud Administration Command). Restrict to approved documents only.

**Remediation:** Use IAM policy conditions to restrict ssm:SendCommand to specific document names. Deny AWS-RunShellScript and AWS-RunPowerShellScript for non-admin roles. Use Session Manager for interactive access instead of Run Command for shell access.

---

### CTL.SSM.SECURETYPE.001

**SSM Parameters in Sensitive Paths Must Use SecureString Type**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

AWS Systems Manager Parameter Store parameters that store values in String or StringList type when their path indicates sensitive content are readable by any IAM principal with ssm:GetParameter. SecureString parameters are KMS-encrypted at rest and require kms:Decrypt to read. This control checks the parameter type field — not the parameter value.

**Remediation:** Create a new SecureString parameter with the same value and update all references. SSM does not support changing parameter type in place — you must create a new parameter. Use aws ssm put-parameter --name <path> --type SecureString --value <value> --overwrite.

---

### CTL.SSM.SESSION.ENCRYPT.001

**SSM Session Manager Must Encrypt Sessions with KMS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8; soc2: CC6.7;

SSM Session Manager session preferences do not enable KMS encryption. Without KMS encryption, session data traverses the SSM channel without end-to-end encryption beyond the TLS transport layer. KMS encryption adds a customer-managed key layer, ensuring session data at rest in logs is encrypted with a key the account controls.

**Remediation:** Configure the SSM-SessionManagerRunShell document to encrypt sessions with a KMS key.

---

### CTL.SSM.SESSION.LOGGING.001

**SSM Session Manager Must Have Logging Enabled**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.2;

SSM Session Manager session preferences do not enable logging to S3 or CloudWatch Logs. Without session logging, interactive shell sessions to EC2 instances leave no audit trail. An attacker or insider who accesses an instance via Session Manager can execute arbitrary commands without detection. Session logging is configured via the SSM-SessionManagerRunShell document.

**Remediation:** Configure the SSM-SessionManagerRunShell document to log sessions to an S3 bucket or CloudWatch Logs log group.

---

