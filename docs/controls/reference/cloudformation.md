# Control Reference — CLOUDFORMATION

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CLOUDFORMATION.DRIFT.001

**CloudFormation Stack Drift Detection Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

CloudFormation stacks managing production infrastructure must have drift detection enabled. Drift indicates out-of-band changes bypassing IaC.

**Remediation:** Detect drift: aws cloudformation detect-stack-drift --stack-name <name>. Configure periodic detection via EventBridge.

---

### CTL.CLOUDFORMATION.INCOMPLETE.001

**Complete Data Required for CloudFormation Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required CloudFormation properties.

**Remediation:** Ensure the extractor calls aws cloudformation describe-stacks.

---

### CTL.CLOUDFORMATION.ROLLBACK.001

**CloudFormation Stacks Must Have Rollback Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFormation stacks must not have DisableRollback set to true. With rollback disabled, a failed deployment leaves resources in a partially created state that may be insecure. Rollback ensures failed changes are reverted to the last known-good state.

**Remediation:** Remove DisableRollback from stack creation/update parameters. Ensure all stacks use the default rollback behavior.

---

### CTL.CLOUDFORMATION.SECRETS.001

**CloudFormation Stack Outputs Must Not Contain Secrets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); soc2: CC6.1;

CloudFormation stack outputs must not contain hardcoded secrets. Stack outputs are readable by anyone with cloudformation:DescribeStacks access, visible in the console, and logged in CloudTrail.

**Remediation:** Remove secrets from outputs. Use Secrets Manager or Parameter Store with dynamic references.

---

### CTL.CLOUDFORMATION.STACKPOLICY.001

**CloudFormation Stacks Must Have a Stack Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CM-3; soc2: CC8.1;

CloudFormation stack has no stack policy. Without a stack policy, any IAM principal with UpdateStack permission can modify or replace any resource in the stack. A stack policy acts as a secondary authorization control, preventing accidental or malicious resource replacement even when IAM allows the update.

**Remediation:** Set a stack policy that protects critical resources from replacement.

---

### CTL.CLOUDFORMATION.STACKSETS.RESTRICT.001

**CloudFormation StackSets Must Require Administrator Approval**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** mitre_attack: T1578; nist_800_53_r5: CM-3;

CloudFormation StackSets deploy infrastructure across multiple AWS accounts and regions simultaneously. An attacker with cloudformation:CreateStackSet and cloudformation:CreateStackInstances can execute arbitrary CloudFormation templates across an entire AWS Organization — creating IAM roles, modifying security groups, or deploying compute resources in hundreds of accounts. StackSet operations should require explicit approval and be restricted to trusted automation accounts or principals.

**Remediation:** Restrict cloudformation:CreateStackInstances to designated automation principals via SCP. Deny unless aws:PrincipalArn matches approved automation roles.

---

### CTL.CLOUDFORMATION.STATE.001

**Terraform State Must Be Versioned**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

Terraform state files must be stored in a versioned backend (S3 with versioning, Terraform Cloud, or equivalent). Unversioned state means a corrupted or accidentally deleted state file cannot be recovered, leaving infrastructure in an unmanaged state with no rollback path.

**Remediation:** Configure an S3 backend with versioning enabled and DynamoDB state locking. Alternatively, use Terraform Cloud or an equivalent managed backend with built-in versioning.

---

### CTL.CLOUDFORMATION.TERMINATION.001

**CloudFormation Stacks Must Have Termination Protection Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

CloudFormation root stacks must enable termination protection to prevent accidental or unauthorized deletion of infrastructure.

**Remediation:** Enable termination protection on the stack.

---

