# Control Reference — CODECOMMIT

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.CODECOMMIT.ACCESS.001

**CodeCommit Repositories Must Have Restrictive Resource Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; gdpr: Art.32; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

CodeCommit repositories must not allow overly broad access through wildcard principal resource policies or unrestricted IAM read permissions. Repositories contain source code, configuration files, infrastructure definitions, and frequently embedded secrets. MITRE ATT&CK T1213.003 documents code repository access as a collection technique — attackers use repository access to gather credentials and understand internal architecture before moving to higher-value targets. A compromised IAM role with broad CodeCommit read permissions can exfiltrate the entire codebase including hardcoded credentials, IaC files, and CI/CD pipeline configurations.

**Remediation:** Restrict repository resource policies to named principals. Scope IAM policies granting codecommit:GitPull and read actions to specific repository ARNs rather than Resource *. Enable CloudTrail data events for CodeCommit to audit repository access.

---

### CTL.CODECOMMIT.APPROVAL.001

**CodeCommit Repositories Must Have Branch Protection and Approval Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); iso_27001_2022: A.8.4; nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC8.1;

CodeCommit repositories must have approval rule templates configured on protected branches requiring at least one reviewer. Without branch protection, any principal with push permissions can commit directly to the main branch — bypassing code review, inserting malicious code into the deployment pipeline, and establishing persistence through the CI/CD chain. This is a supply chain persistence technique: the attacker uses the legitimate deployment pipeline to deliver their payload. Lambda code signing and ECR image signing enforce integrity at the artifact level; this control enforces integrity at the source level before the artifact is built.

**Remediation:** Create an approval rule template requiring at least one reviewer from a designated reviewer group. Apply the template to the default branch (main/master). Prevent force-push on the default branch. Use aws codecommit create-approval-rule-template to create the template and associate-approval-rule-template-with-repository to apply it.

---

