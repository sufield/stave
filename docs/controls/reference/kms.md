# Control Reference — KMS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.KMS.ALARM.CREATEGRANT.001

**KMS Key Has No CloudWatch Alarm for CreateGrant**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm wired to a CloudTrail metric filter for the kms:CreateGrant API call. Grants are a secondary access-control mechanism that delegate key access without modifying the key policy. An attacker with kms:CreateGrant permission can silently expand key access to arbitrary principals — Decrypt, Encrypt, GenerateDataKey, or RetireGrant — without leaving a trace in the key policy. Distinct from CTL.KMS.GRANT.BROAD.001 (asserts that grants authorize broad operations) and CTL.KMS.GRANT.EXCESSIVE.001 (asserts grant volume): this control fires on the missing detection wiring so each grant creation is caught when it happens.

**Remediation:** Create a CloudTrail metric filter on eventName = CreateGrant and a CloudWatch alarm with an SNS notification action. AWS services (EBS, RDS, Redshift) create grants automatically; tune the threshold to baseline expected service-driven grant volume so human-driven grants stand out. Route notifications to the security team for grant audit.

---

### CTL.KMS.ALARM.CROSSACCOUNT.001

**KMS Key Has No CloudWatch Alarm for Cross-Account Usage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has cross-account access in its policy but no CloudWatch alarm for KMS API calls from external accounts. Cross-account KMS usage is expected when keys are intentionally shared, but unexpected cross-account usage may indicate: a key policy broader than intended, a compromised external account using shared key access, or data exfiltration via cross-account decryption. The control fires ONLY when the key has cross-account access (precondition); a key with no cross-account principal cannot be used cross- account, so the alarm is unnecessary. Distinct from CTL.KMS.POLICY.CROSSACCOUNT.001 (asserts the policy is broad cross-account): this control assumes cross-account access is intentional and fires on the missing detection wiring around it.

**Remediation:** Create a CloudTrail metric filter on KMS events where userIdentity.accountId does not equal the key's account, and a CloudWatch alarm with an SNS notification action. Route to the security team and the SIEM. If cross-account access is unintentional, remove the cross-account statement from the key policy instead of relying solely on the alarm.

---

### CTL.KMS.ALARM.DECRYPT.FAILURE.001

**KMS Key Has No CloudWatch Alarm for Decrypt Failures**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.3;

KMS key has no CloudWatch alarm on Decrypt-failure errors (AccessDeniedException, KMSInvalidStateException, DisabledException). Decrypt failures appear as errorCode in CloudTrail events and indicate either an active security event (unauthorized access attempts, credential stuffing) or an operational failure (key state change breaking dependent services). The control fires on missing detection — alarms on individual failures cause false-positive noise; the intended threshold is a SPIKE in failures over a baseline.

**Remediation:** Create a CloudTrail metric filter on errorCode in [AccessDeniedException, KMSInvalidStateException, DisabledException] for eventName = Decrypt, and a CloudWatch alarm on the resulting metric. Use a spike-relative threshold rather than absolute counts — individual failures are normal; sustained elevated rates indicate an active issue. Route to SIEM for correlation with IAM events.

---

### CTL.KMS.ALARM.DECRYPT.VOLUME.001

**KMS Key Has No CloudWatch Alarm for High-Frequency Decrypt**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm on Decrypt-call volume. KMS Decrypt is invoked every time encrypted data is read — S3 GetObject, RDS data access, Lambda cold start, Secrets Manager GetSecretValue. Normal usage has a baseline. A sudden spike — 10x or 100x baseline — indicates bulk exfiltration (an attacker decrypting thousands of S3 objects or database records), credential theft (decrypting many secrets), or a retry storm. The control checks for ALARM EXISTENCE only; threshold tuning is operational. A static threshold that's too low causes false positives on legitimate traffic spikes, too high misses targeted exfiltration — anomaly detection or baseline-relative thresholds are preferred.

**Remediation:** Create a CloudWatch alarm on the AWS/KMS Decrypt operation count metric (NumberOfRequestsAccepted with Operation=Decrypt). Use anomaly detection with a 2-week baseline, or a threshold based on observed normal volume. Period of 5 minutes balances detection speed against false-positive rate. Notify the security team and route to the SIEM for correlation with downstream S3/RDS/Secrets Manager access patterns.

---

### CTL.KMS.ALARM.DELETION.001

**KMS Key Has No CloudWatch Alarm for ScheduleKeyDeletion**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm wired to a CloudTrail metric filter for the kms:ScheduleKeyDeletion API call. ScheduleKeyDeletion starts the 7-30 day countdown to permanent key destruction — the most destructive KMS operation. CloudTrail records the call by default, but without an alarm the event sits in the log unread until a dependent service fails. Combined with CTL.KMS.STATE.PENDINGDELETION.001, this control is the DETECTION layer: STATE detects the pending state itself; ALARM detects the moment the state is entered, so the team can run CancelKeyDeletion within seconds-to-minutes instead of discovering the change days later. Distinct from CTL.KMS.STATE.PENDINGDELETION.001 (asserts state, fires after the fact) and CTL.KMS.DELETION.MINWAIT.001 (asserts waiting window length, configuration).

**Remediation:** Create a CloudTrail metric filter on eventName = ScheduleKeyDeletion and a CloudWatch alarm with an SNS notification action — aws logs put-metric-filter --filter-pattern '{ $.eventName = "ScheduleKeyDeletion" }' followed by aws cloudwatch put-metric-alarm with a SNS topic that pages on-call. Alarm threshold should be 1 (any occurrence) and the period should be the smallest available (60s) so notification fires within minutes of the API call.

---

### CTL.KMS.ALARM.DISABLE.001

**KMS Key Has No CloudWatch Alarm for DisableKey**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm wired to a CloudTrail metric filter for the kms:DisableKey API call. DisableKey takes effect immediately — there is no waiting period. Every subsequent Encrypt, Decrypt, GenerateDataKey, and ReEncrypt call returns KMSInvalidStateException, breaking every dependent service on its next cryptographic operation. EnableKey reverses the damage but only after someone notices and acts. Without an alarm, discovery depends on cascading error alerts from dependent services — minutes to hours later depending on traffic. Distinct from CTL.KMS.STATE.DISABLED.001 (asserts the resulting state, fires after the fact): this control fires on the missing detection wiring so the disable event itself is caught in real time.

**Remediation:** Create a CloudTrail metric filter on eventName = DisableKey and a CloudWatch alarm with an SNS notification action that pages on-call. Threshold should be 1 (any occurrence) and the period should be 60s so notification fires within minutes — fast enough that EnableKey can run before cascading service failures accumulate.

---

### CTL.KMS.ALARM.POLICYCHANGE.001

**KMS Key Has No CloudWatch Alarm for PutKeyPolicy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.6; fedramp_moderate: SI-4; hipaa: 164.312(b); iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm wired to a CloudTrail metric filter for the kms:PutKeyPolicy API call. PutKeyPolicy replaces the entire key policy document — the access control for who may use the key. A single API call can grant Decrypt to new principals, add Principal "*", grant cross-account access, remove condition keys, or grant GrantWithGrant. Key policy changes don't affect existing ciphertexts, but they change WHO can decrypt that data going forward. Without a real-time alarm, key policy modifications are invisible until the next manual audit. Distinct from CTL.KMS.POLICY.ADMIN.BROAD.001 (asserts the resulting permission breadth) and CTL.KMS.POLICY.001 (asserts the presence of Principal "*"): this control fires on the missing detection wiring so the policy change itself is caught at the moment it happens.

**Remediation:** Create a CloudTrail metric filter on eventName = PutKeyPolicy and a CloudWatch alarm with an SNS notification action. Threshold should be 1 (any occurrence) and the period should be 60s so the security team is notified immediately. Consider routing the notification to both on-call and the audit logging system so the change is triaged AND retained for retrospective review.

---

### CTL.KMS.ALARM.ROTATION.FAILURE.001

**KMS Key Has No CloudWatch Alarm for Rotation Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.24; nist_800_53_r5: SI-4; owasp_nhi: NHI7; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

KMS key has no CloudWatch alarm wired to KMS key rotation events. Rotation events indicate the key material was rotated — expected annually if auto-rotation is enabled. A FAILED rotation means the key material did NOT change, so the old material continues past its intended lifetime. An UNEXPECTED rotation (manual rotation outside the schedule) may indicate a compromise response or unauthorized activity. Distinct from CTL.KMS.ROTATION.001 (asserts auto-rotation is enabled, configuration): this control fires on the missing detection wiring around rotation events themselves.

**Remediation:** Create a CloudTrail metric filter on eventName = RotateKeyOnDemand and EnableKeyRotation/DisableKeyRotation, plus the AWS/KMS RotationFailure metric where available. A CloudWatch alarm on the resulting metrics with an SNS notification action surfaces unexpected or failed rotations in real time. Route to the cryptography or platform team for follow-up.

---

### CTL.KMS.ALIAS.GHOST.001

**KMS Alias Points to Disabled or Pending-Deletion Key**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; nist_800_53_r5: CM-2; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

KMS alias resolves to a key in Disabled or PendingDeletion state. KMS aliases are human-readable names for keys — alias/production- encryption, alias/database-key, alias/api-secrets — that resources and IAM policies use instead of bare key IDs. The alias still resolves and appears valid, but the underlying key cannot perform cryptographic operations. A developer reading the IAM policy sees alias/production-encryption and assumes the key is operational. An auditor sees the alias in a resource configuration and marks it compliant. Resources fail with non-obvious errors because the alias hides the key's broken state. This is the "appears to work" pattern at the encryption layer — the reference looks valid, the key cannot function. Distinct from CTL.KMS.ALIAS.ORPHAN.001 (alias points to a key that no longer exists at all): here the key still exists but cannot perform operations.

**Remediation:** Identify the underlying key state (aws kms describe-key --key-id alias/NAME). If the key is Disabled, decide whether to re-enable it (aws kms enable-key) or repoint the alias to a different operational key (aws kms update-alias). If the key is PendingDeletion, either cancel the deletion (aws kms cancel-key-deletion) or repoint the alias before the deletion window expires. Audit which resources reference this alias so the impact of repointing is understood.

---

### CTL.KMS.ALIAS.ORPHAN.001

**KMS Alias Points to a Non-Existent Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; nist_800_53_r5: CM-2; soc2: CC8.1;

KMS alias references a key ID that no longer exists. The underlying key was permanently deleted (the deletion waiting period expired) or never existed. The alias persists in the account — visible to ListAliases, referenced by IAM policies and resource configurations — but cannot resolve to a usable key. Any attempt to use the alias for an Encrypt, Decrypt, GenerateDataKey, or ReEncrypt call returns NotFoundException. Distinct from CTL.KMS.ALIAS.GHOST.001 (alias points to a Disabled or PendingDeletion key that still exists): here the alias points to nothing at all. The orphan alias is operational debris from incomplete decommission — the key was deleted, the alias was not.

**Remediation:** Audit IAM policies and resource configurations for references to this alias before deleting it — the references will fail too, but the failure mode (NotFoundException vs. NotAuthorizedException) and the alias name carry remediation information. Once dependent references are remediated (repoint or remove), delete the alias with aws kms delete-alias --alias-name alias/NAME. Track alias creation and key deletion together in decommission runbooks so future cleanups don't leave orphans.

---

### CTL.KMS.CONCENTRATION.001

**KMS Key Must Not Encrypt More Than 50 Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** nist_800_53_r5: SC-12; soc2: A1.1;

A single KMS key encrypting more than 50 resources represents a cryptographic single point of failure. If the key is deleted, disabled, or its policy misconfigured, all dependent resources become inaccessible. The extractor counts the number of unique resources encrypted with each KMS key.

**Remediation:** Create per-service or per-application KMS keys to distribute the encryption dependency. Use key aliases for easy migration. Enable key deletion protection on high-density keys.

---

### CTL.KMS.CONCENTRATION.002

**High-Density KMS Key Must Have Deletion Protection**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** storage
- **Compliance:** fedramp_moderate: SC-12(1); nist_800_53_r5: SC-12(1); soc2: A1.1;

KMS keys encrypting more than 50 resources must have deletion protection enabled. Without deletion protection, an accidental or malicious ScheduleKeyDeletion call can render hundreds of resources permanently unrecoverable within the 7-day minimum waiting period.

**Remediation:** Enable key deletion protection. Apply a key policy that denies kms:ScheduleKeyDeletion from all principals except a dedicated key administrator role. Add an SCP to deny key deletion at the organization level.

---

### CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001

**KMS Key Shared with Excessive Number of External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.24; nist_800_53_r5: AC-3, AC-4, AC-6; owasp_nhi: NHI6; pci_dss_v4.0: 3.5, 7.1; soc2: CC6.1, CC6.6;

KMS key policy grants access to more than five external AWS accounts. The key's blast radius spans many accounts in both directions: if the key is compromised, disabled, or deleted, every sharing account that depends on it is affected; if any one of the sharing accounts is compromised, the attacker acquires cryptographic operations on data in every other sharing account. The blast radius grows roughly quadratically in the number of sharing accounts — N accounts means N populations of data at risk if the key fails, and N independent compromise paths to the key if any account is breached. Distinct from CTL.KMS.POLICY.CROSSACCOUNT.001 (asserts the presence of conditions on cross-account access) — that control checks the protective semantics of the policy; this control checks the topology of who is sharing, regardless of whether conditions are present. Threshold of five is a heuristic that accommodates legitimate centralized patterns (organization logging key, shared encryption key for a small multi-account application) while flagging the cases where centralization has eroded into sprawl.

**Remediation:** Audit the cross-account principals in the key policy (aws kms get-key-policy --key-id <id> --policy-name default). For each external account, determine whether the access is still required and whether a per-account or per-tenant key would isolate the blast radius. The typical fix is to split the key by tenant or by workload — one key per account or per logical group of accounts — rather than continue to centralize. If a single shared key remains necessary (e.g., a logging pipeline that genuinely spans the organization), document the residual blast radius and add cross- account decryption monitoring (CTL.KMS.ALARM.CROSSACCOUNT.001) to compensate.

---

### CTL.KMS.CROSSACCOUNT.DECOMMISSIONED.001

**KMS Key Policy Grants Access to Decommissioned Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-2; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: AC-2, AC-3; owasp_nhi: NHI1; pci_dss_v4.0: 3.5, 7.2.4; soc2: CC6.1, CC8.1;

KMS key policy grants access to an AWS account ID that is no longer active in the organization — the account was closed, decommissioned, or transferred to an external party. The policy entry persists. The danger has two shapes: if the account ID was transferred, the key policy now grants access to an entity outside organizational control; if the account was closed, the residual policy entry is decommission debris that obscures the actual access topology. Detection requires cross-referencing the key policy's cross-account principals against the active account list (AWS Organizations or an inventory of authorized accounts). When account inventory is unavailable the control cannot fire — fail loud rather than silently passing keys whose authorization has not been reconciled. Same incomplete-decommission family as CTL.KMS.GRANT.ORPHAN.001 (orphan grant principal), CTL.KMS.ALIAS.ORPHAN.001 (alias orphan), and CTL.IAM.ROLE.GHOST.001 — debris that survives the decommission of its referent.

**Remediation:** Confirm the account's status with AWS Organizations (aws organizations describe-account --account-id <id>). If the account was closed or transferred, remove the principal from the key policy (aws kms put-key-policy --key-id <id> --policy-name default --policy <updated>). Investigate any other artifacts that referenced the same account ID — IAM trust policies, S3 bucket policies, SCPs — to ensure the decommission is complete. If the account was migrated inside the organization to a new ID, repoint the policy to the new ID rather than leaving both.

---

### CTL.KMS.DELETION.MINWAIT.001

**KMS Key Deletion Scheduled With Minimum Waiting Period**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12(1); hipaa: 164.312(a)(1); nist_800_53_r5: SC-12(1); pci_dss_v4.0: 3.6.1.4; soc2: A1.1;

KMS key is scheduled for deletion with the minimum waiting period (7 days). The deletion waiting period is the safety window between ScheduleKeyDeletion and permanent key deletion — the only time during which CancelKeyDeletion can stop the destruction and during which dependent resources surface failures that prompt investigation. The configurable range is 7-30 days. At 7 days, a weekly batch job may not run before deletion; a monthly report will not discover the failure; a low-traffic service may not trigger enough errors to be noticed. 30 days provides time for weekly jobs, monthly processes, and infrequently-invoked services to encounter the failure, alert, and prompt CancelKeyDeletion. The minimum window should be reserved for keys confirmed to have no dependent resources — an audit, not a default.

**Remediation:** Cancel the deletion (aws kms cancel-key-deletion) and reschedule with a 30-day waiting period (--pending-window-in-days 30). The longer window allows weekly and monthly jobs to encounter failures and trigger investigation. Use the 7-day minimum only when an audit confirms no dependent resources reference the key across S3, RDS, EBS, Lambda, DynamoDB, CloudWatch Logs, Secrets Manager, SNS, SQS, and other services.

---

### CTL.KMS.ENTROPY.EXTERNAL.ORIGIN.001

**KMS Customer Keys Should Use AWS-Generated Key Material, Not Imported External Material**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12, SC-13; soc2: CC6.1;

A customer-managed KMS key uses imported external key material (Origin: EXTERNAL). Imported material may have been generated with insufficient entropy on an external system — a laptop, an on-prem HSM of unknown configuration, or a weak RNG. AWS-generated keys (Origin: AWS_KMS) and CloudHSM-generated keys (Origin: AWS_CLOUDHSM) use FIPS 140-2 validated HSMs with a hardware RNG; the entropy quality of imported material is unverifiable — Stave can see that a key was imported, not how its bytes were produced.
Advisory (low severity), not a hard failure: imported material is a legitimate pattern for key portability and multi-cloud/BYOK key management. This control flags customer-managed EXTERNAL-origin keys for review — confirm the external source used a CSPRNG backed by a hardware RNG. AWS-managed keys (is_aws_managed) are skipped: they always use AWS-generated material. The PendingImport state does not clear the concern — the intent is still to use imported material whose entropy is unverifiable.
Entropy controls inspired by NCC Group "Time as an Attack Surface" white paper — extended to cover key material and key pair algorithm entropy properties.

**Remediation:** Prefer AWS-generated material: create the key with Origin AWS_KMS (or AWS_CLOUDHSM). If imported material is required for portability/BYOK, confirm the external source used a CSPRNG backed by a validated hardware RNG and document the exception.

---

### CTL.KMS.FIPS.001

**KMS Keys Must Use FIPS 140-2 Validated HSM Origin**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-13;

KMS keys must have AWS_KMS origin, confirming they are generated and stored in FIPS 140-2 Level 2 validated hardware security modules. Keys with EXTERNAL or CUSTOM_KEY_STORE origin may not meet FedRAMP FIPS 140 cryptography requirements.

**Remediation:** Create a new key with AWS_KMS origin (default). Rotate data encrypted with the non-compliant key to the new key.

---

### CTL.KMS.GRANT.BROAD.001

**KMS Grant Has Overly Broad Operations**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

A KMS grant includes multiple sensitive operations (Decrypt, Encrypt, GenerateDataKey, ReEncryptFrom, ReEncryptTo) for a single grantee. Grants should follow least privilege — a grantee that needs to encrypt should not also have decrypt. Broad grants effectively give full cryptographic access to the key.

**Remediation:** Restrict KMS grants to the minimum required operations. A grantee that needs Encrypt should not also have Decrypt. Use separate grants for distinct operational needs. Review grants with aws kms list-grants --key-id KEY.

---

### CTL.KMS.GRANT.EXCESSIVE.001

**KMS Key Has Excessive Active Grants**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.24; nist_800_53_r5: AC-6; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

KMS key has more than 100 active grants. The KMS service limit is 50,000 grants per key, but more than 100 active grants is a red flag for: programmatic grant creation without governance (grants created but never retired), an unauditable access surface (100+ grants across many principals and operations cannot be manually reviewed), and incomplete cleanup of short-lived workloads. AWS services that use grants (EBS, RDS, Redshift) may create many grants automatically; the threshold is conservative to avoid false positives on service-managed grant volume.

**Remediation:** Audit grants with aws kms list-grants --key-id KEY. Retire grants whose grantee principals no longer exist or whose operations are no longer needed. Establish a grant lifecycle: every workflow that creates a grant must retire it on completion. Track grant count over time; investigate unbounded growth.

---

### CTL.KMS.GRANT.ORPHAN.001

**KMS Grant References a Deleted Principal**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; nist_800_53_r5: AC-2; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.4; soc2: CC6.1;

KMS grant grants cryptographic operations to a principal (IAM role or user) that has been deleted. The grant persists in the key's grant list — consuming grant quota (50,000 per key) and cluttering the access-control surface. Orphaned grants cannot be exercised (the principal does not exist) but they signal incomplete cleanup and obscure the actual access state of the key. Distinct from CTL.KMS.POLICY.GHOSTREF.001 (deleted principal in the key policy): grants are an alternative access mechanism not visible in the key policy document. They require a separate ListGrants API call to enumerate. Orphan grants imply the IAM role lifecycle drove the grantee out of existence but the grant retirement step was skipped.

**Remediation:** Retire the orphan grant with aws kms retire-grant --grant-id GRANT_ID --key-id KEY. Audit the IAM lifecycle workflow that deleted the role to ensure grant retirement is part of the decommission runbook (the role-delete tooling should call ListGrantsForPrincipal across keys it had grants on, then RetireGrant for each).

---

### CTL.KMS.GRANT.STALE.001

**KMS Key Has Grants Older Than Last Rotation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6; pci_dss_v4.0: 3.7.5; soc2: CC6.1;

A KMS key has rotation enabled and active grants that were created before the most recent key material rotation. These grants were authorized against the previous key material and may authorize principals that should no longer have access. Key rotation changes the cryptographic material but does not invalidate or review existing grants — the old grants carry forward automatically. When a grant was created for a time-bounded purpose (short-lived workload, temporary access) and the key has since rotated, the grant's continued existence represents stale authorization that rotation was meant to address. The compound failure: rotation happens but the access surface does not contract.

**Remediation:** Review all active grants on the key. Retire grants that were created for time-bounded purposes and are no longer needed. Use aws kms list-grants and aws kms retire-grant to audit and clean up stale grants after each rotation.

---

### CTL.KMS.IMPORTED.EXPIRY.001

**Imported KMS Key Material Without Expiration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: SC-12(1); nist_800_53_r5: SC-12(1); owasp_nhi: NHI7; pci_dss_v4.0: 3.6.1.2; soc2: CC6.1;

Imported key material has no expiration date set. Imported keys persist indefinitely without forced rotation. Unlike AWS-generated key material (which supports automatic rotation), imported material must be manually re-imported. Without expiration, there is no mechanism forcing re-import and periodic review of the key material source.

**Remediation:** Re-import the key material with an expiration date set. Use aws kms import-key-material with --valid-to to set an expiration that forces periodic re-import and review.

---

### CTL.KMS.INCOMPLETE.001

**Complete Data Required for KMS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required KMS key properties. A safety assessment cannot be completed without key policy data.

**Remediation:** Ensure the extractor calls aws kms get-key-policy and maps the response to the cryptography observation properties.

---

### CTL.KMS.ISOLATION.001

**PHI/CDE Encryption Key Must Not Be Shared Across Sensitivity Domains**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

KMS keys protecting PHI or CDE data must not be shared with resources at a lower sensitivity classification. Shared keys collapse the cryptographic boundary between trust domains. A compromised developer account with access to a shared key can decrypt production PHI data even if all other access controls are correctly configured. Encryption is only as strong as the isolation of its keys.

**Remediation:** Create dedicated KMS keys per sensitivity domain. Apply key policies that restrict usage to IAM roles operating within that domain. Rotate existing PHI/CDE data to new domain-exclusive keys. Use KMS key tags (sensitivity=phi) and SCPs to prevent cross-domain key usage at the organizational level.

---

### CTL.KMS.LIFECYCLE.CROSSENV.001

**KMS Key Used Across Production and Non-Production Environments**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.5.10, A.8.24; nist_800_53_r5: AC-4, SC-12, SC-28; pci_dss_v4.0: 3.5, 7.2.4; soc2: CC6.1, CC6.7;

KMS key encrypts resources tagged production AND resources tagged non-production (development, staging, testing). A single key crossing the prod/non-prod boundary is a bidirectional risk: a non-production action — a developer disabling the key during cleanup, a sandbox automation scheduling deletion, a policy broadened for debug access — silently changes the security posture of the production data also encrypted with that key. The relationship runs the other way too: anyone with Decrypt on the key in non-production can decrypt production ciphertext, because it is the same key. The remediation is a per-environment key with an alias that encodes the environment (alias/prod-database-key, alias/dev-database-key) and policies that do not authorize cross-environment use. Same cross-environment pattern as CTL.RDS.SNAPSHOT.CROSSENV.001, CTL.APIGATEWAY.STAGE.CROSSENV.001, and CTL.VPC.SEGMENT.ENVMIX.001 — environment is a trust domain, and shared cryptographic material collapses that domain.

**Remediation:** Create per-environment keys with environment-encoded aliases (alias/prod-<workload>-key, alias/dev-<workload>-key). Re-encrypt non-production data under the non-production key and update resource references; production data should remain on a production-only key whose policy does not authorize non-production principals. Once split, gate future key use with provisioning pipelines that enforce environment alignment between key and resource. Use environment tags (env=prod, env=dev) consistently across resources so the drift can be re-detected.

---

### CTL.KMS.LIFECYCLE.DORMANT.001

**KMS Key Not Used for 90+ Days With Active Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2; hipaa: 164.312(a)(1); nist_800_53_r5: AC-2; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.4; soc2: CC6.1;

KMS key has not been used for any cryptographic operation in more than 90 days, yet its key policy continues to grant access to principals. Dormant keys are a latent decryption surface: the policy still grants kms:Decrypt, the key can still be used by anyone with that permission, and nobody monitors the key for anomalous usage because it appears unused. If the key encrypted historical data in S3, RDS snapshots, or other services, that data remains decryptable to anyone who discovers the key ARN and has Decrypt permission — even though no application actively uses the key. Same 90-day dormancy threshold used across Lambda, IAM roles, DynamoDB, CloudFront, and Route 53 controls. The finding prompts review: if the key is truly unused, disable it (and eventually schedule deletion); if it encrypts archival data, minimize the policy to the principals who legitimately need archival decryption.

**Remediation:** Audit the key's usage history (CloudTrail GetKeyPolicy / Encrypt / Decrypt events) to confirm true dormancy. If the key is unused, disable it (aws kms disable-key) and plan decommission. If it still encrypts archival data, minimize the key policy to the specific principals authorized for archival decryption and add aws:CalledVia or kms:ViaService conditions so the policy cannot be used outside the archival workflow.

---

### CTL.KMS.LIFECYCLE.NOALIAS.001

**KMS Key Has No Alias**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.9, A.8.24; nist_800_53_r5: CM-2, CM-3; soc2: CC6.1, CC8.1;

KMS key has no alias attached and is referenced only by its key ID (a UUID). Aliases are the human-readable handle for a key — alias/production-database, alias/s3-backup-encryption, alias/api-secrets — and they are how IAM policies, resource configurations, and runbooks should reference the key. A key with no alias is unmanageable at scale: a key ID like 1234abcd-12ab-34cd-56ef-1234567890ab carries no information about purpose, owner, or workload. Audit trails name the ID; on-call cannot tell at a glance whether the key in question encrypts production data or a developer experiment. This is a governance signal, not a vulnerability — the key is no less secure for lacking an alias — but alias-less keys correlate with incomplete provisioning, lost ownership, and key sprawl. Distinct from CTL.KMS.ALIAS.GHOST.001 (alias points to a Disabled or PendingDeletion key) and CTL.KMS.ALIAS.ORPHAN.001 (alias points to a deleted key) — both check the validity of an existing alias; this control checks for the alias's presence at all.

**Remediation:** Attach an alias that names the key's purpose (aws kms create-alias --alias-name alias/<purpose> --target-key-id <id>). Use a stable naming convention — alias/<environment>-<workload>-<role> — and gate new key creation on alias presence in your provisioning pipeline. Update IAM policies and resource configurations to reference the alias rather than the key ID, so that key rotations and replacements do not require policy edits.

---

### CTL.KMS.LIFECYCLE.ROTATION.PERIOD.001

**KMS Key Rotation Period Exceeds Compliance Requirement**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: CM-2, CM-3, SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 3.6; soc2: CC6.1, CC8.1;

KMS key has automatic rotation enabled, but the configured rotation period exceeds the rotation cadence required by an applicable compliance profile. The AWS default is 365 days; KMS now supports configurable rotation periods between 90 and 2560 days. Some compliance interpretations and many internal policies require shorter cadences — 90 days is the common floor — to limit the volume of data encrypted under any single key version and to bound the recovery window after a key compromise. This control is profile-conditioned: it fires only when a compliance tag or compliance profile is present on the key AND the configured period exceeds the required period. Same compliance-profile pattern as CTL.RDS.BACKUP.RETENTION.COMPLIANCE.001 — the requirement comes from the profile, not from a single fixed threshold. Distinct from CTL.KMS.ROTATION.001 (asserts rotation is enabled at all): this control assumes rotation is on and asserts the period is short enough.

**Remediation:** Reduce the rotation period to the required cadence (aws kms enable-key-rotation --key-id <id> --rotation-period-in-days 90). Confirm the required cadence with the compliance profile owner before setting the value — different profiles require different periods, and the floor of 90 days is not universal. If the key is shared across workloads with different compliance profiles, the strictest period applies. After updating, verify the next scheduled rotation (aws kms get-key-rotation-status --key-id <id>) aligns with the new cadence.

---

### CTL.KMS.MATERIAL.EXPIRED.001

**KMS Imported Key Material Has Expired**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12(2); hipaa: 164.312(a)(1); nist_800_53_r5: SC-12(2); pci_dss_v4.0: 3.6.1.2; soc2: CC6.1;

KMS key with EXTERNAL origin has key material whose expiration date has passed. The key still exists, but new Encrypt and GenerateDataKey calls fail with KMSInvalidStateException because the cryptographic material is past its valid-to date. Existing ciphertext can still be decrypted (KMS retains expired material for decryption), so historical workloads continue to work — but any new write path fails immediately. The failure pattern is asymmetric and confusing: read paths succeed, write paths fail, the key is enabled, the key has material. The fix is to import fresh key material via aws kms import-key-material with a new --valid-to or --expiration-model KEY_MATERIAL_DOES_NOT_EXPIRE. Distinct from CTL.KMS.IMPORTED.EXPIRY.001 (no expiration set): here the expiration was set and has been reached.

**Remediation:** Import fresh key material with aws kms import-key-material. Fetch import parameters (aws kms get-parameters-for-import), wrap the fresh key bytes with the returned wrapping key, and submit them with the import token. Choose a deliberate expiration: either a future --valid-to that aligns with the key- rotation runbook, or KEY_MATERIAL_DOES_NOT_EXPIRE if the key must never auto-expire. Update the rotation runbook so the next expiration is detected before it is reached, not after.

---

### CTL.KMS.MULTIREGION.NONCOMPLIANT.REGION.001

**KMS Multi-Region Key Replicated to Non-Compliant Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12; gdpr: Art.44; iso_27001_2022: A.5.34, A.8.24; nist_800_53_r5: SC-12, SC-13, CP-6; pci_dss_v4.0: 3.5; soc2: CC6.1;

KMS multi-region key has a replica in a region that does not comply with the data residency requirements applied to the key. Data residency typically constrains where ciphertext may live, but the same constraints almost always extend to the key material — the key material is the cryptographic decision authority for the data, and a key material present in a region is decryption-capable in that region. Even when the encrypted data remains in a compliant region, a replica in a non-compliant region means decryption can occur there: an authorized principal in the non-compliant region can pull ciphertext, decrypt it locally with the replica, and the plaintext exists in the non-compliant region for the duration of that operation. Same data residency inheritance pattern as CTL.S3.BUCKET.REGION.RESIDENCY.001 and CTL.RDS.SNAPSHOT.RESIDENCY.001.

**Remediation:** Identify the offending replica (aws kms describe-key --key-id <id> in the suspect region), confirm with legal/compliance whether residency requirements extend to key material, and either schedule the replica for deletion (aws kms schedule-key-deletion in the non-compliant region) or relocate the workload to permit residency. If business requirements demand cryptographic operations in the region, escalate to revisit residency scope rather than ignore the gap.

---

### CTL.KMS.MULTIREGION.NOREPLICA.001

**KMS Multi-Region Key Has No Replicas**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, CP-6; soc2: CC6.1;

KMS key has multi-region configuration enabled but no replica keys exist in other regions. Multi-region keys carry overhead — the service-linked role for replication, the cross-region coordination, the key-policy semantics that admit replication — without delivering the benefit (no cross-region key availability, no latency reduction for cross-region workloads, no DR position for encrypted data). Either the key should have replicas in the regions where it is needed, or it should be a single-region key. The configuration as it stands is the multi-region overhead with the single-region utility. Same pattern as CTL.DYNAMODB.GLOBAL.SINGLEREGION.001 and CTL.RDS.AURORA.SINGLEINSTANCE.001 — declared multi-region topology with no actual multi-region presence.

**Remediation:** Either replicate the key to the regions that need it (aws kms replicate-key --key-id <primary-key-id> --replica-region <region>) or remove multi-region configuration by recreating the key as single-region. Multi-region configuration without replicas is rarely intentional — investigate the original design and align the configuration with the actual usage.

---

### CTL.KMS.MULTIREGION.POLICY.MISMATCH.001

**KMS Multi-Region Key Replicas Have Inconsistent Key Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3, SC-12; pci_dss_v4.0: 3.5; soc2: CC6.1;

KMS multi-region key has replicas in other regions whose key policies differ from the primary's. The same key material is present in multiple regions but the access control surface is not — principals authorized to use the key in one region may be unauthorized in another, or worse, principals denied at the primary may be permitted at a replica. Because every replica shares the primary's key material, ciphertext encrypted in any region can be decrypted in any region whose replica grants Decrypt to the caller. The effective access control for data encrypted with this key is the weakest replica policy. Same cryptographic-boundary-collapse pattern as CTL.DYNAMODB.GLOBAL.ENCRYPT.MISMATCH.001 and CTL.RDS.AURORA.GLOBAL.UNENCRYPTED.001 applied to the key- policy layer.

**Remediation:** Standardize the key policy across the primary and all replicas. KMS does not automatically replicate key policies — every region's policy must be put explicitly. Establish a single policy template, apply it via aws kms put-key-policy in every region the key exists, and gate future changes with a deployment pipeline that updates all replicas atomically. If the regional differences are intentional (e.g., region-specific service principals), document them and confirm that the weakest policy is acceptable for the data the key protects.

---

### CTL.KMS.PENDING.DELETION.001

**KMS Key Must Not Be Pending Deletion While Resources Depend On It**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12(1); nist_800_53_r5: SC-12(1); owasp_nhi: NHI1; soc2: A1.1;

KMS keys scheduled for deletion have a waiting period (7-30 days) before key material is permanently destroyed. Once deleted, all data encrypted by the key becomes permanently inaccessible — S3 objects, RDS snapshots, EBS volumes, Secrets Manager secrets, and any other resource encrypted by this key. This control detects keys pending deletion that still have dependent resources, giving operators time to cancel deletion or re-encrypt resources with a different key.

**Remediation:** Cancel key deletion with aws kms cancel-key-deletion, then re-evaluate whether the key should be deleted. If deletion is intentional, first re-encrypt all dependent resources with a different key.

---

### CTL.KMS.POLICY.001

**KMS Key Policy Must Restrict Access to Specific Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; ffiec: ISH-4; gdpr: Art.32; hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; nist_csf_2.0: PR.DS; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies must not grant wildcard principal access. A key policy with Principal "*" allows any IAM entity in the account (or any account if conditions are missing) to use the key, defeating the purpose of customer-managed encryption.

**Remediation:** Update the key policy to restrict Principal to specific IAM roles or accounts. Remove any statements with Principal "*".

---

### CTL.KMS.POLICY.ADMIN.BROAD.001

**KMS Key Administration Must Be Restricted to Key Administrators**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6(5); iso_27001_2022: A.8.24; nist_800_53_r5: AC-6(5); owasp_nhi: NHI5; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

KMS key policies must not grant key administration actions (kms:Create*, kms:Put*, kms:Disable*, kms:ScheduleKeyDeletion, kms:EnableKey, kms:EnableKeyRotation, kms:UpdateKeyDescription) to principals beyond designated key administrators. Broad administrative access allows any granted principal to disable the key, schedule it for deletion, or modify its policy — disrupting every resource encrypted by the key.

**Remediation:** Restrict key administration statements to designated key administrator roles. Separate key usage (Encrypt/Decrypt) from key administration (Create*/Put*/Disable*/Schedule*) in the key policy. Use separate statements with distinct principals for usage and administration.

---

### CTL.KMS.POLICY.CONDITION.001

**KMS Key Policy Must Include Protective Conditions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies granting usage actions (kms:Decrypt, kms:Encrypt, kms:GenerateDataKey*, kms:ReEncrypt*) should include at least one protective condition: kms:ViaService (restricts which AWS service can use the key), kms:CallerAccount (restricts which account can call through the service), or kms:EncryptionContext (restricts the context in which the key can be used). Without conditions, any principal granted by the policy can use the key for any purpose from any service — the policy is authorization without scope.

**Remediation:** Add kms:ViaService to restrict the key to specific services (e.g., "s3.us-east-1.amazonaws.com"). Add kms:CallerAccount for cross-account scenarios. Add kms:EncryptionContext for application-level scoping. At least one condition should be present on every non-administrative usage statement.

---

### CTL.KMS.POLICY.CROSSACCOUNT.001

**KMS Key Policy Must Not Grant Broad Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; owasp_nhi: NHI6; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key policies must not grant kms:Decrypt, kms:Encrypt, kms:GenerateDataKey, or kms:* to external account principals without restricting via kms:CallerAccount, kms:ViaService, or aws:PrincipalOrgID conditions. Unlike IAM policies, the key policy is the primary authorization mechanism — IAM policies alone cannot grant KMS access unless the key policy permits it. Broad cross-account key access allows external principals to decrypt every resource encrypted by this key.

**Remediation:** Add kms:CallerAccount or aws:PrincipalOrgID conditions to cross-account statements. Restrict kms:ViaService to the specific services that require cross-account key access. Remove statements that grant broad cross-account access.

---

### CTL.KMS.POLICY.DECRYPT.BROAD.001

**KMS Key Policy Grants Decrypt to Overly Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; owasp_nhi: NHI5; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

Customer-managed KMS key policy grants kms:Decrypt to a broad principal — the account root (arn:aws:iam::ACCT:root) without IAM-side restrictions, a wildcard principal (Principal: *), or a broad IAM pattern (arn:aws:iam::ACCT:role/*). Decrypt is the most sensitive KMS operation: it reads encrypted data. Broad Decrypt access means any matching principal can decrypt any ciphertext encrypted with this key — S3 objects, RDS snapshots, EBS volumes, Lambda environment variables, Secrets Manager secrets. Distinct from CTL.KMS.POLICY.ADMIN.BROAD.001 (broad admin actions) and CTL.KMS.POLICY.001 (wildcard Principal "*" on any action): this control fires on Decrypt-specific broad scope even when admin and wildcard checks pass. Suppressed on AWS-managed keys, whose policies are AWS-controlled.

**Remediation:** Replace broad Decrypt grants with explicit role ARNs that require Decrypt. Remove arn:aws:iam::ACCT:root grants of Decrypt unless the IAM side is locked down to specific consumers. Never use Principal "*" or role-wildcard ARNs on Decrypt statements.

---

### CTL.KMS.POLICY.GHOSTREF.001

**KMS Key Policy Must Not Reference Deleted Principals**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; owasp_nhi: NHI1; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

KMS key policies must not grant cryptographic permissions to principal ARNs that don't exist in the IAM inventory. A ghost principal in a key policy inherits decrypt access to every resource encrypted by that key — S3 objects, RDS snapshots, EBS volumes, Secrets Manager secrets. KMS keys are the trust anchor for encryption. Resource-based policies (including key policies) evaluate ARN strings, not unique IDs. An attacker who creates a role matching the ghost principal's name inherits the key's full permission scope.

**Remediation:** Remove the ghost principal ARN from the key policy. Audit which resources use this key for encryption.

---

### CTL.KMS.POLICY.GRANTWITHGRANT.001

**KMS Key Allows GrantWithGrant Delegation Chains**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; owasp_nhi: NHI9; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

KMS key policy grants kms:CreateGrant AND at least one existing grant on the key includes GrantWithGrant in its operations or retiring-principal constraints — enabling a chain of delegation. Principal A creates a grant for Principal B with GrantWithGrant. Principal B creates a grant for Principal C. Principal C creates a grant for Principal D. The key's effective access becomes a chain that is invisible from the key policy alone and grows without further policy changes.

**Remediation:** Audit existing grants with aws kms list-grants --key-id KEY and retire any grant whose Operations include "GrantWithGrant" unless explicitly required. Restrict CreateGrant in the key policy to specific service-linked roles; deny the chain by forbidding GrantWithGrant in newly created grants.

---

### CTL.KMS.POLICY.NOCONTEXT.001

**KMS Key Policy Does Not Require Encryption Context**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; owasp_nhi: NHI9; pci_dss_v4.0: 3.6.1.4; soc2: CC6.1;

KMS key policy does not include a kms:EncryptionContext condition on usage statements. Without encryption context enforcement, any ciphertext encrypted with the key can be decrypted without providing context — there is no per-operation additional authentication data. Encryption context provides per-operation access control: a principal must know the context (key-value pairs) used during encryption to decrypt. Without context enforcement, Decrypt is a blanket operation on every ciphertext encrypted by the key. Narrows CTL.KMS.POLICY.CONDITION.001 to the specific case where EncryptionContext is missing even if ViaService or CallerAccount is present.

**Remediation:** Add kms:EncryptionContext or kms:EncryptionContextKeys conditions to usage statements in the key policy. Choose context keys that match how the calling application uses the key (e.g., tenant_id, object_id, application). Verify producers and consumers pass the same context values; mismatched context fails Decrypt.

---

### CTL.KMS.POLICY.NOVIASERVICE.001

**KMS Key Policy Does Not Restrict Usage to Specific AWS Services**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.8.24; nist_800_53_r5: AC-3; owasp_nhi: NHI9; pci_dss_v4.0: 3.4.1; soc2: CC6.1;

KMS key with key_usage=ENCRYPT_DECRYPT has no kms:ViaService condition on its usage statements. Without ViaService, the key is usable directly via the KMS Decrypt/Encrypt APIs — not just through AWS services (S3, RDS, EBS, Secrets Manager). A principal with kms:Decrypt can call KMS Decrypt directly with any ciphertext encrypted by the key, bypassing the calling service's access controls. ViaService restricts key usage to operations performed through specific AWS services (kms:ViaService = s3.us-east-1.amazonaws.com means the key can only be used through S3 in us-east-1). Narrows CTL.KMS.POLICY.CONDITION.001 to the specific case where ViaService is missing, even when other protective conditions (CallerAccount, EncryptionContext) are present. Only applies to ENCRYPT_DECRYPT keys; SIGN_VERIFY and GENERATE_VERIFY_MAC keys do not use ViaService.

**Remediation:** Add kms:ViaService conditions to all usage statements in the key policy. Use service-and-region-qualified values such as "s3.us-east-1.amazonaws.com" or "secretsmanager.us-east-1.amazonaws.com" rather than service-only patterns. ViaService does not apply to keys used for SIGN_VERIFY or GENERATE_VERIFY_MAC; this control only fires on ENCRYPT_DECRYPT keys.

---

### CTL.KMS.ROTATION.001

**KMS Customer-Managed Key Rotation Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: SC-12; ffiec: ISH-4; gdpr: Art.32; iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; nist_csf_2.0: PR.DS; owasp_nhi: NHI7; pci_dss_v4.0: 3.6.1; soc2: CC6.7;

Customer-created symmetric KMS keys must have automatic key rotation enabled. Key rotation limits the amount of data encrypted with a single key version, reducing the blast radius of key compromise.

**Remediation:** Enable key rotation: aws kms enable-key-rotation --key-id <key-id>

---

### CTL.KMS.SEPARATION.001

**KMS Key Admin and Key User on Same Principal**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-5; hipaa: 164.312(a)(1); nist_800_53_r5: AC-5; pci_dss_v4.0: 7.2.2; soc2: CC6.3;

Same IAM principal has both key administration permissions (kms:Create*, kms:Delete*, kms:Enable*, kms:Disable*, kms:Put*) and key usage permissions (kms:Encrypt, kms:Decrypt, kms:GenerateDataKey). No separation of duties — the principal who manages the key also uses it for cryptographic operations. A compromised principal can both modify the key's security configuration and decrypt all protected data.

**Remediation:** Separate key administration and key usage into distinct IAM principals. Key administrators should not have Encrypt, Decrypt, or GenerateDataKey permissions. Key users should not have Create*, Delete*, Enable*, Disable*, or Put* permissions.

---

### CTL.KMS.STATE.DISABLED.001

**KMS Key Is Disabled While Referenced by Active Resources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

KMS key is in Disabled state while active resources reference it for encryption — S3 buckets, RDS instances, EBS volumes, Lambda functions, DynamoDB tables, CloudWatch log groups, Secrets Manager secrets, or other dependent services. Unlike PendingDeletion (which becomes permanent after the waiting period), Disabled is reversible via EnableKey. But while disabled, every Encrypt, Decrypt, GenerateDataKey, and ReEncrypt call returns KMSInvalidStateException. The key appears in the KMS console with a valid key ID and ARN — it looks operational — but cannot perform any cryptographic operation. Resources referencing this key fail in service-specific ways: S3 GetObject returns AccessDenied (ciphertext cannot be decrypted), Lambda fails on cold start (cannot decrypt environment variables), EBS volumes cannot be attached, and RDS instances enter inaccessible state on restart. The control fires when the key is disabled AND has at least one dependent resource; re-enabling the key (EnableKey) immediately restores all operations and no data is permanently lost.

**Remediation:** Identify dependent resources with aws kms list-aliases and audit which services reference the key (S3 bucket encryption settings, RDS DescribeDBInstances, Lambda GetFunctionConfiguration, etc.). If the key should be operational, re-enable it: aws kms enable-key --key-id KEY. If the disable was intentional (e.g., emergency revocation), re-encrypt dependent resources with a different key before they fail at scale.

---

### CTL.KMS.STATE.PENDINGDELETION.001

**KMS Key Scheduled for Deletion While Referenced by Active Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12(1); hipaa: 164.312(a)(1); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12(1); pci_dss_v4.0: 3.6.1.4; soc2: A1.1;

KMS key is in PendingDeletion state and is referenced by one or more active resources — S3 buckets, RDS instances, EBS volumes, Lambda functions, DynamoDB tables, CloudWatch log groups, Secrets Manager secrets, SNS topics, SQS queues, or other services using this key for encryption. When the deletion waiting period (7-30 days) expires, the key is permanently destroyed. Every resource encrypted with the key permanently loses its encryption capability. S3 objects encrypted with this key become permanently unreadable. RDS instances encrypted with this key cannot be started after shutdown. EBS volumes cannot be attached. Lambda functions cannot decrypt environment variables. Secrets Manager secrets become unrecoverable. CancelKeyDeletion can stop the countdown — but only during the waiting window. After expiry the data is gone with no recovery. This is the most destructive ghost reference in the catalog: one state change, cascading permanent data loss across every service the key encrypts. Distinct from CTL.KMS.PENDING.DELETION.001 (fires on pending_deletion=true with no dependent-resource gate, medium severity): this control fires only when active dependents are also present, escalating to critical because the blast radius is concrete and known.

**Remediation:** Cancel the deletion immediately: aws kms cancel-key-deletion --key-id KEY. Then audit dependent resources across S3, RDS, EBS, Lambda, DynamoDB, CloudWatch Logs, Secrets Manager, SNS, and SQS to confirm the impact. If deletion is still required, re-encrypt every dependent resource with a different key BEFORE rescheduling deletion. Treat ScheduleKeyDeletion calls on keys with dependents as a pager-tier event.

---

### CTL.KMS.STATE.PENDINGIMPORT.001

**KMS Key in PendingImport State Has No Key Material**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-12; hipaa: 164.312(a)(1); nist_800_53_r5: SC-12; pci_dss_v4.0: 3.6.1; soc2: CC6.1;

KMS key was created with Origin EXTERNAL but key material has not been imported. The key exists in KMS — it has a valid key ID, ARN, and key policy — but contains no cryptographic material. Any Encrypt, Decrypt, GenerateDataKey, or ReEncrypt call fails. The key appears valid in the console (the policy is syntactically correct, the alias resolves) but is operationally empty. Resources configured to use this key for encryption fail on every cryptographic operation. Distinct from Disabled (key exists with material but is administratively turned off): PendingImport means the key has never had material to operate on. The fix is not to enable but to import key material via aws kms import-key-material with a wrapped key blob and an import token.

**Remediation:** Import key material with aws kms import-key-material. First fetch the import parameters (aws kms get-parameters-for-import with --wrapping-algorithm and --wrapping-key-spec), then wrap the raw key bytes with the returned public key, and call import-key-material with the wrapped material, the import token, and an expiration model. If the key was created in error, schedule it for deletion to remove the empty placeholder.

---

