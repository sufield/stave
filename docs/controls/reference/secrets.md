# Control Reference — SECRETS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SECRETS.ALARM.ACCESS.FAILURE.001

**No CloudWatch Alarm for GetSecretValue Failures**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.4; fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC6.1, CC7.2;

No CloudWatch alarm monitors GetSecretValue API calls that return errors (AccessDeniedException, ResourceNotFoundException, DecryptionFailureException). Access failure spikes indicate either active security events (credential scraping — an attacker testing which secrets they can read), operational failures (secret deleted or KMS key disabled — services breaking), or permission changes (IAM policy modified — legitimate services losing access). The alarm targets spikes, not individual failures, since transient denials happen during normal IAM deployments.

**Remediation:** Create a CloudTrail metric filter on eventName = GetSecretValue with errorCode present: '{ $.eventName = "GetSecretValue" && $.errorCode = "*" }' and a CloudWatch alarm with a threshold tuned to typical baseline noise (start at 5 errors per 5 minutes; tune by environment). Route to ops/security on-call. Optionally split the alarm by errorCode so AccessDeniedException (security signal), ResourceNotFoundException (operational signal), and DecryptionFailureException (KMS signal) page distinct teams.

---

### CTL.SECRETS.ALARM.ACCESS.VOLUME.001

**No CloudWatch Alarm for High-Frequency GetSecretValue Calls**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2;

No CloudWatch alarm monitors for high-frequency GetSecretValue API calls. Sudden spikes may indicate credential scraping (attacker enumerating and reading secrets), caching failure (an application retrieving the secret on every request instead of caching), or bulk credential retrieval (automation reading many secrets simultaneously). Anomaly detection or environment-tuned thresholds reduce false positives from legitimate causes (deployment rolling out, application restart).

**Remediation:** Create a CloudWatch anomaly-detection alarm on AWS/SecretsManager metric (or a CloudTrail metric filter counting GetSecretValue events). Anomaly detection adapts to the baseline call volume per environment so it avoids false positives during deployment ramps. Pair with the access-failure alarm so spikes in either dimension trigger investigation.

---

### CTL.SECRETS.ALARM.DELETE.001

**No CloudWatch Alarm for Secrets Manager DeleteSecret**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4, CP-10; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm monitors CloudTrail for DeleteSecret API calls. DeleteSecret schedules the secret for permanent deletion with a recovery window (7-30 days). Without an alarm, deletion is invisible until dependent services start failing. Companion to CTL.SECRETS.GHOST.DELETION.REFERENCED.001 (SM-1): GHOST detects state (already pending deletion); this alarm detects the event (deletion happening now), enabling immediate restore-or-confirm response.

**Remediation:** Create a CloudTrail metric filter on eventName = DeleteSecret scoped to the account, then a CloudWatch alarm with threshold 1 and a 60-second period: aws logs put-metric-filter --filter-pattern '{ $.eventName = "DeleteSecret" }' followed by aws cloudwatch put-metric-alarm. Route the alarm to an SNS topic with confirmed subscribers (ops on-call, PagerDuty) so deletions surface within minutes — enough time to RestoreSecret if the deletion was accidental.

---

### CTL.SECRETS.ALARM.POLICYCHANGE.001

**No CloudWatch Alarm for Secret Policy Changes**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: AU-6, SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2;

No CloudWatch alarm monitors CloudTrail for PutResourcePolicy or DeleteResourcePolicy API calls on secrets. Policy changes modify who can access the credential — adding new principals, adding cross-account access, removing scoping conditions. Without an alarm, secret access-control modifications are invisible until audited. Same pattern as KMS.ALARM.POLICYCHANGE and SNS.ALARM.DELETETOPIC: the access posture changes and nobody is told.

**Remediation:** Create CloudTrail metric filters on eventName = PutResourcePolicy and eventName = DeleteResourcePolicy scoped to Secrets Manager, then a CloudWatch alarm with threshold 1 over a 5-minute period. Route to security on-call so policy changes trigger immediate review against a recent snapshot of the policy. Pair with CTL.SECRETS.AUDIT.DATAEVENTS.001 so the modification event AND any subsequent reads of the affected secret are correlated in the audit trail.

---

### CTL.SECRETS.ALARM.PUTVALUE.001

**No CloudWatch Alarm for Secrets Manager PutSecretValue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: SI-4; hipaa: 164.312(a)(1); iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AU-6, SI-4, IR-4; pci_dss_v4.0: 8.2.4, 10.6; soc2: CC6.1, CC7.2, CC7.3;

No CloudWatch alarm monitors CloudTrail for PutSecretValue API calls. PutSecretValue replaces the secret's credential value — the database password, API key, or token changes. Without an alarm, credential modification is invisible. An attacker with PutSecretValue permission can replace a production database password with one they control, and every service that retrieves the secret then authenticates with the attacker's password. The alarm should ideally filter rotation-initiated PutSecretValue calls (userIdentity = rotation Lambda ARN) and alert only on manual or non-rotation modifications.

**Remediation:** Create a CloudTrail metric filter on eventName = PutSecretValue. To reduce noise from rotation-initiated calls, exclude events where userIdentity.arn matches a known rotation Lambda pattern: '{ $.eventName = "PutSecretValue" && $.userIdentity.arn != "*lambda*rotation*" }'. Wire to a CloudWatch alarm with threshold >= 1 over a 5-minute period. Route to ops on-call so manual modifications surface immediately and trigger investigation.

---

### CTL.SECRETS.ALARM.ROTATION.APPROACHING.001

**No Monitoring for Secrets Approaching Rotation Deadline**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: IA-5, SI-4; owasp_nhi: NHI7; pci_dss_v4.0: 8.2.4; soc2: CC7.2;

No monitoring tracks secrets approaching their rotation deadline — secrets where (LastRotatedDate + interval) falls within the next 7 days. Proactive control (vs. reactive ROTATION.STALE.001 which fires after rotation is already overdue): early warning lets the team verify the rotation pipeline before failure.

**Remediation:** Run a periodic Lambda or scheduled query that flags secrets where (LastRotatedDate + RotationRules.AutomaticallyAfterDays) is within 7 days of now. Publish the list to an SNS topic, ticket queue, or dashboard so the team can verify the rotation pipeline (Lambda exists, network path works, target service reachable) before rotation actually runs. Pair with CTL.SECRETS.ALARM.ROTATION.FAILURE.001 so when rotation does run, failures are caught in real time.

---

### CTL.SECRETS.ALARM.ROTATION.FAILURE.001

**No CloudWatch Alarm for Secrets Manager Rotation Failure**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: SI-4; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: IA-5, SI-4, IR-4; owasp_nhi: NHI7; pci_dss_v4.0: 8.2.4, 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm monitors the RotationFailed event (Secrets Manager → CloudWatch Events / EventBridge) or CloudTrail RotateSecret error events. When rotation fails the credential doesn't change, the next rotation attempt may also fail, and the credential becomes static while rotation appears configured. Companion to CTL.SECRETS.GHOST.ROTATIONLAMBDA.001 and CTL.SECRETS.ROTATION.STALE.001 (SM-1): the SM-1 controls detect rotation already broken (state); this alarm detects rotation failing now (event), enabling minutes-level response.

**Remediation:** Either: (a) configure an EventBridge rule on aws.secretsmanager source with detail-type "AWS API Call via CloudTrail" and event names containing rotation failure / lambda invocation errors, then route to a CloudWatch alarm via SNS notification; or (b) create a CloudTrail metric filter on eventName = RotateSecret AND errorCode is present, then a CloudWatch alarm with threshold >= 1 over a 5-minute period. Either path provides minutes-level detection. Verify the alarm action publishes to a topic with at least one confirmed subscriber (see CTL.SNS.LIFECYCLE.UNCONFIRMED.001).

---

### CTL.SECRETS.AUDIT.DATAEVENTS.001

**CloudTrail Data Events Not Enabled for Secrets Manager**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 3.2; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.1, 10.2; soc2: CC7.1, CC7.2;

CloudTrail is not configured to log Secrets Manager data events (GetSecretValue, PutSecretValue, DeleteSecret). Management events (CreateSecret, DescribeSecret, UpdateSecret) are logged by default but the most sensitive operation — GetSecretValue, the credential read — is not. For secrets containing database passwords, API keys, and service credentials, data events are the only credential-access audit trail. Higher severity than SQS/SNS data-event controls (medium): credential access is the most sensitive data access operation in AWS.

**Remediation:** Add a Secrets Manager data-event selector to a CloudTrail trail covering the account or the relevant secret ARNs: aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[{"Name":"Secrets Manager data events","FieldSelectors": [{"Field":"eventCategory","Equals":["Data"]}, {"Field":"resources.type","Equals":["AWS::SecretsManager::Secret"]}]}]'. For high-volume environments, restrict the resource ARN selector to security-sensitive secrets to bound log-volume cost. Verify the trail's S3 destination has appropriate access controls and retention.

---

### CTL.SECRETS.CROSSACCOUNT.BLASTRADIUS.001

**Secret Shared with Excessive Number of Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, SC-12; owasp_nhi: NHI6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.6;

Secret resource policy grants GetSecretValue to more than 5 external accounts. Same blast-radius pattern as CTL.KMS.CROSSACCOUNT.BLASTRADIUS.001 — each sharing account increases risk in both directions: credential compromise affects all accounts, and account compromise in any one of them provides credential access. Threshold of 5 is consistent across cross-account blast radius controls.

**Remediation:** Audit the cross-account list and remove accounts that no longer require access. For accounts that genuinely need the credential, prefer architecture changes that avoid sharing: each consuming account uses a separate secret with its own rotation, or each account authenticates through a shared service that brokers access. If broad sharing is unavoidable (a true enterprise-wide credential), pair with strict aws:PrincipalOrgID conditions (CTL.SECRETS.POLICY.CROSSACCOUNT.001), high-frequency access alarms (CTL.SECRETS.ALARM.ACCESS.VOLUME.001), and CloudTrail data events in every consuming account (CTL.SECRETS.AUDIT.DATAEVENTS.001).

---

### CTL.SECRETS.CROSSACCOUNT.NOKMS.001

**Secret Shared Cross-Account Without KMS Key Sharing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-4, SC-12; owasp_nhi: NHI6; pci_dss_v4.0: 3.4.1, 7.1; soc2: CC6.1, CC6.7;

Secret resource policy grants GetSecretValue to an external account but the secret's KMS key policy doesn't grant kms:Decrypt to that account. The external account has Secrets Manager permission to read the secret but can't decrypt it — the KMS key blocks the decryption. The access appears granted; the decryption fails. This is a cross-service permission mismatch where one service grants access and the other blocks it. Note: secrets encrypted with the AWS-managed key (aws/secretsmanager) cannot be shared cross-account at all — this control applies to CMK-encrypted secrets where cross-account access is intended.

**Remediation:** Either: (a) update the KMS key policy to grant kms:Decrypt to the external account principal that the secret policy authorizes (aws kms put-key-policy --key-id <id> --policy <policy>); or (b) if cross-account access was unintended, remove the cross-account grant from the secret resource policy. Both sides — Secrets Manager AND KMS — must consistently authorize the external account for cross- account secret reads to function.

---

### CTL.SECRETS.CROSSACCOUNT.VALUECOPIED.001

**Secret Value Duplicated in Another Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12, CM-2; owasp_nhi: NHI9; pci_dss_v4.0: 3.5, 8.2.4; soc2: CC6.1, CC6.7;

The same credential value exists in secrets in multiple accounts — the credential was copied between accounts instead of using cross-account access via resource policy. When the credential rotates in the source account, the copy is stale; authentication may fail or destination accounts may continue using the old value. Stave detects duplication via observation metadata (matching credential fingerprints, tag patterns, or scanner-flagged duplicates) rather than reading the credential value itself.

**Remediation:** Replace duplication with cross-account access. Pick one secret as authoritative, configure its resource policy to grant GetSecretValue to consuming-account principals (with aws:PrincipalOrgID — see CTL.SECRETS.POLICY.CROSSACCOUNT.001), point all consumers at the authoritative secret ARN, then delete the duplicate secrets. Audit the duplicates' rotation history before deletion to identify the rotation pipeline that needs to take over.

---

### CTL.SECRETS.GHOST.DELETION.REFERENCED.001

**Secret Scheduled for Deletion While Referenced by Active Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CP-10, IR-4; pci_dss_v4.0: 10.6, 10.7; soc2: CC6.1, CC8.1, A1.2;

Secret is scheduled for deletion and is referenced by active resources — Lambda functions (env-var ARN), ECS task definitions (valueFrom), RDS Proxy (auth configuration), or other services. When the deletion recovery window expires, the secret is permanently deleted; every service that references it then fails: Lambda cold starts can't load the credential, ECS tasks can't launch, RDS Proxy can't authenticate. Same transversal-ghost pattern as CTL.KMS.STATE.PENDINGDELETION.001 — one resource pending deletion, multiple dependent services affected.

**Remediation:** Decide intent: (a) if deletion is unintended, restore the secret immediately (aws secretsmanager restore-secret --secret-id <id>); (b) if deletion is intended, repoint every dependent resource (Lambda env vars, ECS task definitions, RDS Proxy auth config, etc.) to a replacement secret BEFORE the recovery window expires, then verify the dependent services have read the new value at least once. The minimum recovery window is 7 days — short enough that accidental deletions of widely-referenced secrets require immediate action.

---

### CTL.SECRETS.GHOST.POLICY.PRINCIPAL.001

**Secret Resource Policy References Deleted IAM Principal**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, CM-2, CM-3; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.7;

Secret resource policy grants access to an IAM principal (role or user ARN) that has been deleted. The policy statement persists. If the principal ARN is reclaimed (a new role is created with the same name), the secret policy unintentionally grants access to the new principal — the same ARN-reclamation hazard covered by CTL.SQS.GHOST.POLICY.PRINCIPAL.001 and similar SNS/IAM ghost-policy controls.

**Remediation:** Edit the secret's resource policy and remove statements that reference deleted principal ARNs (aws secretsmanager put-resource-policy --secret-id <id> --resource-policy <policy>). If the access was intentional and the principal is being recreated, confirm the recreated role assumes the same trust posture before re-adding the statement.

---

### CTL.SECRETS.GHOST.ROTATIONLAMBDA.001

**Secret Rotation Lambda Function Deleted**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: IA-5; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12, CM-2, CM-3; owasp_nhi: NHI1; pci_dss_v4.0: 3.6, 8.2.4; soc2: CC6.1, CC6.7, CC8.1;

Secret has rotation enabled but the rotation Lambda function has been deleted. The console shows rotation enabled, the rotation schedule is set, the rotation ARN is present — but the Lambda function doesn't exist. When the next rotation is triggered, the invocation fails silently. The credential never rotates. The secret appears to have active rotation; it doesn't. This is the credential rotation ghost — the most dangerous ghost reference in the Secrets Manager domain because the gap is INVISIBLE to audits: the rotation configuration shows "Enabled, 30-day interval" while the credential has been static since the Lambda was deleted.

**Remediation:** Restore the rotation Lambda by redeploying the function (the same SAR template that was originally used for the credential type — RDS-PostgreSQL-Rotation, RDS-MySQL-Rotation, etc.), then update the secret's rotation configuration to point at the new function ARN (aws secretsmanager rotate-secret --secret-id <id> --rotation-lambda-arn <arn>). Force an immediate rotation so the static credential is replaced (aws secretsmanager rotate-secret --secret-id <id> --rotate-immediately). Audit the secret's LastRotatedDate to determine how long rotation has been silently broken; rotate any other secrets that share the same rotation Lambda template.

---

### CTL.SECRETS.INTEGRATION.RDS.NOSECRET.001

**RDS Instance Master Credential Not Managed by Secrets Manager**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: IA-5; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12, SC-28; pci_dss_v4.0: 3.5, 8.2.4; soc2: CC6.1, CC6.7;

RDS instance has a master user password that is not managed by Secrets Manager. The password was set at instance creation (CloudFormation parameter, CLI, or console) and is stored somewhere outside Secrets Manager — in a CloudFormation template, deployment script, environment variable, developer's notes, or nowhere (forgotten). The password can't be rotated via Secrets Manager, can't be audited via CloudTrail data events, and can't be restricted via resource policy. Does not fire on RDS instances that use IAM database authentication (no master password in use).

**Remediation:** Migrate the master credential to Secrets Manager. Preferred: enable RDS-managed password (aws rds modify-db-instance --db-instance-identifier <id> --manage-master-user-password --master-user-secret-kms-key-id <cmk>) — RDS creates and rotates the secret automatically. Alternative: create a Secrets Manager secret manually, attach a rotation Lambda, point applications at the secret ARN, then run a one-time password reset through the new rotation pipeline. After migration, verify the secret has rotation enabled (CTL.SECRETS.ROTATION.001) and is encrypted with a customer-managed key (CTL.SECRETSMANAGER.ENCRYPT.001).

---

### CTL.SECRETS.LIFECYCLE.DELETION.MINWAIT.001

**Secret Scheduled for Deletion with Minimum Recovery Window**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CP-10; pci_dss_v4.0: 1.2; soc2: CC6.1, CC8.1, A1.2;

Secret is scheduled for deletion with the minimum 7-day recovery window. The minimum window provides the least time to discover dependent services that fail. A 30-day window provides more time for weekly batch jobs and monthly processes to fail loudly while the secret is still recoverable. Same pattern as CTL.KMS.DELETION.MINWAIT.001 — short windows force every consumer to be discovered fast or not at all.

**Remediation:** Cancel the deletion (aws secretsmanager restore-secret --secret-id <id>) and reschedule with a longer recovery window — at least 30 days (aws secretsmanager delete-secret --secret-id <id> --recovery-window-in-days 30). Audit the secret's CloudTrail history for callers that retrieve the credential infrequently (weekly batch, monthly billing, quarterly compliance jobs); a 7-day window will not surface those.

---

### CTL.SECRETS.LIFECYCLE.DORMANT.001

**Secret Not Accessed in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, IA-5, SA-22; pci_dss_v4.0: 1.2, 8.2.4, 8.5; soc2: CC6.1, CC8.1;

Secret has not been accessed (GetSecretValue) in more than 90 days. The credential exists, may still be valid at the target service (database password still works, API key still authenticates), and the secret policy still grants access — but nobody retrieves it. Dormant secrets are latent credential surfaces: the credential works but isn't used, the policy permits reading but nobody reads, and nobody monitors for anomalous access. Same 90-day dormancy threshold used across Lambda, IAM, DynamoDB, CloudFront, Route 53, KMS, SQS, and SNS controls — uniform across domains.

**Remediation:** Audit the secret's CloudTrail history (GetSecretValue events) to confirm true dormancy. If the secret is truly unused, schedule it for deletion (aws secretsmanager delete-secret --secret-id <id> --recovery-window-in-days 30) so any unrecorded consumers fail loudly during the recovery window. If the secret is held for future use, restrict the policy to a minimal principal set, attach a CloudWatch alarm on GetSecretValue access, and document the planned reactivation date.

---

### CTL.SECRETS.LIFECYCLE.NEVERACCESSED.001

**Secret Never Accessed Since Creation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2, 8.5; soc2: CC6.1, CC8.1;

Secret was created but has never been accessed (GetSecretValue never called). The credential was stored but never retrieved by any service or application. This indicates: deployment incomplete (secret created but the application was never configured to retrieve it), abandoned provisioning (infrastructure partially deployed), or manual credential storage without integration (a password saved "just in case"). Fires only after a 30-day grace period so freshly created secrets in active deployments don't trip the control prematurely.

**Remediation:** Audit the original ticket / deployment that created the secret. If the deployment is still in progress, expect the first GetSecretValue within the deployment window; otherwise schedule deletion (aws secretsmanager delete-secret --secret-id <id> --recovery-window-in-days 30). If the secret was stored manually as a contingency, document the consumer that will retrieve it and confirm a path exists for legitimate access.

---

### CTL.SECRETS.LIFECYCLE.ORPHAN.DATABASE.001

**Secret Exists for Decommissioned Database**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2, 8.5; soc2: CC6.1, CC8.1;

Secret contains credentials for a database (RDS, Aurora, Redshift, DocumentDB) that has been deleted. The database is gone; the credential authenticates to nothing. But the secret persists with its policy, encryption, and rotation configuration — credential infrastructure for infrastructure that no longer exists. If rotation is still configured, every rotation execution attempts to update a credential on a database that doesn't exist, failing silently and possibly compounding with CTL.SECRETS.GHOST.ROTATIONLAMBDA.001 patterns.

**Remediation:** Schedule the secret for deletion (aws secretsmanager delete-secret --secret-id <id> --recovery-window-in-days 30). Disable rotation first if rotation is still configured (the rotation Lambda will keep failing on every cycle until disabled). Audit the secret's principals — anyone who recently retrieved this credential is reading a value that authenticates to nothing, which is an integration bug worth surfacing.

---

### CTL.SECRETS.LIFECYCLE.PREVIOUSOLD.001

**Secret AWSPREVIOUS Version Older Than 180 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12, AU-11; pci_dss_v4.0: 3.6, 8.2.4; soc2: CC6.1, CC6.7;

Secret's AWSPREVIOUS version stage contains a credential value that is more than 180 days old. AWSPREVIOUS holds the previous credential after rotation — intended for rollback during the brief rotation window. A 180-day-old AWSPREVIOUS means: the previous credential has been accessible for 6 months, any principal with GetSecretValue and the version-stage parameter can retrieve the old credential, and the old credential may still work at the target service (not all target services invalidate old passwords after rotation).

**Remediation:** Remove the AWSPREVIOUS stage by re-rotating the secret (which advances AWSCURRENT to a new version and AWSPREVIOUS to the just-superseded one) so the stale AWSPREVIOUS is replaced. If rotation isn't producing fresh AWSPREVIOUS values, investigate the rotation pipeline (see CTL.SECRETS.ROTATION.STALE.001 and CTL.SECRETS.GHOST.ROTATIONLAMBDA.001). Verify the target service has invalidated the old credential — for RDS, confirm the previous password has been revoked at the database; for API providers, confirm the old key has been revoked at their console.

---

### CTL.SECRETS.POLICY.CROSSACCOUNT.001

**Secret Resource Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; hipaa: 164.312(a)(1); iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-4, AC-6; owasp_nhi: NHI9; pci_dss_v4.0: 7.1, 7.2, 1.2; soc2: CC6.1, CC6.6, CC6.7;

Secret resource policy grants secretsmanager:GetSecretValue to principals in external accounts without an aws:PrincipalOrgID condition. Any principal in the specified external account with the matching IAM permissions can read the credential. Distinct from CTL.SECRETSMANAGER.POLICY.PUBLIC.001 (Principal '*') and from CTL.SECRETS.CROSSACCOUNT.NOKMS.001 (cross-service KMS mismatch): this control checks the org-boundary scoping condition specifically.

**Remediation:** Add aws:PrincipalOrgID to every Statement that grants cross-account GetSecretValue (or PutSecretValue) so the grant only applies to accounts currently in the organization. If the access was unintended, remove the cross-account principal from the policy. If the access must extend outside the organization (true partner access), require a sourceVpce or sourceAccount condition pinning the access to specific infrastructure.

---

### CTL.SECRETS.POLICY.READWRITE.001

**Secret Policy Grants Both Read and Write to Same Principal**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, SC-12; owasp_nhi: NHI5; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

Secret resource policy grants both secretsmanager:GetSecretValue (read the credential) and secretsmanager:PutSecretValue (modify the credential) to the same APPLICATION principal. The principal that reads the credential can also change it — no separation between credential consumer (reads) and credential manager (writes). An attacker who compromises the principal can read the current credential AND replace it. The control excludes rotation-Lambda principals (which legitimately need PutSecretValue for rotation) by checking the policy_rotation_principals inventory.

**Remediation:** Split the principal: keep GetSecretValue on the application role and move PutSecretValue to a separate administrative or rotation role. Update the secret resource policy to reflect the split (separate Statement blocks per role). If a single principal genuinely needs both — a service that updates its own credential — document the rationale and add compensating controls (audit alarm on PutSecretValue events, MFA condition on PutSecretValue).

---

### CTL.SECRETS.POLICY.SPRAWL.001

**Secret Resource Policy Has Excessive Permission Statements**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, CM-2; owasp_nhi: NHI5, NHI9; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC8.1;

Secret resource policy has more than 10 permission statements. Same threshold and pattern as CTL.SQS.POLICY.SPRAWL.001, CTL.SNS.POLICY.SPRAWL.001, and CTL.LAMBDA.POLICY.ACCUMULATED.001 — accumulated permission statements make the credential's access surface unauditable. Sprawled secret policies often hide effectively-public access in a Statement that the team forgot was added.

**Remediation:** Audit every Statement: for each, identify the principal, actions, and conditions. Consolidate redundant Statements (multiple Statements granting the same actions to similar principals can be merged). Remove Statements for decommissioned consumers. The target is a policy where every Statement is reviewable in a single sitting and the team can articulate why each grant exists.

---

### CTL.SECRETS.REPLICA.NONCOMPLIANT.REGION.001

**Secret Replicated to Non-Compliant Region**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4; hipaa: 164.312(a)(1); iso_27001_2022: A.5.31, A.8.20; nist_800_53_r5: AC-4, SC-12, SC-28; pci_dss_v4.0: 1.2; soc2: CC6.1, CC6.7;

Secrets Manager secret is replicated to a region that doesn't comply with data residency requirements. The credential value — which may be a database password, API key, or service token — exists in a region where data processing is not authorized. Same pattern as CTL.KMS.MULTIREGION.NONCOMPLIANT.REGION.001.

**Remediation:** Remove the non-compliant replica (aws secretsmanager remove-regions-from-replication --secret-id <id> --remove-replica-regions <region>). Audit the secret's CloudTrail data events in the non-compliant region to understand whether the credential was retrieved while the replica existed — if so, treat as a data-residency incident and rotate the credential. Configure SCPs to deny secretsmanager:ReplicateSecretToRegions for non-compliant regions to prevent re-introduction.

---

### CTL.SECRETS.REPLICA.ORPHAN.001

**Secret Primary Deleted But Replicas Remain**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SC-12; pci_dss_v4.0: 1.2, 8.2.4; soc2: CC6.1, CC8.1;

Secrets Manager secret primary was deleted but replica secrets in other regions still exist. Replicas retain the credential value (frozen at the last value before deletion), the resource policy, and the encryption configuration — but no longer receive rotation updates from the primary. The replicas are orphaned credential caches with no lifecycle management.

**Remediation:** Decide intent: (a) if the deletion was intentional and no consumers in the replica region depend on the secret, schedule the replica for deletion (aws secretsmanager delete-secret --secret-id <replica-arn> --recovery-window-in-days 30); (b) if the replica region has consumers that still need the credential, promote the replica to a standalone primary and re-establish rotation (aws secretsmanager remove-regions-from-replication on the original primary first if a primary still exists). Audit the target service to confirm the credential held in the replica is still valid; if not, the orphan replica is misleading consumers with a stale value.

---

### CTL.SECRETS.REPLICA.POLICY.MISMATCH.001

**Secret Replicas Have Different Access Policies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-4, SC-12; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.6;

Secrets Manager secret is replicated to other regions but the replicas have different resource policies. The same credential value exists in multiple regions with inconsistent access control. The weakest replica policy is the effective access control for the credential — same pattern as CTL.KMS.MULTIREGION.POLICY.MISMATCH.001.

**Remediation:** Synchronize the resource policy across the primary and every replica. Either: (a) rebuild the replicas after aligning the primary's policy (aws secretsmanager replicate-secret-to-regions or delete-replica + replicate); or (b) update each replica's resource policy individually (aws secretsmanager put-resource-policy --secret-id <replica-arn> --resource-policy <policy>) so all regions enforce the same rules. Pair with CloudTrail data events (CTL.SECRETS.AUDIT.DATAEVENTS.001) in every region — a less-monitored replica region weakens the audit surface as well as the access surface.

---

### CTL.SECRETS.ROTATION.001

**Secrets Manager Secrets Must Have Automatic Rotation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** aws_security_hub: SecretsManager.1; mitre_attack: T1528; nist_800_53_r5: IA-5; owasp_nhi: NHI7;

Secrets without automatic rotation retain the same credential value indefinitely. An attacker who obtains a secret value through any means (log harvesting, memory dump, API call) has permanent access unless the secret is manually rotated. Automatic rotation limits the window of compromise — a stolen credential becomes invalid after the rotation interval.

**Remediation:** Configure automatic rotation with a Lambda rotation function: aws secretsmanager rotate-secret --secret-id <id> --rotation-lambda-arn <arn> --rotation-rules AutomaticallyAfterDays=30

---

### CTL.SECRETS.ROTATION.INTERVAL.LONG.001

**Secret Rotation Interval Exceeds 90 Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: IA-5; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 3.6, 8.2.4; soc2: CC6.1, CC6.7;

Secret rotation interval is configured to more than 90 days. Most compliance frameworks recommend or require credential rotation within 90 days — PCI-DSS recommends 90-day rotation, NIST 800-53 recommends periodic rotation, and many organizational policies require 90 days or less. A rotation interval of 365 days means the credential is the same for an entire year. Note: some credentials don't rotate frequently (long-lived API keys for stable integrations, OAuth client secrets); the finding warrants review against credential type and compliance requirements rather than a hard reject.

**Remediation:** Reduce the rotation interval to 90 days or less (aws secretsmanager rotate-secret --secret-id <id> --rotation-rules AutomaticallyAfterDays=30). For credential types that genuinely cannot rotate frequently (stable third-party API integrations, legacy OAuth client secrets), document the exception with the rationale and the compensating controls (network isolation, audit logging, least-privilege scoping).

---

### CTL.SECRETS.ROTATION.NEVER.001

**Secret Rotation Enabled But Never Successfully Completed**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: IA-5; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 3.6, 8.2.4; soc2: CC6.1, CC6.7;

Secret has rotation enabled but LastRotatedDate is null — rotation has never successfully completed. Rotation was configured (enabled, Lambda set, schedule set) but has never executed successfully. The credential is the same value that was stored when the secret was created. The configuration shows good intent ("rotation enabled, 30-day interval") but the credential has never actually been changed.

**Remediation:** Force an immediate rotation (aws secretsmanager rotate-secret --secret-id <id> --rotate-immediately) and watch the rotation Lambda's CloudWatch logs. The first rotation often fails on permission gaps (the rotation Lambda's execution role can't assume the database admin role, can't update the target service, can't write back to Secrets Manager). Fix the underlying error and re-run until LastRotatedDate is populated. Until that succeeds, the secret holds its original creation-time value.

---

### CTL.SECRETS.ROTATION.SINGLEUSER.PROD.001

**Production Secret Uses Single-User Rotation Strategy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: IA-5, CP-10; owasp_nhi: NHI7; pci_dss_v4.0: 8.2.4; soc2: CC6.1, A1.2;

Production secret uses the single-user rotation strategy instead of the multi-user (alternating-users) strategy. Single-user rotation: changes the password for the same database user. During the brief window between password change and secret update, connections using the old password fail. Multi-user rotation: alternates between two users (e.g., app_user and app_user_clone). One is always valid while the other rotates. No downtime window. Fires only on production secrets — single-user rotation on dev/test is acceptable. Same production heuristic as CTL.APIGATEWAY.EXECLOG.LEVEL.001 and CTL.ECS.EXEC.PRODUCTION.001.

**Remediation:** Switch to multi-user rotation by creating a clone database user (same permissions, different name) and updating the rotation Lambda to alternate between the two users on each cycle. The AWS-provided rotation templates (RDS-PostgreSQL-MultiUser-Rotation, RDS-MySQL-MultiUser-Rotation) implement this pattern out of the box. After the switch, rotate the secret immediately to verify the new strategy works end-to-end.

---

### CTL.SECRETS.ROTATION.STALE.001

**Secret Rotation Enabled But Last Rotation Was Long Ago**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 2.4; fedramp_moderate: IA-5; hipaa: 164.312(a)(1); iso_27001_2022: A.5.16, A.8.5; nist_800_53_r5: IA-5, SC-12; owasp_nhi: NHI7; pci_dss_v4.0: 3.6, 8.2.4; soc2: CC6.1, CC6.7;

Secret has rotation enabled but the last successful rotation was more than 2x the rotation interval ago. If the configured interval is 30 days and the last rotation was 90 days ago, rotation has been failing or stuck for 60+ days. The configuration shows "rotation enabled, 30-day interval" — the credential hasn't actually changed in 90 days. Deepens CTL.SECRETS.ROTATION.001 (which checks whether rotation is enabled) by checking whether rotation is actually WORKING.

**Remediation:** Force an immediate rotation (aws secretsmanager rotate-secret --secret-id <id> --rotate-immediately) and watch the rotation Lambda's CloudWatch logs to identify the failure mode. Common causes: rotation Lambda was deleted (see CTL.SECRETS.GHOST.ROTATIONLAMBDA.001), rotation Lambda errors on every execution (code bug, network issue, permission change), the rotation schedule was manually paused and never resumed. After the underlying issue is fixed, verify LastRotatedDate advances on the next scheduled cycle.

---

