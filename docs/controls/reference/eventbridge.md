# Control Reference — EVENTBRIDGE

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.EVENTBRIDGE.ALARM.APIDEST.5XX.001

**EventBridge API Destination Has No Alarm On 5xx Invocation Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EventBridge API destination has no CloudWatch alarm on the partner-endpoint 5xx response rate. API destinations invoke external partner endpoints; without monitoring on the response code distribution, partner-side outages surface only via downstream symptoms (the partner stops receiving events; some other system flags the gap). For destinations on critical-path partner integrations (incident notification, audit forwarding), the alarm is the early-warning that the partner is failing.

**Remediation:** Create a CloudWatch alarm on InvocationsHttpResponseCode (5xx bucket) for the destination. Threshold should be tight enough to catch partner-side incidents (e.g., >5% over a 5-minute window) and wired to SNS for on-call. For low-volume destinations, the alarm should fire on absolute count rather than rate.

---

### CTL.EVENTBRIDGE.ALARM.DEADLETTER.001

**EventBridge Rule DLQ Has No CloudWatch Alarm On Depth**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4, AU-6; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, AU-6; soc2: CC7.2, A1.2;

EventBridge rule has a DLQ configured but no CloudWatch alarm on the DLQ's ApproximateNumberOfMessagesVisible metric. Failed events route to the DLQ; without an alarm, the DLQ silently accumulates events that the rule failed to deliver. By the time operators notice the depth, the oldest failed events may have already aged out per the DLQ's retention.

**Remediation:** Create a CloudWatch alarm on the SQS DLQ's ApproximateNumberOfMessagesVisible metric in AWS/SQS namespace, scoped to the DLQ's QueueName. Threshold typically 0 over a 5-minute window — any DLQ accumulation is operationally noteworthy and warrants investigation while the DLQ retention window still has the failed events available for inspection.

---

### CTL.EVENTBRIDGE.ALARM.DELETE.001

**EventBridge Bus Has No Alarm For DeleteEventBus / DeleteRule**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.24, A.8.15, A.8.16; nist_800_53_r5: AU-6, IR-5, SI-4; pci_dss_v4.0: 10.2, 10.4; soc2: CC7.2, A1.2;

EventBridge bus has no CloudWatch alarm wired to CloudTrail for the destructive operations DeleteEventBus and DeleteRule. These are the two most-impactful API calls: DeleteEventBus removes the bus and every rule on it; DeleteRule silently ends every downstream invocation the rule was driving. Without an alarm, destructive operations land without immediate operator awareness — by the time monitoring catches the symptoms (rule no longer firing, downstream automation silent), the deletion is already minutes-to-hours old.

**Remediation:** Create a CloudTrail-derived metric filter matching eventName = DeleteEventBus or DeleteRule on the bus's region trail. Wire a CloudWatch alarm on that metric to SNS for immediate notification. Pair with an SCP denying these operations from non-admin roles for defense in depth.

---

### CTL.EVENTBRIDGE.ALARM.FAILEDINVOCATIONS.001

**EventBridge Rule Has No Alarm On FailedInvocations Metric**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4, AU-6; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, AU-6; soc2: CC7.2, A1.1;

EventBridge rule has no CloudWatch alarm on the FailedInvocations metric. Every event that fails target invocation after retries exhaust contributes to this metric. Without an alarm, transient downstream failures go unnoticed until volume crosses operationally-visible thresholds — by which time the cause may already be self-correcting and diagnostic context (target health, IAM status, network) is harder to recover.

**Remediation:** Create a CloudWatch alarm on the FailedInvocations metric in AWS/Events namespace, scoped to the specific RuleName. Threshold should be tighter than the rule's expected background failure rate (often 0 over a 5-minute window for low-volume rules). Wire to SNS for notification.

---

### CTL.EVENTBRIDGE.ALARM.PIPE.FAILED.001

**EventBridge Pipe Has No Alarm On ExecutionFailed Or State Transitions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, AU-6; soc2: CC7.2, A1.2;

EventBridge Pipe has no CloudWatch alarm on ExecutionFailed / ExecutionThrottled metrics, and no alarm on pipe state-machine transitions to CREATE_FAILED / UPDATE_FAILED / STOPPED. Pipes are long-running data-plane components; without alarms, state failures (which leave the pipe non-functional but its source bindings active) go unnoticed for weeks.

**Remediation:** Create CloudWatch alarms on (a) Pipe ExecutionFailed and ExecutionThrottled metrics in AWS/Pipes namespace, scoped to the PipeName, and (b) an EventBridge rule + alarm chain that watches CloudTrail for Pipe state transitions to CREATE_FAILED / UPDATE_FAILED / STOPPED. Pair with a DLQ so failed records have a preservation surface.

---

### CTL.EVENTBRIDGE.ALARM.POLICYCHANGE.001

**EventBridge Bus Has No Alarm For Resource-Policy Changes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SI-4; iso_27001_2022: A.5.15, A.5.24, A.8.15; nist_800_53_r5: AC-3, AU-6, SI-4; pci_dss_v4.0: 7.2, 10.2; soc2: CC6.1, CC7.2;

EventBridge bus has no CloudWatch alarm covering PutPermission / PutResourcePolicy API events. These operations expand the bus's access policy — the typical failure mode is "an integration rollout temporarily added a broad principal grant and forgot to remove it" or "a cross-account configuration accidentally permitted external publishers." Without an alarm, expanded policy persists until the next manual policy review.

**Remediation:** Create a CloudTrail metric filter matching eventName = PutPermission OR PutResourcePolicy on the bus's region trail. Wire a CloudWatch alarm on that metric to SNS. Tag the alarm so on-call understands the alert means "bus access policy expanded — review immediately for intended principal scope."

---

### CTL.EVENTBRIDGE.ALARM.REMOVETARGETS.001

**EventBridge Has No Alarm For RemoveTargets / DisableRule**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-6, SI-4; iso_27001_2022: A.5.24, A.8.15, A.8.16; nist_800_53_r5: AU-6, IR-5, SI-4; pci_dss_v4.0: 10.2, 10.4; soc2: CC7.2, A1.2;

EventBridge has no CloudWatch alarm covering RemoveTargets and DisableRule API events. RemoveTargets silently disables a rule's downstream invocations while leaving the rule in place; DisableRule pauses rule firing entirely. Both are reachable from broad PutTargets / PutRule grants (see EB-2's POLICY.REMOVETARGETS.BROAD) and produce silent-rule-failure outcomes (see EB-3's RULE.NOTARGETS). Alarm coverage on these calls is the detection layer for the silent-disablement pattern.

**Remediation:** Create a CloudTrail metric filter matching eventName = RemoveTargets OR DisableRule on the bus's region trail. Wire a CloudWatch alarm on that metric to SNS. RemoveTargets is the silent-disable pattern — the rule remains visible, targets are stripped — and benefits most from immediate alert.

---

### CTL.EVENTBRIDGE.ALARM.SCHEDULER.DROPPED.001

**EventBridge Scheduler Has No Alarm On InvocationDroppedCount**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, AU-6; soc2: CC7.2, A1.2;

EventBridge Scheduler schedule has no CloudWatch alarm on the InvocationDroppedCount metric (failed invocations after retry exhaustion that were dropped because there was no DLQ or the DLQ was unavailable). Combined with EB-5's SCHEDULER.NODLQ.001, this is the detection layer: the configuration control catches "DLQ missing"; this control catches "alarm on the silent-drop counter missing", so drops have no preservation surface AND no alert.

**Remediation:** Create a CloudWatch alarm on InvocationDroppedCount and TargetErrorThrottledCount metrics in AWS/Scheduler namespace, scoped to the ScheduleName. Threshold of 0 over a 5-minute window for most schedules; tighter thresholds for high-volume schedules. Pair with a DLQ so drops are preserved.

---

### CTL.EVENTBRIDGE.ALARM.THROTTLED.001

**EventBridge Rule Has No Alarm On ThrottledRules Metric**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; soc2: CC7.2, A1.1;

EventBridge rule has no CloudWatch alarm on the ThrottledRules metric. EventBridge throttles rules when they hit per-rule or per-account quotas; throttled events are dropped (or sent to DLQ if configured). Without an alarm, throttling goes unnoticed and the operator only notices via downstream gaps. For high-volume rules, throttling is a real production failure mode that compounds whenever upstream events spike.

**Remediation:** Create a CloudWatch alarm on the ThrottledRules metric in AWS/Events namespace. For most rules the threshold should be 0 (any throttling is operationally noteworthy); for high-volume rules near per-rule quotas, set a tighter threshold matching expected steady-state volume.

---

### CTL.EVENTBRIDGE.APIDEST.GHOST.CONNECTION.001

**EventBridge API Destination References Deleted Connection**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

EventBridge API destination's ConnectionArn points to a Connection that has been deleted. Every invocation through the destination fails because the connection — and therefore the auth credentials — no longer resolves. Same ghost- reference pattern as other EB ghost-target controls; specific to the API-destination → connection link.

**Remediation:** Recreate the Connection at the original ARN, repoint the destination to a live Connection (UpdateApiDestination), or delete the destination if the partner integration is decommissioned.

---

### CTL.EVENTBRIDGE.APIDEST.HTTP.001

**EventBridge API Destination Targets HTTP Endpoint**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-13; iso_27001_2022: A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

EventBridge API destination has an InvocationEndpoint that uses the http:// scheme rather than https://. Events delivered to the destination — which often carry account-scoped IDs, payload templates with detail fields, and partner-API request bodies — leave AWS in plaintext. The destination's auth credentials, even when stored in Secrets Manager, are also transmitted on the wire to authenticate the request.

**Remediation:** Update the InvocationEndpoint to use https://. If the partner endpoint genuinely doesn't support TLS, escalate to the partner — there's no acceptable production posture for HTTP-only event delivery.

---

### CTL.EVENTBRIDGE.APIDEST.RATELIMIT.UNSET.001

**EventBridge API Destination Has No Invocation Rate Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6; nist_800_53_r5: SC-5; soc2: A1.1;

EventBridge API destination has InvocationRateLimitPerSecond unset (no upper bound on requests per second to the partner endpoint). Rule fan-out can DDoS the partner if a bus event triggers a rule with many records or a high-volume source. Rate-limiting at the destination level — independent of the partner's own throttling — is AWS's documented protection against this case.

**Remediation:** Set InvocationRateLimitPerSecond to a value matching the partner's documented rate limit, with safety margin (typically 50-80% of the partner's published limit). EventBridge buffers excess events at the bus and respects the configured rate; without the cap, every event flows immediately to the partner.

---

### CTL.EVENTBRIDGE.ARCHIVE.CROSSREGION.UNENCRYPTED.001

**EventBridge Archive Cross-Region Copy Lacks Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-28; iso_27001_2022: A.5.17, A.8.20, A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.6;

EventBridge archive replicates to a second region (cross- region archive copy) without encryption configured on the destination. Cross-region archive copies are operationally useful for DR and compliance retention in geographically separated regions, but without explicit destination encryption the archive's encryption posture degrades on the copy: even if the source archive uses CMK, the copy may fall back to AWS-managed keys in the destination region. The audit boundary the source archive established is broken at the region boundary.

**Remediation:** Configure the destination region's archive copy with a CMK in that region. Cross-region KMS access requires either multi-region keys (recommended) or per-region CMKs with aligned key policies. Update the cross-region replication target accordingly.

---

### CTL.EVENTBRIDGE.ARCHIVE.DEFAULTBUS.001

**EventBridge Archive Targets The Default Bus**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20, A.8.24; nist_800_53_r5: AC-3, AC-4, AC-21, SC-7; soc2: CC6.1, CC6.6, P4.0;

EventBridge archive is attached to the account's default bus. The default bus carries every AWS service event in the account plus any application events any team has pushed to the default bus rather than to a dedicated bus. An archive on the default bus captures all of it — cross-tenant data mixing, sensitive service events (Health, GuardDuty, Config), and any application data flowing through the default bus all land in one archive. Replay then re-injects all of that, creating a cross-tenant exfiltration vector.

**Remediation:** Create a dedicated custom bus for the application that needs archiving (CreateEventBus). Move producers and rules onto the custom bus. Delete the default-bus archive and create a new archive on the custom bus with a narrower filter pattern. The default bus should not be archived at all in multi-tenant accounts; AWS service events captured for audit purposes belong in a dedicated audit bus or in CloudTrail.

---

### CTL.EVENTBRIDGE.ARCHIVE.NOCMK.001

**EventBridge Archive Encrypted With AWS-Managed Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-28; iso_27001_2022: A.5.17, A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1;

EventBridge archive uses AWS-managed key encryption (aws/events) rather than a customer-managed KMS key. Archive payloads include every event matched by the archive's filter pattern — typically spanning months of audit-grade traffic. AWS-managed-key encryption can't be revoked, audited at the key level, or rotated on the org's schedule. For archives serving compliance retention or incident-investigation roles, CMK is the required posture.

**Remediation:** Create a CMK with a key policy allowing events.amazonaws.com to encrypt/decrypt archive payloads, scoped by aws:SourceAccount. Update the archive's KmsKeyId via UpdateArchive (or recreate the archive — the KmsKeyIdentifier can only be set at create time on some CFN paths, so a recreate may be required). Existing archived events under the AWS-managed key remain readable until the archive's retention expires.

---

### CTL.EVENTBRIDGE.ARCHIVE.NOFILTER.001

**EventBridge Archive Has No Event-Pattern Filter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SC-5; soc2: CC6.1, CC8.1;

EventBridge archive has no EventPattern set — the archive captures every event the bus delivers. For high-throughput buses, the archive accumulates orders of magnitude more data than it needs to. Storage cost compounds, retention-window privacy exposure compounds, and replay (when used) re-injects noise alongside the events the operator actually wanted to replay. AWS designed archive filtering specifically so the archive can be scoped to the audit-relevant subset.

**Remediation:** Set EventPattern to scope the archive to the audit-relevant event subset. For audit archives, typically filter by detail-type / source matching the operational events worth preserving. For incident-investigation archives, scope to the security-relevant sources (aws.guardduty, aws.health, aws.config). A catch-all archive only makes sense if the bus itself is single-purpose; on a shared bus, filter explicitly.

---

### CTL.EVENTBRIDGE.ARCHIVE.RETENTION.LONG.001

**EventBridge Archive Retention Exceeds Documented Compliance Window**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11, SI-12; gdpr: Art-5(1)(e); hipaa: 164.530(j); iso_27001_2022: A.5.33, A.8.10; nist_800_53_r5: AU-11, SI-12; soc2: CC6.5, P4.0;

EventBridge archive retention is set to indefinite (RetentionDays unset / 0) or to a value greater than 730 days (2 years) without documented compliance rationale. Long-retained archives accumulate PII, audit-grade event detail, and stale operational metadata. GDPR Article 5(1)(e) and HIPAA's minimum-necessary standard both push toward "no longer than necessary" retention; long defaults without explicit rationale create regulatory exposure with no operational benefit.

**Remediation:** Decide the archive's intended use. For incident-investigation archives, 90-180 days is typical. For compliance-required retention (HIPAA 6yr, PCI 1yr, SOX 7yr), tag the archive with the framework + retention rationale (Compliance=HIPAA, RetentionRationale=164.530(j)). Then set RetentionDays explicitly to match — not "indefinite as a default".

---

### CTL.EVENTBRIDGE.ARCHIVE.RETENTION.SHORT.001

**EventBridge Archive Retention Shorter Than Incident Investigation Window**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11, IR-4; iso_27001_2022: A.5.24, A.8.16; nist_800_53_r5: AU-11, IR-4; soc2: CC7.2, CC7.3;

EventBridge archive retention is below 30 days. Incident investigations routinely look back 30-90 days for chains of causation; an archive with retention shorter than the typical investigation window provides little of its intended value. Common cause: RetentionDays defaulted to 7 by an example template and never reviewed against operational needs.

**Remediation:** Set RetentionDays to at least 30, and align with the archive's operational role: incident-investigation needs typically want 90+, audit retention is framework-specific. Pair with a tag (Purpose=incident-investigation / audit-retention) so the choice is explicit.

---

### CTL.EVENTBRIDGE.AUDIT.DATAEVENTS.001

**EventBridge PutEvents Data Events Not Logged In CloudTrail**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-2, AU-3; iso_27001_2022: A.5.28, A.8.15; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.2; soc2: CC7.2;

EventBridge management events (PutRule, DeleteEventBus, PutPermission, etc.) are logged in CloudTrail by default, but data-tier events (PutEvents — every PutEvents call into a bus) are NOT logged unless explicitly enabled via CloudTrail event selectors. Without data-event logging, there's no reconstruction path for "who put which event into the bus" — only the management-plane API calls are auditable. For buses carrying audit-grade event traffic, this is a forensic gap.

**Remediation:** Enable CloudTrail data events for EventBridge: in the trail's event selectors, add a DataResource for the AWS::Events::EventBus type (with the specific bus ARN or "All" for organization-wide capture). Ensure the trail destination is sufficient for the volume — PutEvents on a busy bus generates significant CloudTrail data.

---

### CTL.EVENTBRIDGE.BUS.CROSSACCOUNT.001

**EventBridge Event Bus Must Not Allow Unrestricted Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge event bus resource policies must not grant event delivery to external accounts without conditions. Cross-account event injection allows external principals to trigger downstream service actions.

**Remediation:** Restrict cross-account access with conditions or specific account IDs.

---

### CTL.EVENTBRIDGE.BUS.PUBLIC.001

**EventBridge Event Bus Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge event bus resource policies must not grant public access (Principal "*"). Public access allows anyone to publish events that trigger downstream Lambda, Step Functions, or other targets.

**Remediation:** Restrict the resource policy to specific accounts or principals.

---

### CTL.EVENTBRIDGE.COMPLIANCE.NOTAGS.001

**EventBridge Bus Has No Data Classification Tags**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CA-7, CM-8; iso_27001_2022: A.5.9, A.5.12; nist_800_53_r5: CA-7, CM-8; soc2: CC6.1, CC6.5;

EventBridge bus has no data-classification or compliance- scope tags. Without tags, automated compliance reports (HIPAA / PCI / SOC2) can't determine whether the bus carries regulated data, encryption / retention / audit controls applied appropriately, or who owns the bus. Same governance-tag pattern as similar tagless-resource controls across other services.

**Remediation:** Tag the bus with at least DataClassification (Public / Internal / Confidential / Restricted) and Owner (team or individual). For buses subject to specific compliance frameworks, also tag Compliance (HIPAA / PCI / SOC2 / GDPR) so compliance-scope reports can scope correctly.

---

### CTL.EVENTBRIDGE.CONNECTION.APIKEY.PLAINTEXT.001

**EventBridge Connection API Key Embedded In Definition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.17, A.8.5, A.8.24; nist_800_53_r5: AC-3, IA-5, SC-28; pci_dss_v4.0: 3.5, 8.3; soc2: CC6.1, CC6.3;

EventBridge Connection uses API_KEY authentication with the key value embedded directly in the connection definition rather than referenced from Secrets Manager. The key is visible to any principal with events:DescribeConnection. Same plaintext-credential pattern as BASIC auth but for API-key-style integrations (most third-party SaaS APIs use this auth style).

**Remediation:** Move the API key to AWS Secrets Manager. Update the connection's ApiKeyAuthParameters to use a SECRETS_MANAGER reference. Configure the secret for automatic rotation where the partner API supports it.

---

### CTL.EVENTBRIDGE.CONNECTION.BASIC.PLAINTEXT.001

**EventBridge Connection Stores BASIC Auth Credentials In Plaintext**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.17, A.8.5, A.8.24; nist_800_53_r5: AC-3, IA-5, SC-28; pci_dss_v4.0: 3.5, 8.3; soc2: CC6.1, CC6.3;

EventBridge Connection uses BASIC authentication with username and password supplied directly in the connection definition rather than via a Secrets Manager reference. The credentials are visible to any principal with events:DescribeConnection, CloudTrail logs them in PutConnection / UpdateConnection events, and rotation requires editing the connection definition rather than rotating a secret.

**Remediation:** Move credentials to AWS Secrets Manager. Update the connection's BasicAuthParameters to use a SECRETS_MANAGER reference. Configure the secret for automatic rotation and grant the connection's role secretsmanager:GetSecretValue on the secret ARN only.

---

### CTL.EVENTBRIDGE.CONNECTION.DEAUTHORIZED.001

**EventBridge Connection In DEAUTHORIZED State With Active Destinations**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, A1.2;

EventBridge Connection is in DEAUTHORIZED state but API destinations referencing it are still configured to receive events. DEAUTHORIZED indicates the connection's credentials have been invalidated (often after a partner-side credential rotation that wasn't reflected in Secrets Manager); every destination invocation through the connection fails authentication. The destinations look configured; invocations silently fail.

**Remediation:** Identify the cause via DescribeConnection's StateReason. Common causes: secret rotation that broke the partner-side credential, OAuth refresh-token expiry, partner API revoked the credential. Either re-authorize via UpdateConnection with current credentials, delete the connection plus dependent destinations, or pause the rules invoking the destinations until the connection is restored.

---

### CTL.EVENTBRIDGE.CONNECTION.GHOST.SECRET.001

**EventBridge Connection References Deleted Secrets Manager Secret**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, IA-5; iso_27001_2022: A.5.16, A.5.17, A.8.32; nist_800_53_r5: CM-2, CM-3, IA-5; soc2: CC6.1, CC8.1, CC7.4;

EventBridge Connection's auth parameters reference an AWS Secrets Manager secret that no longer exists. Every API destination invocation through this connection requires the connection's auth credentials, which are fetched from the named secret — when the secret is gone, the destination invocation fails authentication. Same ghost-reference pattern as the other EB ghost-target controls but on the auth surface.

**Remediation:** Recreate the secret at the original ARN with the current valid credentials, repoint the connection to a live secret via UpdateConnection, or delete the connection and the associated API destinations if the integration is being decommissioned. Audit which API destinations depend on this connection (events:DescribeApiDestination, filter by ConnectionArn) and consider their failure mode while the secret is missing.

---

### CTL.EVENTBRIDGE.CONNECTION.OAUTH.PLAINTEXT.001

**EventBridge Connection OAuth Client Secret Embedded In Definition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.17, A.8.5, A.8.24; nist_800_53_r5: AC-3, IA-5, SC-28; pci_dss_v4.0: 3.5, 8.3; soc2: CC6.1, CC6.3;

EventBridge Connection uses OAUTH_CLIENT_CREDENTIALS authentication with the ClientSecret embedded directly in the connection definition rather than referenced from Secrets Manager. The secret is visible to any principal with events:DescribeConnection. OAuth client secrets typically authorize the application's full API scope at the partner; exposure compromises every principal that obtains tokens through this client.

**Remediation:** Move the ClientSecret to AWS Secrets Manager. Update the connection's OAuthParameters.ClientParameters to use a SECRETS_MANAGER reference. The OAuth refresh-token rotation cadence is governed by the partner's authorization server; document the rotation expectations in the connection's description so future operators understand the rotation contract.

---

### CTL.EVENTBRIDGE.DISCOVERER.GHOST.BUS.001

**EventBridge Schema Discoverer References Deleted Bus**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC6.1, CC8.1, CC7.4;

EventBridge schema discoverer's SourceArn points to an event bus that has been deleted. The discoverer is in STARTED state but observes nothing — every API call against it succeeds but discovers no new schemas. Same ghost-reference pattern as the rule-target ghosts, on the schema-discoverer surface.

**Remediation:** Either delete the discoverer (DeleteDiscoverer) or update its SourceArn to point at a live bus. Discoverers cost per-event-observed; a discoverer pointed at a deleted bus accumulates IAM-audit surface without producing schemas.

---

### CTL.EVENTBRIDGE.DISCOVERER.SENSITIVE.BUS.001

**EventBridge Schema Discoverer Indexes A Sensitive Event Bus**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SI-12; iso_27001_2022: A.5.15, A.8.16, A.8.24; nist_800_53_r5: AC-3, AC-21, SI-12; soc2: CC6.1, CC6.6, P4.0;

EventBridge schema discoverer is enabled on a bus whose source filter or known traffic includes sensitive event sources (aws.guardduty, aws.health, aws.config, aws.iam, application events with PII detail fields). The discoverer infers schemas from event bodies — every shape it sees becomes a registered schema definition, including PII field names, account-scoped IDs, and finding-detail layouts. The schema registry then carries those shapes for anyone with DescribeSchema access to read.

**Remediation:** Either move the discoverer to a non-sensitive analytics bus, or set the discoverer state to STOPPED if the discovery sprint is complete. If the schemas of sensitive sources must be discovered for downstream codegen, restrict DescribeSchema access via a custom registry — don't use the default registry.

---

### CTL.EVENTBRIDGE.FEDERATION.GHOST.SPOKE.001

**EventBridge Federation Rule Targets Deleted Spoke Bus**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

Hub-and-spoke EventBridge federation: a rule on the hub bus forwards events to a spoke bus that has been deleted. The rule pattern continues to match upstream events; every match attempts cross-account/cross-region delivery to a missing destination, which fails. Same ghost-target pattern as the EB-1 controls but specific to federation.

**Remediation:** Recreate the spoke bus at the original ARN, repoint the federation rule target to a live bus, or remove the federation rule.

---

### CTL.EVENTBRIDGE.FEDERATION.NOSOURCEACCOUNT.001

**EventBridge Hub Bus Accepts Federated Events Without sourceAccount Validation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

Hub-and-spoke EventBridge federation: hub bus's resource policy grants events:PutEvents to spoke account principals without an aws:SourceAccount or aws:PrincipalOrgID condition narrowing which spokes may publish. Any account that's been granted federation access can spoof events as if they came from any spoke account in the topology — confused-deputy at the federation layer.

**Remediation:** Add aws:SourceAccount or aws:PrincipalOrgID conditions to every Statement granting cross-account PutEvents on the hub. Pin to the explicit list of authorized spoke accounts.

---

### CTL.EVENTBRIDGE.GHOST.RULE.DLQ.001

**EventBridge Rule Dead-Letter Queue Target Does Not Exist**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-11; soc2: CC6.1, CC8.1, A1.2;

An EventBridge rule has a dead-letter queue configured but the DLQ ARN names an SQS queue that has been deleted. Failed invocations meant to be preserved in the DLQ for investigation are silently lost. This is the rule-side analog of CTL.SQS.GHOST.DLQ.001 (queue-side DLQ ghost) and the most dangerous SQS-coupling failure for EventBridge: when the rule target itself fails, the DLQ is the safety net; when the DLQ is ghosted, the safety net is gone.

**Remediation:** Recreate the SQS DLQ at the original ARN, repoint the rule's DLQ to a live queue (aws events put-rule / put-targets with --dead-letter-config), or remove the DLQ if the workload no longer needs it. Pair with a CloudWatch alarm on DeadLetterInvocations so future deletions surface immediately.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.BATCH.001

**EventBridge Rule Targets Deleted Batch Job Queue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is an AWS Batch job queue ARN that no longer exists. Each matching event attempts SubmitJob against a missing queue — the API rejects it. Events route to DLQ if configured or are discarded. AWS Batch is typically used for long-running compute and ML pipelines triggered by events; a ghost Batch target silently halts those pipelines.

**Remediation:** Recreate the Batch job queue at the original ARN, repoint the target to a live queue, or remove the target. Verify the associated compute environment also still exists — a deleted compute environment will silently fail downstream of a live queue with the same symptom.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.CODEPIPELINE.001

**EventBridge Rule Targets Deleted CodePipeline Pipeline**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-5; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CM-5; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is a CodePipeline pipeline ARN that no longer exists. The rule pattern often fires on commit-push or upstream artifact-changed events; a ghost CodePipeline target means CI/CD invocations from those events silently fail. Releases and deployments triggered by upstream changes stop happening without anyone noticing until a stakeholder checks for the missing deploy.

**Remediation:** Recreate the pipeline at the original ARN, repoint the rule target to a live pipeline, or remove the target. If the pipeline was renamed, update the rule target ARN to match the new name.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.ECS.001

**EventBridge Rule Targets Deleted ECS Cluster Or Task Definition**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is an ECS cluster ARN or task definition revision that no longer exists. Each matching event attempts to RunTask against a missing resource — the API returns ClusterNotFoundException or InvalidParameterException. The event is sent to DLQ if configured or discarded. ECS rule targets often drive scheduled batch jobs, recurring data pipelines, and event- driven processing — a ghost ECS target silently halts that work.

**Remediation:** Recreate the cluster, repoint the target to a live cluster / task-definition family, or remove the target. If a task definition revision was deprecated, update the target to use the new revision (or pin to the family rather than a specific revision so future revisions are picked up automatically).

---

### CTL.EVENTBRIDGE.GHOST.TARGET.FIREHOSE.001

**EventBridge Rule Targets Deleted Firehose Delivery Stream**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, AU-9; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, AU-9; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is a Kinesis Data Firehose delivery stream ARN that no longer exists. Firehose targets are typically on the path to durable storage (S3 archive, Redshift, OpenSearch), so a ghost Firehose target means events that should have landed in long-term storage are silently dropped. Same ghost-reference pattern as the Kinesis stream variant, but the failure tail is more severe because Firehose feeds compliance-grade archives.

**Remediation:** Recreate the Firehose at the original ARN, repoint the rule target to a live delivery stream, or remove the target. If the delivery stream was decommissioned, also delete any S3/Redshift archive expectations downstream that depended on it.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.IAMROLE.001

**EventBridge Rule Target Invocation Role Was Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2, CM-3; soc2: CC6.1, CC6.3, CC8.1;

An EventBridge rule references an IAM role for target invocation, but the role ARN no longer exists. The rule pattern continues to match events; each match attempts AssumeRole on the missing role and fails. Events route to DLQ or are discarded. This is the identity-side of the ghost-target moat — the target resource may still exist, but the rule cannot reach it because the assumed role was deleted. Same silent failure pattern but the failure point is the IAM role rather than the downstream service.

**Remediation:** Recreate the IAM role at the original ARN (preserve the name and trust policy to avoid breaking other rules using it), update the rule target to use a live role, or remove the target. Verify the role's trust policy permits events.amazonaws.com to assume it.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.KINESIS.001

**EventBridge Rule Targets Deleted Kinesis Stream**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is a Kinesis data stream ARN that no longer exists. The rule continues to match events; every matching event attempts to PutRecords into a stream that has been deleted. The PutRecords call fails with ResourceNotFoundException; after the rule's retry budget exhausts, the event is either redirected to the rule's DLQ (if configured) or silently discarded. Same silent failure pattern as CTL.EVENTBRIDGE.TARGET.GHOST.001 but specific to Kinesis stream targets — important because Kinesis streams are often the bridge between EB events and downstream analytics, and a ghost stream silently breaks the analytics pipeline.

**Remediation:** Recreate the Kinesis stream at the original ARN, repoint the rule target to a live stream (aws events put-targets --rule <name> --targets ...), or remove the target. If the stream was decommissioned intentionally, also remove the EventBridge invocation role's kinesis:PutRecord/PutRecords permission for the deleted ARN. Configure a rule DLQ so future deletions surface as DeadLetterInvocations metric spikes.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.LOGGROUP.001

**EventBridge Rule Targets Deleted CloudWatch Log Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-3, AU-9, CM-2; iso_27001_2022: A.5.16, A.8.15, A.8.32; nist_800_53_r5: AU-3, AU-9, CM-2; soc2: CC6.1, CC7.2, CC7.4;

An EventBridge rule's target is a CloudWatch Log Group ARN that no longer exists. Log Group targets are typically used to capture control-plane events (Config rule changes, CloudTrail events, GuardDuty findings) into a forensic log stream; a ghost Log Group target means those forensic records are dropped. The rule fires; the audit trail is incomplete.

**Remediation:** Recreate the Log Group at the original ARN (preserve the name to avoid breaking consumers), repoint the target to a live Log Group, or remove the target. If the Log Group was decommissioned intentionally, also delete subscription filters / metric filters that depended on it.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.S3.001

**EventBridge Rule Targets Deleted S3 Bucket**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AU-2, SI-4; soc2: CC6.1, CC7.1;

An EventBridge rule's target is an S3 bucket ARN that no longer exists. Events matching the rule pattern are routed but delivery fails silently. If the bucket name is re-registered under a different account, events resume delivery to attacker-controlled storage — a bucket-hijacking vector.

**Remediation:** Update the rule target to an existing S3 bucket: aws events put-targets --rule <rule> --targets Id=<id>,Arn=arn:aws:s3:::<bucket>. Verify event delivery by triggering a matching event.

---

### CTL.EVENTBRIDGE.GHOST.TARGET.SAGEMAKER.001

**EventBridge Rule Targets Deleted SageMaker Pipeline**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC8.1, CC7.4;

An EventBridge rule's target is a SageMaker pipeline ARN that no longer exists. SageMaker pipelines are typically triggered by data arrival events (S3 ObjectCreated) or scheduled retraining; a ghost SageMaker target means model retraining and ML inference pipelines silently stop executing on schedule. Model freshness regresses without anyone noticing until output drift becomes visible.

**Remediation:** Recreate the SageMaker pipeline at the original ARN, repoint the target to a live pipeline, or remove the target. If the pipeline was renamed/migrated, update the rule target ARN to match.

---

### CTL.EVENTBRIDGE.GLOBALENDPOINT.NOHEALTHCHECK.001

**EventBridge Global Endpoint Has No Health Check Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: CP-7, CP-9; soc2: A1.1, CC7.2;

EventBridge Global Endpoint is configured without a Route 53 health check on the primary region. Failover from primary to secondary depends on a health check signaling primary is unhealthy; without one, failover never triggers — when the primary region's bus is unhealthy, events still route there and fail. The Global Endpoint then provides no DR value.

**Remediation:** Create a Route 53 health check that monitors the primary region's bus health. Wire it to the Global Endpoint's routing-config / failover-config. The health check is the signal that triggers failover; without it the Global Endpoint never switches to the secondary.

---

### CTL.EVENTBRIDGE.GLOBALENDPOINT.SECONDARY.NORULES.001

**EventBridge Global Endpoint Secondary Bus Has No Rules**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-7, CP-10; iso_27001_2022: A.5.30, A.8.13, A.8.16; nist_800_53_r5: CP-7, CP-9, CP-10; soc2: A1.1, A1.2, CC7.2;

EventBridge Global Endpoint has a secondary region's bus configured for failover, but that bus has zero rules attached. When failover fires, events arrive at the secondary bus and are silently discarded — no rule matches, no target invokes. The Global Endpoint reports a successful failover; downstream automation still doesn't run during the primary-region incident.

**Remediation:** Replicate the primary region's rule set to the secondary region. The rule definitions, target ARNs (region- appropriate), invocation roles, and DLQs all need to exist in the secondary region. AWS doesn't auto-replicate rules across Global Endpoint members — this is operator responsibility.

---

### CTL.EVENTBRIDGE.LIFECYCLE.BUS.DORMANT.001

**EventBridge Custom Bus Has No Rules And No Recent Invocations**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EventBridge custom bus has zero rules attached AND zero PutEvents in the last 90 days. The bus exists but neither produces nor consumes events. It's typically a leftover from an experiment, a partial decommissioning, or a refactor that moved rules elsewhere without removing the empty bus. Long-dormant buses contribute to inventory clutter and may carry stale resource-policy grants.

**Remediation:** Delete the bus via DeleteEventBus, OR if the bus is deliberately maintained (waiting for an integration rollout, etc.), tag it with Lifecycle=Reserved and DocumentedReason. Long-dormant custom buses accumulate audit surface for no operational benefit.

---

### CTL.EVENTBRIDGE.PARTNER.DEFAULTBUS.001

**EventBridge Partner Event Source Routes To Default Bus**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; soc2: CC6.1, CC6.6;

EventBridge partner event source (Datadog, PagerDuty, Auth0, etc.) is associated with the account's default bus rather than a dedicated partner bus. Partner events mix with AWS service events and any other application traffic on the default bus. Cross-tenant rules can consume partner events; archive on the default bus captures partner payloads alongside org-internal events; per-partner isolation is impossible after association.

**Remediation:** Create a dedicated partner bus (CreateEventBus with EventSourceName matching the partner). Move the partner source association to the dedicated bus. The default bus should never carry partner events — partner data and AWS service events have different access-control, archive-retention, and audit profiles.

---

### CTL.EVENTBRIDGE.PARTNER.ORPHAN.001

**EventBridge Partner Event Source Has No Rules Consuming It**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EventBridge partner event source is associated with a bus but no rules on that bus match the partner's source pattern — no rule consumes the partner events. The partner continues to publish; events accumulate (in archive if configured) or are dropped; no automation runs on them. Common cause: integration was decommissioned but the partner source was not deleted, or the rules consuming the partner were deleted while the source association remained.

**Remediation:** Decide whether the partner integration is decommissioned (delete the partner event source via DeleteEventSource — this also stops the partner from billing for events delivered to AWS) or whether rules are missing (recreate the consuming rules). Long-lived orphan partner sources accumulate cost (partner-side per-event charges) and inventory clutter.

---

### CTL.EVENTBRIDGE.PARTNER.PENDING.STALE.001

**EventBridge Partner Source In PENDING State For Over 30 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EventBridge partner event source is in PENDING state and has been pending for more than 30 days — i.e., the partner registered the source but the AWS-side operator never associated it with a bus. The partner can publish events, but they have no destination; the partner-side billing continues. PENDING is intended as a transient state during initial integration; long-stale PENDING sources are abandoned integrations.

**Remediation:** Decide whether to complete the integration (associate the source with a bus via CreateEventBus with the source's EventSourceName) or delete it (DeleteEventSource) if the partner integration is no longer needed. Long PENDING sources are typically abandoned integrations that should be cleaned up.

---

### CTL.EVENTBRIDGE.PIPE.ENRICHMENT.IAM.WILDCARD.001

**EventBridge Pipe Enrichment Lambda Role Has Wildcard Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EventBridge Pipe enrichment Lambda function execution role grants wildcard actions (iam:*, s3:*, dynamodb:*) instead of the minimum required to enrich each record. Pipe enrichment runs in the data path between source and target — every record flows through it. A wildcard role on the enrichment makes every pipe invocation a potential pivot point: if the enrichment Lambda is ever exploited (deserialization bug, dependency vuln, supply-chain compromise), the wildcard role brings the full scope with it.

**Remediation:** Replace the wildcard with the specific actions the enrichment needs. Most enrichment Lambdas only need to read a lookup table or call a downstream API for context — list those exact actions and resources. Avoid managed policies like AdministratorAccess on enrichment roles.

---

### CTL.EVENTBRIDGE.PIPE.ENRICHMENT.NOTIMEOUT.001

**EventBridge Pipe Enrichment Has No Timeout Or An Excessive One**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6, A.8.16; nist_800_53_r5: SC-5, SI-11; soc2: A1.1, CC8.1;

EventBridge Pipe enrichment Lambda's timeout is at the AWS maximum (15 minutes) or unset (defaults to 3 seconds, but ≥30s is the issue). A long enrichment timeout stalls the pipe's source consumer — Kinesis / DynamoDB-Streams shards block on the in-flight record, source backlog grows, downstream targets starve. A 15-minute enrichment isn't enrichment, it's a long-running workflow that should be a Step Functions target instead.

**Remediation:** Set the enrichment Lambda timeout to <=30 seconds. If the enrichment legitimately needs longer (calling a third-party API with multi-second latency, performing aggregation across a long window), restructure the pipe: use a fast enrichment that emits events to a Step Functions state machine target, let the long work happen out-of-band, and write the result back via a separate path.

---

### CTL.EVENTBRIDGE.PIPE.LIFECYCLE.CREATEFAILED.001

**EventBridge Pipe Stuck In CREATE_FAILED Or UPDATE_FAILED State**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

EventBridge Pipe is in CREATE_FAILED or UPDATE_FAILED state and has not been deleted or repaired. The pipe holds source resources (consumer registrations, IAM bindings, secret references) but isn't processing records. Source-side cost may still accrue (Kinesis enhanced fan-out consumers continue to bill, MSK IAM auth tokens are issued, secret access logs populate). Operators looking at the resource list see "an EventBridge Pipe exists for this stream"; the pipe is effectively offline.

**Remediation:** Investigate the StateReason via DescribePipe. Common causes: invalid IAM permissions, missing source resource, secret decryption failure, target ARN not yet provisioned. Either fix the underlying issue and call StartPipe, or delete the pipe (DeletePipe) if the deployment is being abandoned. Add a CloudWatch alarm on pipe state to surface future failures fast.

---

### CTL.EVENTBRIDGE.PIPE.LIFECYCLE.DORMANT.001

**EventBridge Pipe Has Been STOPPED For Over 90 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

EventBridge Pipe is in STOPPED state and has been stopped for more than 90 days. Long-stopped pipes are typically forgotten experiments, decommissioning that never finished, or stale staging-environment fixtures. They retain source bindings, IAM trust policies, and secret references that surface as inventory clutter and audit noise. Either delete the pipe entirely or document the long-pause rationale via a tag.

**Remediation:** Decide whether the pipe is decommissioned (DeletePipe) or paused for a documented reason (add a tag like Lifecycle=Hibernating + DocumentedReason=<jira-ticket>). Long-stopped pipes accumulate as inventory clutter and extend the IAM-policy audit surface for no operational benefit.

---

### CTL.EVENTBRIDGE.PIPE.SOURCE.IAM.WILDCARD.001

**EventBridge Pipe Source Role Has Wildcard Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EventBridge Pipe source IAM role grants wildcard actions on the source service (kinesis:*, dynamodb:*, sqs:*, kafka:*) instead of the minimum required for pipe consumption (typically GetRecords / GetShardIterator / DescribeStream-style read-only actions). A wildcard role lets the pipe — or anyone able to assume it — do far more than poll the source: write back, modify the stream's consumer registration, delete records, or reshape the resource. Same overprivilege pattern as Lambda execution roles, scoped to the pipe-source surface.

**Remediation:** Replace the wildcard action with the specific read-only actions the pipe needs. For Kinesis: GetRecords, GetShardIterator, DescribeStream, ListShards. For DynamoDB Streams: DescribeStream, GetRecords, GetShardIterator, ListStreams. For SQS: ReceiveMessage, DeleteMessage, GetQueueAttributes. For self-managed Kafka / MSK: the IAM actions documented for the chosen auth mechanism. AWS publishes least-privilege role examples per source type; those are the right starting point.

---

### CTL.EVENTBRIDGE.PIPE.SOURCE.KAFKA.PLAINTEXT.001

**EventBridge Pipe Self-Managed Kafka Source Stores Credentials In Plaintext**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.17, A.8.5, A.8.24; nist_800_53_r5: AC-3, IA-5, SC-28; pci_dss_v4.0: 3.5, 8.3; soc2: CC6.1, CC6.3;

EventBridge Pipe with a self-managed Apache Kafka source has authentication credentials configured directly (BasicAuth / SASL_SCRAM with cleartext username and password) instead of via Secrets Manager reference. The credentials are visible to anyone with pipes:DescribePipe permission and rotate only when the pipe is updated. Same plaintext-credential pattern as Lambda environment variables but in pipe scope.

**Remediation:** Move the credentials to AWS Secrets Manager. Replace the pipe's SourceParameters.SelfManagedKafkaParameters.Credentials with a SECRETS_MANAGER reference (BasicAuth ARN or ClientCertificateTlsAuth ARN as appropriate). Configure the secret for automatic rotation and grant the pipe role secretsmanager:GetSecretValue on the secret ARN only.

---

### CTL.EVENTBRIDGE.PIPE.SOURCE.MSK.NOIAM.001

**EventBridge Pipe MSK Source Does Not Use IAM Authentication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, IA-5; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, IA-5; soc2: CC6.1, CC6.3;

EventBridge Pipe with an Amazon MSK source uses TLS-only or SASL_SCRAM authentication instead of IAM-based authentication. IAM auth (CLIENT_CERTIFICATE_TLS_AUTH excluded) lets pipe access be controlled through standard AWS IAM policies, integrates with CloudTrail, and avoids the operational burden of rotating SCRAM secrets or distributing client certificates. MSK IAM auth is the recommended posture; non-IAM modes are an identity-management gap unless there's a documented compatibility reason.

**Remediation:** Switch the pipe's SourceParameters.ManagedStreamingKafkaParameters authentication to MSK IAM auth (set credentials reference to use IAM rather than SASL_SCRAM secret). Grant the pipe role kafka-cluster:Connect plus the per-topic kafka-cluster:DescribeTopic / kafka-cluster:ReadData actions scoped to the consuming topic ARN. Remove the SCRAM secret from the pipe configuration.

---

### CTL.EVENTBRIDGE.PIPE.SOURCE.NODLQ.001

**EventBridge Pipe Source Has No Dead-Letter Queue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11, CP-10; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CP-10; soc2: A1.2, CC7.2;

EventBridge Pipe has no DeadLetterConfig on its source. Poison-pill records — malformed payloads, items that crash enrichment, items the target rejects after retry exhaustion — block the pipe's source consumer indefinitely or are silently discarded depending on source semantics. Without a DLQ there's no preservation surface for failed records and no mechanism for the pipe to make forward progress past a bad item. Pipes with Kinesis / DynamoDB-Streams sources are particularly affected: the source iterator stalls on the bad shard until intervention.

**Remediation:** Configure a DeadLetterConfig pointing at an SQS queue, with queue retention of at least 14 days for investigation headroom. Pair with a CloudWatch alarm on the DLQ depth so the pipe's failure rate surfaces fast. For Kinesis / DynamoDB-Streams sources, also configure OnPartialBatchItemFailure to handle per-record failures without stalling the shard.

---

### CTL.EVENTBRIDGE.PIPE.SOURCE.NOFILTER.001

**EventBridge Pipe Has No Source Filter Pattern**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SC-5; soc2: CC6.1, CC8.1;

EventBridge Pipe has no SourceParameters.FilterCriteria configured. Every record from the source flows through enrichment (if configured) and into the target. Without a filter, the pipe's enrichment Lambda processes every record regardless of relevance, and the target receives the full source firehose. Cost, latency, and downstream load all scale with source volume rather than with the actually-relevant subset. AWS pipes support source-side filtering precisely so the pipe can drop unwanted records before incurring enrichment or target invocation cost.

**Remediation:** Configure SourceParameters.FilterCriteria with a JSON-event pattern matching only the records the pipe should process. Filter early to reduce enrichment Lambda invocations and target load. If a true catch-all is needed (an analytics archive sink), document the rationale in the pipe's tags (Purpose=archive-all) and pair with throughput monitoring.

---

### CTL.EVENTBRIDGE.PIPE.TARGET.NODLQ.001

**EventBridge Pipe Target Failure Has No Dead-Letter Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11; soc2: A1.2, CC7.2;

EventBridge Pipe has source DLQ configured (or not) but no separate target-failure DLQ. When the target rejects a record (after retries), the pipe routes the record to its source DLQ if one exists, conflating source-side poison records with target-side failures. Operators investigating "why are records in the DLQ" can't distinguish between the source emitting malformed records and the target's downstream service being unhealthy. Pipes with mixed-failure-mode workloads benefit from separate target DLQ to keep the failure modes distinguishable.

**Remediation:** Configure a separate TargetParameters.DeadLetterConfig pointing at a distinct SQS queue. Tag the queue (Source=eb-pipe-target-failures, PipeName=<name>) so operators investigating failures can distinguish target- side from source-side poison records. Pair with a CloudWatch alarm on each DLQ so the failure mode is visible.

---

### CTL.EVENTBRIDGE.POLICY.CLOUDWATCH.NOSOURCE.001

**EventBridge Bus Policy Allows CloudWatch PutEvents Without SourceAccount**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; soc2: CC6.1, CC6.6;

EventBridge bus resource policy grants events:PutEvents to the CloudWatch service principal (cloudwatch.amazonaws.com or events.amazonaws.com on cross-account flows) without an aws:SourceAccount or aws:SourceArn condition. Any CloudWatch alarm in any AWS account can publish events to the bus. The bus accepts the spoofed alarm-state-change event; downstream rules matching alarm-related patterns fire on attacker-controlled input — including security-response automations.

**Remediation:** Add aws:SourceAccount (the legitimate publishing account) or aws:SourceArn (the specific alarm ARN) to every statement granting CloudWatch PutEvents.

---

### CTL.EVENTBRIDGE.POLICY.DELETEEVENTBUS.BROAD.001

**EventBridge Bus Policy Allows DeleteEventBus Or DeleteRule To Non-Admin**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, SI-12; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3, A1.2;

EventBridge bus resource policy grants events:DeleteEventBus or events:DeleteRule to principals beyond a tightly-scoped administrative role. Deleting the bus or its rules is the most destructive EB operation: every downstream automation built on the bus stops running, ghost references propagate to upstream CloudWatch alarms, and recovery requires recreating both resources and re-validating consumer integrations.

**Remediation:** Restrict events:DeleteEventBus and events:DeleteRule to a dedicated platform-admin role with break-glass approval. Add a CloudWatch alarm on DeleteEventBus / DeleteRule API calls so destructive events trigger an immediate page. Consider AWS SCPs to deny deletion org-wide except from a designated admin account.

---

### CTL.EVENTBRIDGE.POLICY.IDENTITY.MISMATCH.001

**EventBridge Cross-Account Bus Permission Without Matching Target IAM**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, CM-2; soc2: CC6.1, CC8.1;

EventBridge bus's resource policy grants cross-account PutEvents access, but the target-side IAM (rule invocation role on the receiving account) doesn't grant the corresponding permission. AWS authorization for cross- account event delivery requires BOTH: bus policy permits the call, AND the target's invocation context permits the invoke. A mismatch silently drops events at the permissions check — no error to the publisher, no delivery to the target.

**Remediation:** Audit cross-account flows: for each bus policy granting cross-account PutEvents, trace to the target rules in the receiving account and verify their invocation roles permit the target action. Use AWS access analyzer or the IAM policy simulator on a sample event flow.

---

### CTL.EVENTBRIDGE.POLICY.PARTNER.BROAD.001

**EventBridge Bus Policy Allows Partner Event Source Registration Broadly**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.5.19, A.8.2; nist_800_53_r5: AC-3, AC-6, SC-7; soc2: CC6.1, CC6.3, CC6.6;

EventBridge bus resource policy grants events:CreatePartnerEventSource to principals beyond a tightly- scoped administrative role. Partner event sources are SaaS integrations (Datadog, PagerDuty, Auth0, etc.) that publish events into the bus. Allowing broad registration means an unauthorized account or role can register a partner-shaped source and inject events that downstream rules treat as coming from a trusted partner.

**Remediation:** Restrict events:CreatePartnerEventSource and events:CreateEventBus (for partner buses) to a dedicated platform-admin role. Audit existing partner event sources via ListPartnerEventSources for unexpected registrations.

---

### CTL.EVENTBRIDGE.POLICY.PUTRULE.BROAD.001

**EventBridge Bus Policy Allows PutRule To Non-Admin Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, CM-3; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3, CC6.6;

EventBridge bus resource policy grants events:PutRule to principals beyond a tightly-scoped administrative role. PutRule creates or modifies rules on the bus — it controls which patterns fire, which downstream automation runs, and on which event shapes. A PutRule grant on a bus is equivalent to control over the account's automation surface. Most production bus policies should reserve PutRule to a dedicated platform role; broad grants (Principal: *, broad role wildcards, cross-account principals without scope) are an automation-takeover surface.

**Remediation:** Restrict events:PutRule to a dedicated platform-admin role. Remove Principal: * statements; replace cross-account principal wildcards with specific role ARNs scoped by aws:PrincipalOrgID. Audit every existing rule for unexpected creators via CloudTrail PutRule events.

---

### CTL.EVENTBRIDGE.POLICY.PUTTARGETS.BROAD.001

**EventBridge Bus Policy Allows PutTargets To Non-Admin Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, CM-3; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3, CC6.6;

EventBridge bus resource policy grants events:PutTargets to principals beyond a tightly-scoped administrative role. PutTargets attaches new targets to an existing rule — without changing the pattern. The rule continues to advertise the same behavior to reviewers; the actual delivery surface silently grows to include the attacker's target. This is the most insidious EB privilege because it leaves the rule itself unchanged. Existing pattern audits don't catch it.

**Remediation:** Restrict events:PutTargets to a dedicated platform-admin role. Audit every existing rule's target list for unexpected ARNs via DescribeRule + ListTargetsByRule. Add a CloudWatch alarm on PutTargets API calls to surface future additions.

---

### CTL.EVENTBRIDGE.POLICY.REMOVETARGETS.BROAD.001

**EventBridge Bus Policy Allows RemoveTargets To Non-Admin Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-6, SI-4; iso_27001_2022: A.5.15, A.8.2, A.8.16; nist_800_53_r5: AC-3, AC-6, SI-4; pci_dss_v4.0: 7.2, 10.2; soc2: CC6.1, CC6.3, CC7.2;

EventBridge bus resource policy grants events:RemoveTargets to principals beyond a tightly-scoped administrative role. RemoveTargets strips targets from a rule. The rule's pattern stays — events still match — but they have no destination. The rule becomes a silent dead rule. Security automation, remediation pipelines, and audit ingestion that depended on the rule are turned off without visible configuration change.

**Remediation:** Restrict events:RemoveTargets to a dedicated platform-admin role. Add a CloudWatch alarm on RemoveTargets API calls so future strips surface immediately. Pair with rule-target audit via daily DescribeRule + ListTargetsByRule reconciliation.

---

### CTL.EVENTBRIDGE.POLICY.S3.NOSOURCE.001

**EventBridge Bus Policy Allows S3 PutEvents Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

EventBridge bus resource policy grants events:PutEvents to the S3 service principal (s3.amazonaws.com) without an aws:SourceArn or aws:SourceAccount condition. Any S3 bucket in any AWS account can configure event notifications targeting the bus and have them accepted. Same confused-deputy pattern as CTL.SQS.POLICY.S3.NOSOURCE.001 / CTL.SNS.POLICY.S3.NOSOURCE.001 — but the EventBridge variant has the largest blast radius because the injected event reaches every rule whose pattern matches it, including security-automation Lambdas, downstream Step Functions, and cross-account targets.

**Remediation:** Add aws:SourceArn (the legitimate bucket ARN) or aws:SourceAccount (the bucket-owning account) to every Statement granting s3.amazonaws.com PutEvents. Combine both for defense in depth — sourceArn pins the specific bucket, sourceAccount blocks any bucket in foreign accounts.

---

### CTL.EVENTBRIDGE.POLICY.SES.NOSOURCE.001

**EventBridge Bus Policy Allows SES Inbound Without Source Restriction**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; soc2: CC6.1, CC6.6;

EventBridge bus resource policy grants events:PutEvents to the SES service principal (ses.amazonaws.com) without an aws:SourceArn or aws:SourceAccount condition. Any SES sending identity in any account can publish bounce, complaint, and delivery events to the bus. Downstream rules consuming SES events for compliance / abuse handling fire on spoofed payloads.

**Remediation:** Add aws:SourceArn (the SES configuration set or identity ARN) or aws:SourceAccount (the SES-owning account) to every statement granting ses.amazonaws.com PutEvents.

---

### CTL.EVENTBRIDGE.POLICY.SPRAWL.001

**EventBridge Bus Policy Has Excessive Statement Count**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CM-2; iso_27001_2022: A.5.15, A.8.2, A.8.32; nist_800_53_r5: AC-3, CM-2; soc2: CC6.1, CC8.1;

EventBridge bus resource policy contains an excessive number of Allow statements (>= 10), accumulated over time as integrations came and went. Each statement is an attack surface — service principals, cross-account grants, and condition variants multiply. Sprawl correlates strongly with stale grants for decommissioned services, partner sources, and account-to-account flows that no longer exist. Same governance pattern as CTL.SNS.POLICY.SPRAWL.001 and CTL.SQS.POLICY.SPRAWL.001.

**Remediation:** Audit every Allow statement: identify the integration that introduced it, confirm the integration still exists, and remove statements for decommissioned services. After consolidation the policy should typically have under 10 statements; more usually indicates layered grants that should be merged with shared conditions.

---

### CTL.EVENTBRIDGE.POLICY.SSM.NOSOURCE.001

**EventBridge Bus Policy Allows SSM Run Command Inbound Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7, AT-3; soc2: CC6.1, CC6.6;

EventBridge bus resource policy grants events:PutEvents to the Systems Manager service principal (ssm.amazonaws.com) without an aws:SourceArn or aws:SourceAccount condition. SSM publishes Run-Command, Maintenance-Window, and Automation events. Without source restriction any SSM document execution in any account can inject events targeting the bus — and downstream automation rules built around SSM event types (e.g., remediation-on-document- failure) execute on attacker-controlled triggers.

**Remediation:** Add aws:SourceArn (the SSM document or association ARN) or aws:SourceAccount (the SSM-owning account) to every statement granting ssm.amazonaws.com PutEvents. SSM events are operationally privileged — restrict tightly.

---

### CTL.EVENTBRIDGE.REPLAY.CROSSBUS.001

**EventBridge Replay Targets A Different Bus Than The Source**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, AC-4, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, AC-21, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6, CC6.7;

EventBridge replay's destination is a different event bus than the bus the archive captured. This is the documented exfiltration vector for archive abuse: an archive on a sensitive bus (security-events, audit) is replayed into a less-controlled bus (analytics, dev) where downstream subscribers — including potentially attacker-controlled ones — receive every replayed event. Replay between buses should require an explicit business justification and an audit log, not be a default capability.

**Remediation:** Cancel the replay (CancelReplay) if it's still active. Audit who started the replay (CloudTrail StartReplay event) and whether the destination bus has subscribers that shouldn't have access to the source's events. For legitimate cross-bus replays (e.g., replaying to a dedicated incident-replay bus), document the business case in tags and restrict events:StartReplay via the source archive bus's policy to specific principals + specific destination bus ARNs (aws:RequestedRegion + aws:ResourceTag conditions).

---

### CTL.EVENTBRIDGE.REPLAY.FILTER.WIDE.001

**EventBridge Replay Filter Pattern Broader Than Archive Filter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, AC-3; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, AC-3; soc2: CC6.1, CC8.1;

EventBridge replay's event-pattern filter is broader than (or absent compared to) the archive's filter. Effective replay scope is "events matching archive filter AND replay filter", but if the operator intended replay to be a strict subset of the archive — replaying only HIGH-severity findings rather than all GuardDuty events, for example — a missing or broader replay filter re-injects more than intended. Downstream subscribers see events the operator didn't mean to replay.

**Remediation:** Cancel the replay (CancelReplay). Restart with a replay filter that's a strict subset of the archive filter — typically a more-specific detail-type or a severity threshold. If the goal is to replay everything in the archive, set the replay filter equal to the archive filter explicitly so future operators reading the replay know it was deliberate.

---

### CTL.EVENTBRIDGE.REPLAY.SESSION.STALE.001

**EventBridge Replay Session Has Been Running Longer Than Expected**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.8.32; nist_800_53_r5: SI-4; soc2: CC8.1, A1.1;

EventBridge replay session has been in RUNNING state for more than 24 hours. Replays typically complete in minutes to hours depending on the archive window and downstream throughput; a replay that's been running for over a day is either re-injecting an unexpectedly large window, blocked on downstream backpressure, or was simply forgotten. Long-running replays continue to invoke downstream targets — every hour of run time is more downstream load.

**Remediation:** Check replay status (DescribeReplay): EventLastReplayedTime indicates progress, EventEndTime indicates target completion. If the replay has stalled or is invoking targets unexpectedly, cancel it (CancelReplay). For long-running replays that are legitimately processing a large archive window, document the expected duration in the replay's description so future operators don't mistake it for a stalled session.

---

### CTL.EVENTBRIDGE.REPLAY.UNTHROTTLED.001

**EventBridge Replay Has No Rate Throttle Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; iso_27001_2022: A.8.6, A.8.16; nist_800_53_r5: SC-5, SI-11; soc2: A1.1, A1.2;

EventBridge replay was initiated without rate limiting and re-injects events at the bus's maximum ingestion rate. For archives capturing high-volume events over weeks or months, unthrottled replay overwhelms downstream targets — Lambda concurrency limits hit, SQS backpressure builds, target service 5xx rates spike. Replay should be paced to stay within the downstream's normal operating envelope.

**Remediation:** Cancel the in-flight replay (CancelReplay), then re-initiate with a narrower time window (replay smaller archive segments) or with downstream pre-warming (Lambda reserved concurrency adjusted, SQS visibility-timeout + worker capacity scaled up). EventBridge does not currently expose a rate-throttle parameter on StartReplay; pacing is achieved by replaying narrow time windows in sequence rather than the full archive at once.

---

### CTL.EVENTBRIDGE.REPLICATION.001

**EventBridge Global Endpoints Must Enable Event Replication**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: CP-10; soc2: A1.1;

EventBridge global endpoints must have event replication enabled to replicate events to both primary and secondary regions for cross-region resilience.

**Remediation:** Enable event replication on the global endpoint.

---

### CTL.EVENTBRIDGE.RULE.DEFAULTBUS.001

**EventBridge Rule On Default Bus Carries Application-Specific Pattern**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, AC-4, SC-7; soc2: CC6.1, CC6.6;

EventBridge rule lives on the account's default bus and carries an application-specific pattern (custom source, custom detail-type) rather than an AWS-service-event pattern. The default bus is the catch-all for AWS service events; mixing application events into it creates cross-tenant exposure in multi-tenant accounts (every team's rules see every other team's app events) and complicates per-application encryption, archive retention, and isolation. Application events should live on a dedicated custom bus.

**Remediation:** Create a dedicated custom event bus for the application (CreateEventBus). Move the rule to the new bus by deleting and recreating it with EventBusName set. Update producers (PutEvents callers) to publish to the custom bus. The default bus should only carry AWS service events (aws.<service> source) plus rules subscribing to those.

---

### CTL.EVENTBRIDGE.RULE.FANOUT.WIDE.001

**EventBridge Rule Has Excessive Target Count**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SC-5; soc2: CC8.1, A1.1;

EventBridge rule has more than 5 targets configured (AWS soft limit). Each event matching the rule is delivered independently to each target; one target's throttle, failure, or rate-limit doesn't isolate from the others, but operationally a wide fan-out often signals that the rule has accumulated targets over time — a new consumer was added without auditing what's already there. The mix of targets often spans criticality classes (security automation alongside analytics, alongside dev observability), and a noisy target throttling the rule's invocation budget starves the critical paths.

**Remediation:** Review the target list via DescribeRule + ListTargetsByRule. For each target, confirm the consumer is still active and that the rule's pattern is the right subscription point — not a more-narrow downstream rule. Consider splitting the rule into per-criticality rules (security, analytics, dev) so target-level throttling on one tier doesn't starve the others. AWS hard limit is 5 targets per rule; values >5 indicate a config validation gap or use of newer features that allow more.

---

### CTL.EVENTBRIDGE.RULE.MAXAGE.SHORT.001

**EventBridge Rule MaximumEventAge Is Shorter Than Recovery Window**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11, CP-10; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CP-10; soc2: A1.2;

EventBridge rule has a MaximumEventAge value below 60 seconds. AWS allows MaximumEventAge in the range 60-86400 seconds; setting it to the 60-second floor means events expire from the retry buffer in less than a minute. Any downstream incident lasting longer than 60 seconds — Lambda cold-start storm, target service 5xx, network blip — exhausts the retention before recovery, and events expire to the DLQ (if configured) or are dropped. The default of 24h is appropriate for most rules; a deliberate reduction is a brittle posture that should be explicit and documented.

**Remediation:** Increase MaximumEventAge to at least 300 seconds; AWS default is 86400 (24h) and is appropriate for most rules. If a short age is a deliberate latency-vs-durability trade, document the rationale in the rule description and pair with a DLQ to preserve expired events.

---

### CTL.EVENTBRIDGE.RULE.NODLQ.001

**EventBridge Rule Has No Dead-Letter Queue Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11, CP-10; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CP-10; soc2: A1.2, CC7.2;

EventBridge rule has no DeadLetterConfig at all — failed target invocations have no preservation surface. After the rule's retry budget exhausts, the event is discarded. Failed events are gone with no record of payload, target, or invocation history. Same failure-handling defect as the SQS NODLQ control but at the EB rule layer; distinct from CTL.EVENTBRIDGE.GHOST.RULE.DLQ.001 (which detects a configured-but-deleted DLQ — this control detects "never configured"). Critical rules — security automation, audit pipelines, billing events — should always have a DLQ.

**Remediation:** Configure a DeadLetterConfig pointing at an SQS queue. Set the queue's retention to at least 14 days (max) to maximize investigation window. Pair with a CloudWatch alarm on the DLQ's ApproximateNumberOfMessagesVisible so failures surface immediately.

---

### CTL.EVENTBRIDGE.RULE.NOTARGETS.001

**EventBridge Rule Has No Targets (Silent Dead Rule)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SI-4; iso_27001_2022: A.5.16, A.8.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-4; soc2: CC6.1, CC7.2, CC8.1;

EventBridge rule is enabled and matches events but has no targets configured. Every matching event is silently dropped — the rule fires, no downstream invocation occurs. This is the structural outcome of RemoveTargets-without-DeleteRule (see CTL.EVENTBRIDGE.POLICY.REMOVETARGETS.BROAD.001) but is also reachable through normal ops drift: a target was removed during decommissioning, the rule wasn't deleted, the pattern still matches. Console shows a healthy rule; downstream consumers see nothing.

**Remediation:** Either attach the intended targets via PutTargets, disable the rule (DisableRule) if it's expected to be inactive, or delete the rule entirely (DeleteRule) if it was supposed to be decommissioned. Pair with a CloudWatch alarm on Invocations==0 for rules tagged as critical so future target strips surface immediately.

---

### CTL.EVENTBRIDGE.RULE.PATTERN.OVERLAP.001

**EventBridge Rule Pattern Overlaps Another Rule On Same Bus**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, SI-11; soc2: CC8.1, A1.1;

EventBridge bus has multiple rules whose patterns overlap — at least one event shape matches more than one rule. Overlapping patterns produce duplicate target invocations: every event in the overlap fires every overlapping rule, and each rule's targets process the event independently. This is rarely intentional; it's usually the result of a refactor that split one rule into two without removing the original, or two teams writing rules for the same event source without coordinating.

**Remediation:** Identify the overlapping rules via DescribeRule for each rule on the bus. Choose one of: (a) consolidate into a single rule with all needed targets, (b) narrow each rule's pattern with a discriminating key (different detail-type / source / tag) so the patterns are mutually exclusive, or (c) accept the overlap explicitly and add a tag (Overlap=intentional) plus a documentation note stating which rule is canonical.

---

### CTL.EVENTBRIDGE.RULE.PATTERN.SENSITIVE.001

**EventBridge Rule Subscribes To Sensitive Source Without Filter Narrowing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SI-4; iso_27001_2022: A.5.15, A.8.16, A.8.24; nist_800_53_r5: AC-3, AC-21, SI-4; soc2: CC6.1, CC6.6, CC7.2;

EventBridge rule subscribes to a high-sensitivity event source (aws.health, aws.config, aws.guardduty, aws.securityhub, aws.cloudtrail, aws.iam) without narrowing the pattern beyond the source key. The rule receives every event from the sensitive source and forwards it to every target. Health, Config, and GuardDuty events contain finding details, account IDs, resource identifiers, and remediation hints — broad fan-out exposes that material to every target including those that don't need it.

**Remediation:** Add at least one narrowing key to the pattern: detail-type (specific event class), detail.severity (e.g., HIGH / CRITICAL only for GuardDuty findings), detail.eventName (specific CloudTrail API), or resource ARN prefix. Targets that don't need the full firehose should subscribe to a narrowed downstream rule, not the sensitive-source root rule.

---

### CTL.EVENTBRIDGE.RULE.PATTERN.WIDE.001

**EventBridge Rule Pattern Matches All Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: AC-3, CM-2; soc2: CC6.1, CC8.1;

EventBridge rule has an event pattern that matches every event on the bus — either an empty pattern object, a pattern that prefix-matches the empty string, or a logically equivalent always-true expression. The rule fans out every event to every configured target. This is rarely the intent; it's almost always a debug stub left in production, a copy-paste from a "match all" example, or a pattern whose narrowing keys were accidentally removed. The cost is throughput, downstream invocation count, and loss of the pattern's diagnostic value (no longer answers "which events triggered this rule").

**Remediation:** Tighten the pattern with at least one narrowing key — source, detail-type, or detail field equality. If a true catch-all is required, document it with a tag (e.g., Purpose=catch-all-archive) and pair it with a dedicated archive-only target so the fan-out is bounded.

---

### CTL.EVENTBRIDGE.RULE.RETRY.NONE.001

**EventBridge Rule Retry Policy Disabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-10; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CP-10; soc2: CC7.2, A1.2;

An EventBridge rule has MaximumRetryAttempts set to 0, disabling retries on target-invocation failure. Any transient downstream failure (Lambda throttling, ECS RunTask capacity, SQS visibility collision) results in immediate event loss. Combined with no DLQ this is a complete failure-path collapse; even with a DLQ, this trades retry headroom for tighter latency at the cost of durability. Rules in the failure-handling path of upstream services (security automation, audit pipelines) should not have retries disabled.

**Remediation:** Set MaximumRetryAttempts to a non-zero value (AWS default is 185, range 0–185) via aws events put-targets with --retry-policy. For high-throughput rules a lower bound around 5–25 is reasonable; for security/audit rules use the default. Pair with a DLQ so events that exhaust retries are still preserved.

---

### CTL.EVENTBRIDGE.RULE.SCHEDULE.SYNTAX.001

**EventBridge Schedule Expression Has Invalid Syntax**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CP-10; soc2: CC6.1, CC8.1, A1.2;

EventBridge rule has a ScheduleExpression that is syntactically invalid (cron typo, rate-expression unit error, or unsupported format). The rule is created — EventBridge accepts the expression at PutRule time only with limited validation — but it never fires. The rule appears active in the console; CloudWatch shows zero invocations; the work the schedule was supposed to drive silently doesn't happen.

**Remediation:** Validate the expression syntax. cron expressions in EventBridge use 6 fields (minute, hour, day-of-month, month, day-of-week, year) — different from standard 5-field cron. rate expressions must use minute/minutes/hour/hours/day/days units. Test the expression by enabling the rule briefly and confirming the next-invocation time, or use the AWS console's schedule preview.

---

### CTL.EVENTBRIDGE.RULE.SCHEDULE.TIMEZONE.001

**EventBridge Schedule Expression Defaults To UTC When Local Intended**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2; soc2: CC8.1, A1.2;

EventBridge rule has a cron-format schedule expression that references hour-of-day or day-of-week without explicit timezone context. EventBridge interprets the expression in UTC. When the schedule was intended for a local business timezone (e.g., "9 AM every weekday in PST"), it fires at the wrong wall-clock time — typically 8 hours off, drifting across DST boundaries. Pure UTC schedules are fine; business-hour schedules require the newer EventBridge Scheduler (with ScheduleExpressionTimezone) or an explicit UTC-converted offset documented in the rule's description.

**Remediation:** For business-hour-sensitive schedules, migrate to EventBridge Scheduler which supports ScheduleExpressionTimezone. If keeping the rule on EventBridge, document the UTC offset in the rule description (e.g., "9 AM PST = 17:00 UTC standard / 16:00 UTC during DST") and add a tag indicating manual DST rollover responsibility.

---

### CTL.EVENTBRIDGE.RULE.SELFLOOP.001

**EventBridge Rule Target Republishes To Same Bus With Matching Pattern**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5, SI-11; iso_27001_2022: A.8.6, A.8.16; nist_800_53_r5: SC-5, SI-11; soc2: A1.1, A1.2;

EventBridge rule has a target that republishes events back to the same bus, and the rule's pattern matches the republished event shape. Each event match triggers a target invocation that produces another matching event — the cycle multiplies until a rate limit, account quota, or downstream failure breaks it. Most commonly seen with rules whose target is a Lambda or Step Functions workflow that PutEventses augmented copies back to the bus for downstream consumers.

**Remediation:** Either narrow the rule pattern to exclude the target's republished event shape (add a source/detail-type filter that discriminates original from republished), or route the target's republish to a different bus. As a defense-in-depth floor, set a CloudWatch alarm on Invocations exceeding a historical p99 baseline so a runaway loop surfaces fast.

---

### CTL.EVENTBRIDGE.SCHEDULER.AAC.DELETE.001

**EventBridge Scheduler ActionAfterCompletion=DELETE On A Recurring Schedule**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2; soc2: CC8.1;

EventBridge Scheduler schedule has ActionAfterCompletion set to DELETE while the schedule is recurring (cron or rate expression). DELETE is intended for one-time `at()` schedules to auto-clean themselves after firing; on a recurring schedule it has no defined effect on a per-fire basis but is a strong smell of misconfiguration — the operator either intended a one-time schedule (and should switch the expression) or intended NONE (and should switch the action). Either way the current state diverges from the intent.

**Remediation:** Decide which intent applies: (a) the schedule should fire once and clean up — change the expression to `at(...)`; (b) the schedule should recur — change ActionAfterCompletion to NONE. The current cron+DELETE / rate+DELETE combination suggests one of the two settings was edited without the other being updated.

---

### CTL.EVENTBRIDGE.SCHEDULER.AT.STALE.001

**EventBridge Scheduler One-Time Schedule Has Already Fired Or Expired**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC8.1;

EventBridge Scheduler one-time schedule (using `at()` expression) has a target time in the past and is still in the schedule list. The schedule has either fired and the post-completion action didn't delete it, or it expired without firing. Either way the schedule is dead weight in the schedule group's inventory — it will not fire again, but it accumulates IAM-audit surface and obscures which schedules are actually live.

**Remediation:** Delete the schedule (DeleteSchedule). For one-time schedules going forward, set ActionAfterCompletion=DELETE so post-fire cleanup is automatic. Audit the schedule group for other stale `at()` schedules.

---

### CTL.EVENTBRIDGE.SCHEDULER.CRON.SYNTAX.001

**EventBridge Scheduler Schedule Expression Has Invalid Syntax**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, CP-10; soc2: CC6.1, CC8.1, A1.2;

EventBridge Scheduler schedule has a malformed ScheduleExpression (cron typo, rate-unit error, or unsupported `at()` form). The schedule is created — Scheduler accepts the expression at CreateSchedule time with limited validation — but never fires. The schedule appears healthy in the console; CloudWatch shows zero invocations; the work the schedule was supposed to drive silently doesn't happen. Same silent-failure pattern as CTL.EVENTBRIDGE.RULE.SCHEDULE.SYNTAX.001 but on the Scheduler sub-product.

**Remediation:** Validate the expression. EventBridge Scheduler supports `cron(...)` (6-field cron with year), `rate(...)` (numeric + minutes/hours/days), and `at(YYYY-MM-DDThh:mm:ss)` for one-time. Test by calling GetSchedule and checking ScheduleState — non-running schedules with NextInvocationTime absent are typically the malformed ones.

---

### CTL.EVENTBRIDGE.SCHEDULER.GHOST.DLQ.001

**EventBridge Scheduler DLQ Target Does Not Exist**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-11; soc2: CC6.1, CC8.1, A1.2;

EventBridge Scheduler schedule has DeadLetterConfig configured but the DLQ ARN names an SQS queue that has been deleted. Failed invocations meant to be preserved in the DLQ for investigation are silently lost — the safety net advertised in the schedule's configuration doesn't exist. Same ghost-reference pattern as CTL.EVENTBRIDGE.GHOST.RULE.DLQ.001 but on the Scheduler sub-product.

**Remediation:** Recreate the SQS queue at the original ARN, repoint the schedule's DeadLetterConfig to a live queue (UpdateSchedule with new Target.DeadLetterConfig.Arn), or remove the DLQ if no longer needed. Pair with a CloudWatch alarm on InvocationDroppedCount so future deletions surface.

---

### CTL.EVENTBRIDGE.SCHEDULER.GROUP.NOCMK.001

**EventBridge Scheduler Schedule Group Encrypted With AWS-Managed Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-28; iso_27001_2022: A.5.17, A.8.24; nist_800_53_r5: SC-12, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1;

EventBridge Scheduler schedule group has KmsKeyArn empty or set to the AWS-managed key (aws/scheduler) instead of a customer- managed key (CMK). Schedule input payloads — the body delivered to the target on each fire — may contain sensitive data (account-scoped IDs, payload templates with detail fields). AWS-managed-key encryption can't be revoked, audited at the key level, or rotated on the org's schedule. Same CMK-vs-AWS- managed pattern as SNS topic encryption.

**Remediation:** Create a customer-managed KMS key with appropriate key policy (allowing scheduler.amazonaws.com encrypt/decrypt for schedules in this account, restricted by SourceArn) and update the schedule group's KmsKeyArn (UpdateScheduleGroup). Schedules created in the group inherit the group's encryption key.

---

### CTL.EVENTBRIDGE.SCHEDULER.NODLQ.001

**EventBridge Scheduler Schedule Has No Dead-Letter Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11, CP-10; iso_27001_2022: A.8.16; nist_800_53_r5: SI-11, CP-10; soc2: A1.2, CC7.2;

EventBridge Scheduler schedule has no DeadLetterConfig. Failed invocations after retry exhaustion are dropped: the schedule fired, the target invocation failed, and there's no preservation surface. The Scheduler InvocationDroppedCount CloudWatch metric increments — but without a DLQ there's no way to recover the failed invocation's payload, target, or failure reason for replay. Critical scheduled work (security-automation triggers, audit-log rotation, retention enforcement) should always have a DLQ.

**Remediation:** Configure Target.DeadLetterConfig with an SQS queue ARN. Set the queue's retention to at least 14 days (max). Pair with a CloudWatch alarm on the DLQ depth and on the Scheduler InvocationDroppedCount metric so failures surface fast.

---

### CTL.EVENTBRIDGE.SCHEDULER.PAUSED.STALE.001

**EventBridge Scheduler Schedule Has Been DISABLED For Over 90 Days**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

EventBridge Scheduler schedule is in DISABLED state and has been paused for more than 90 days. Long-paused schedules are typically forgotten experiments, decommissioning that never finished, or stale temporary disables that nobody remembered to revisit. They retain IAM trust, role bindings, and schedule-group membership that surface as inventory clutter. Either delete or document the long-pause rationale.

**Remediation:** Decide whether the schedule is decommissioned (DeleteSchedule) or paused for a documented reason (add a tag like Lifecycle=Hibernating + DocumentedReason=<jira-ticket>). Long-disabled schedules accumulate IAM trust and role binding audit surface for no operational benefit.

---

### CTL.EVENTBRIDGE.SCHEDULER.ROLE.TRUST.001

**EventBridge Scheduler Role Trust Policy Not Restricted To Scheduler Service**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6, IA-2; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1, CC6.3;

EventBridge Scheduler invocation role's trust policy does not restrict AssumeRole to scheduler.amazonaws.com — the role can be assumed by other AWS services or by IAM principals through the standard sts:AssumeRole path. Scheduler-only trust is the AWS-recommended posture; broader trust expands which principals can pivot through the role to the schedule's target permissions.

**Remediation:** Restrict the trust policy to a single Statement allowing sts:AssumeRole only when Principal.Service is scheduler.amazonaws.com. Add a Condition with aws:SourceAccount = your account ID and aws:SourceArn matching the schedule ARN pattern to prevent confused-deputy use across accounts. Remove any other Service or AWS principals from the trust.

---

### CTL.EVENTBRIDGE.SCHEDULER.ROLE.WILDCARD.001

**EventBridge Scheduler Role Grants Wildcard Target Actions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.2; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 7.2; soc2: CC6.1, CC6.3;

EventBridge Scheduler schedule's invocation IAM role grants wildcard actions on the target service (lambda:*, states:*, ecs:*, sqs:*) instead of the specific InvokeFunction / StartExecution / RunTask / SendMessage action the schedule needs. The role grants substantially more than the schedule exercises; if the role is ever assumed by another principal (role trust gap, audit blind spot), the wildcard scope brings the full attack surface with it. Same overprivilege pattern as Lambda execution roles.

**Remediation:** Replace the wildcard with the single action the target needs: lambda:InvokeFunction (Lambda target), states:StartExecution (Step Functions target), ecs:RunTask plus iam:PassRole (ECS task target), sqs:SendMessage (SQS target), or the Universal-target's specific service:Action. Restrict the Resource to the specific target ARN, not Resource: *.

---

### CTL.EVENTBRIDGE.SCHEDULER.TIMEZONE.001

**EventBridge Scheduler Cron Schedule Has No ScheduleExpressionTimezone**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2; soc2: CC8.1, A1.2;

EventBridge Scheduler cron schedule has no ScheduleExpressionTimezone set. Without an explicit timezone the cron expression is interpreted in UTC. Scheduler is the AWS surface specifically designed to support timezone-aware schedules (unlike legacy EventBridge rule schedules which are UTC-only); leaving the field unset wastes that capability and creates twice-yearly DST drift if the schedule was intended for a local-business cadence.

**Remediation:** Set ScheduleExpressionTimezone to the IANA timezone name (e.g., "America/New_York", "Europe/London", "Asia/Singapore") matching the schedule's intended local-business cadence. Scheduler handles DST transitions automatically when timezone is set. If the schedule is genuinely UTC-driven (data-pipeline coordinator, cross-region reconciliation), set the field to "UTC" explicitly so the choice is documented rather than defaulted.

---

### CTL.EVENTBRIDGE.SCHEMA.PUBLIC.001

**EventBridge Schema Registry Must Not Allow Public or Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

EventBridge schema registry resource policies must not grant public or unrestricted cross-account access. Schema registries describe event structure — public access reveals internal API contracts.

**Remediation:** Restrict the registry resource policy.

---

### CTL.EVENTBRIDGE.TARGET.GHOST.001

**EventBridge Rule Must Not Target Deleted Resources**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.1;

EventBridge rules must not target Lambda functions, SQS queues, or other resources that no longer exist. Events matching the rule are silently dropped. If the rule triggers security automation, that automation stops functioning while appearing active.

**Remediation:** Update the rule target to an existing resource or disable the rule.

---

