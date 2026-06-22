# Control Reference — SQS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SQS.ALARM.AGE.001

**No CloudWatch Alarm for SQS Queue Oldest Message Age**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: SI-4, AU-11; pci_dss_v4.0: 10.6; soc2: CC7.2, A1.2;

No CloudWatch alarm watches the ApproximateAgeOfOldestMessage metric on the SQS source queue. Message age measures processing latency: a 5-second- old message is normal; a 3-hour-old message means consumers are far behind; a 3-day-old message is approaching the default 4-day retention and will expire if not consumed. For time-sensitive workloads (payment processing, order fulfillment, real-time notifications), age directly measures the delay customers experience. Companion to CTL.SQS.ALARM.DEPTH.001 — depth catches accumulation, age catches stalled processing even when arrival and consumption rates are roughly balanced.

**Remediation:** Set the threshold to the longest acceptable processing-latency budget for the workload (e.g., 1 hour for real-time, 24 hours for batch). The alarm should fire well before the queue retention period: aws cloudwatch put-metric-alarm --alarm-name SQS-Age-<queue-name> --metric-name ApproximateAgeOfOldestMessage --namespace AWS/SQS --statistic Maximum --period 300 --evaluation-periods 2 --threshold 3600 --comparison-operator GreaterThanThreshold --dimensions Name=QueueName,Value=<queue-name> --alarm-actions <sns-topic-arn>.

---

### CTL.SQS.ALARM.DELETEQUEUE.001

**No CloudWatch Alarm for SQS DeleteQueue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: AU-6, IR-4, SI-4, CP-10; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm is wired to a CloudTrail metric filter on the DeleteQueue API call. DeleteQueue is permanent — the queue and all its messages are gone in a single call, every producer and consumer starts erroring, and the messages are unrecoverable. Unlike PurgeQueue (which keeps the queue alive), DeleteQueue removes the resource itself. Without an alarm a queue can be deleted accidentally or maliciously without real-time notification; the team discovers the loss only when downstream traffic surfaces errors. Companion to CTL.SQS.ALARM.PURGE.001 — both monitor catastrophic destructive operations.

**Remediation:** Create a CloudTrail metric filter on eventName = DeleteQueue scoped to the queue's ARN, then a CloudWatch alarm with threshold 1 and a 60-second period so the deletion call pages on-call within seconds: aws logs put-metric-filter --filter-pattern '{ $.eventName = "DeleteQueue" && $.requestParameters.queueUrl = "*<queue-name>*" }' followed by aws cloudwatch put-metric-alarm. Deletion cannot be undone, but a fast notification lets the team capture context for forensics and accelerate downstream recovery.

---

### CTL.SQS.ALARM.DEPTH.001

**No CloudWatch Alarm for SQS Queue Depth**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: SI-4, IR-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm watches the ApproximateNumberOfMessagesVisible metric on the SQS source queue. Queue depth is the primary indicator of consumer health: a healthy consumer drains the queue as fast as messages arrive, so depth stays near zero. A growing depth means consumers stopped (Lambda throttled, ECS task crashed, application error) or traffic spiked beyond consumer capacity. Without an alarm, the queue fills silently until retention expires and messages are permanently deleted. Companion to CTL.SQS.ALARM.DLQ.DEPTH.001 — that fires on dead-letter queues; this fires on source queues. The is_dlq guard prevents double-firing.

**Remediation:** Set the threshold to a value the consumer should never legitimately see — for low-traffic queues that's a few hundred messages; for high-traffic queues, a multiple of expected steady-state depth. Use: aws cloudwatch put-metric-alarm --alarm-name SQS-Depth-<queue-name> --metric-name ApproximateNumberOfMessagesVisible --namespace AWS/SQS --statistic Average --period 300 --evaluation-periods 2 --threshold <choose-per-queue> --comparison-operator GreaterThanThreshold --dimensions Name=QueueName,Value=<queue-name> --alarm-actions <sns-topic-arn>.

---

### CTL.SQS.ALARM.DLQ.AGE.001

**No CloudWatch Alarm for SQS Dead-Letter Queue Message Age**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.8.15; nist_800_53_r5: SI-4, AU-11; pci_dss_v4.0: 10.6; soc2: CC7.2, A1.2;

No CloudWatch alarm watches the ApproximateAgeOfOldestMessage metric on the SQS dead-letter queue. An aging DLQ message means one of three things: messages arrived but were never investigated (abandoned DLQ), the investigation is stuck (team saw the messages but the underlying issue is unresolved), or the DLQ consumer is failing itself (recursive failure). If the oldest message approaches the queue retention period (default 4 days, max 14), it expires and is permanently deleted — the failure evidence is lost. Pairs with CTL.SQS.ALARM.DLQ.DEPTH.001 — depth catches accumulation, age catches stalled investigation. Fires only on dead-letter queues.

**Remediation:** Create the alarm with a threshold one day below the queue's retention period (e.g., 3 days for the default 4-day retention) so an investigator has at least a day's notice before messages expire: aws cloudwatch put-metric-alarm --alarm-name SQS-DLQ-Age-<queue-name> --metric-name ApproximateAgeOfOldestMessage --namespace AWS/SQS --statistic Maximum --period 300 --evaluation-periods 1 --threshold 259200 --comparison-operator GreaterThanThreshold --dimensions Name=QueueName,Value=<dlq-name> --alarm-actions <sns-topic-arn>.

---

### CTL.SQS.ALARM.DLQ.DEPTH.001

**No CloudWatch Alarm for SQS Dead-Letter Queue Depth**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: SI-4, IR-4, IR-5; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm watches the ApproximateNumberOfMessagesVisible metric on the SQS dead- letter queue. Failed messages accumulate in the DLQ without notification — the queue may have 10 messages or 10,000 messages and nobody learns until somebody opens the SQS console. This is the single most important SQS alarm: DLQ depth growing means messages are failing processing, the cause is unresolved, and the failure path is collecting data with no investigation. Same pattern as CTL.KMS.ALARM.DELETION.001 — the metric exists in CloudWatch by default, but nobody is paged on it without an explicit alarm. Fires only on queues that ARE dead-letter queues (is_dlq = true); source-queue depth is covered by CTL.SQS.ALARM.DEPTH.001.

**Remediation:** Create the alarm with a threshold of 1 (any message in the DLQ pages on-call): aws cloudwatch put-metric-alarm --alarm-name SQS-DLQ-Depth-<queue-name> --metric-name ApproximateNumberOfMessagesVisible --namespace AWS/SQS --statistic Sum --period 60 --evaluation-periods 1 --threshold 1 --comparison-operator GreaterThanOrEqualToThreshold --dimensions Name=QueueName,Value=<dlq-name> --alarm-actions <sns-topic-arn>. Pair with CTL.SQS.DLQ.NOCONSUMER.001 — an alarm without a consumer is just a delayed-deletion notification. Do both.

---

### CTL.SQS.ALARM.PURGE.001

**No CloudWatch Alarm for SQS PurgeQueue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm is wired to a CloudTrail metric filter on the PurgeQueue API call. PurgeQueue is mass deletion — a single API call removes every message from the queue immediately, irreversibly, with no DLQ preservation. Without an alarm a queue can be purged accidentally, maliciously, or by automation with no real-time notification; the team discovers the loss only when downstream systems report missing data. Pairs with CTL.SQS.POLICY.PURGE.001 (SQS-2) which checks who can issue PurgeQueue; this control checks whether the issuance is monitored. The dangerous combination is "permitted broadly AND undetected", caught by the sqs_destructive_undetected chain.

**Remediation:** Create a CloudTrail metric filter on eventName = PurgeQueue scoped to the queue's ARN, then a CloudWatch alarm with threshold 1 and a 60-second period so a single PurgeQueue call pages on-call within seconds: aws logs put-metric-filter --filter-pattern '{ $.eventName = "PurgeQueue" && $.requestParameters.queueUrl = "*<queue-name>*" }' followed by aws cloudwatch put-metric-alarm.

---

### CTL.SQS.ALARM.SENT.001

**No CloudWatch Alarm for SQS Messages Sent Spike**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm watches the NumberOfMessagesSent metric for anomalous spikes. A sudden producer-side spike usually signals one of: an upstream system failure flooding the queue with error events, a denial-of-service attempt sending messages to the queue, an application bug producing messages in a loop, or a legitimate traffic surge (flash sale, marketing event). All four warrant operator attention; an alarm distinguishes them. Use anomaly-detection or percentage-deviation thresholds rather than static counts — the right "spike" depends on the queue's baseline volume.

**Remediation:** Use CloudWatch anomaly detection rather than a static threshold so the alarm adapts to the queue's baseline: aws cloudwatch put-metric-alarm --alarm-name SQS-Sent-Anomaly-<queue-name> --metric-name NumberOfMessagesSent --namespace AWS/SQS --statistic Sum --period 300 --evaluation-periods 2 --comparison-operator GreaterThanUpperThreshold --thresholds-metric-id e1 --metrics ... --dimensions Name=QueueName,Value=<queue-name> --alarm-actions <sns-topic-arn>. Alternatively, set a percentage-deviation alarm against the same metric's prior-week baseline.

---

### CTL.SQS.AUDIT.DATAEVENTS.001

**CloudTrail Data Events Not Enabled for SQS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 3.2; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.1, 10.2, 10.3; soc2: CC7.1, CC7.2;

CloudTrail is not configured to log SQS data events (SendMessage, ReceiveMessage, DeleteMessage, PurgeQueue). Management events (CreateQueue, DeleteQueue, SetQueueAttributes) are recorded by default — but the message-level operations are not. Without data events there is no audit trail for who sent which message, who received which message, or who deleted messages. For queues carrying PII, financial transactions, or healthcare events, the data-event record is the only message-level audit surface that exists. Cost note: SQS data events generate high log volume; the control is intentionally medium severity because the cost tradeoff is real and the right answer for low-sensitivity queues may be "no data events".

**Remediation:** Add an SQS data-event selector to a CloudTrail trail covering this queue: aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[{"Name":"SQS data events","FieldSelectors": [{"Field":"eventCategory","Equals":["Data"]}, {"Field":"resources.type","Equals":["AWS::SQS::Queue"]}, {"Field":"resources.ARN","Equals":["<queue-arn>"]}]}]'. Restrict the resource ARN selector to security-sensitive queues so the data-event volume cost stays bounded. Verify the trail's S3 destination is in the same organization with appropriate access controls.

---

### CTL.SQS.CONFIG.RETENTION.SHORT.001

**SQS Queue Retention Period Below 24 Hours**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.8.15, A.8.32; nist_800_53_r5: CM-6, AU-11, SI-11; pci_dss_v4.0: 10.6; soc2: CC6.1, A1.2;

SQS queue MessageRetentionPeriod is below 24 hours (86,400 seconds). Short retention means messages that are not consumed quickly are permanently deleted. For workloads with intermittent consumers (batch processing, scheduled Lambda, on-call queues that fire only during incidents), a retention shorter than the longest expected gap between consumer runs leads to message loss. The minimum allowed value is 60 seconds; the SQS default is 4 days. Short retention is sometimes intentional — real-time pipelines where stale messages have no value should drop them — but for any pipeline where a message can become useful after a delay, the retention must accommodate the delay.

**Remediation:** Decide whether short retention is intentional. If the workload is real-time (stale messages have no value), document the choice with a queue tag so the finding is explicitly exempted. Otherwise raise the retention to at least 24 hours, ideally 4 days (the SQS default), so intermittent consumers, replays, and incident-driven processing have a longer recovery window. Apply via aws sqs set-queue-attributes --queue-url <url> --attributes MessageRetentionPeriod=345600.

---

### CTL.SQS.CONFIG.SHORTPOLLING.001

**SQS Queue Uses Short Polling**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-6; iso_27001_2022: A.8.32; nist_800_53_r5: CM-6, SA-22; soc2: CC6.1, A1.2;

SQS queue has ReceiveMessageWaitTimeSeconds set to 0 (short polling). Short polling returns immediately, even when no messages are available. Each ReceiveMessage call is an API request and is billed; short-polled queues with no pending messages produce a steady stream of empty responses, which inflates cost and adds latency (consumers must poll more frequently to detect new messages). Long polling (WaitTimeSeconds 1-20, max 20s) waits for messages to arrive — reducing empty responses, reducing cost, and improving responsiveness. This is an operational/cost control rather than a security control; severity is low because short polling is functionally correct, just inefficient.

**Remediation:** Set ReceiveMessageWaitTimeSeconds to 20 (the maximum) so polls block until a message arrives or the timeout elapses: aws sqs set-queue-attributes --queue-url <url> --attributes ReceiveMessageWaitTimeSeconds=20. The consumer's ReceiveMessage calls should pass WaitTimeSeconds=20 as well to honor long-polling semantics end-to-end.

---

### CTL.SQS.CONFIG.VISIBILITYTIMEOUT.RETENTION.001

**SQS Queue Visibility Timeout Exceeds Message Retention**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-6; iso_27001_2022: A.8.32, A.5.30; nist_800_53_r5: CM-6, SI-11, CP-10; pci_dss_v4.0: 10.6; soc2: CC6.1, A1.2, CC7.4;

SQS queue VisibilityTimeout is greater than its MessageRetentionPeriod. When a consumer calls ReceiveMessage, the message becomes invisible for the visibility-timeout duration; if that duration is longer than the retention period, the message can expire (be deleted by SQS) while the consumer is still processing it. The processing completes against a message that no longer exists; a DeleteMessage call on the receipt handle returns ReceiptHandleIsInvalid. Worse, if the consumer retries (assuming the delete failed transiently), it has nothing to retry against — the message is silently lost. This is a configuration contradiction: visibility must always be shorter than retention so a message is recoverable for at least one visibility cycle.

**Remediation:** Reduce VisibilityTimeout below MessageRetentionPeriod so every in-flight message is recoverable for at least one full visibility cycle. The standard guidance is visibility = max-expected-processing-time + buffer, while retention = visibility * retries (matching the redrive policy's maxReceiveCount). Apply via aws sqs set-queue-attributes --queue-url <url> --attributes VisibilityTimeout=300,MessageRetentionPeriod=345600.

---

### CTL.SQS.CROSSACCOUNT.DLQ.001

**SQS Queue Dead-Letter Queue Is in a Different Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-4; iso_27001_2022: A.5.14, A.5.15; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 3.5; soc2: CC6.1, CC6.6;

SQS source queue's dead-letter queue is in a different AWS account. Failed messages cross an account boundary when they are sent to the DLQ — message content (potentially PII, transaction data, application secrets) traverses from the source account to the DLQ account. The two accounts may have different security controls: different IAM baselines, different monitoring, different access patterns, different audit-logging coverage. If the DLQ account is weaker than the source account, failed messages are less protected in the failure path than in the success path. Cross-account DLQs are sometimes intentional (centralized failure handling in a shared-services account) — when so, the DLQ account must apply equivalent or stronger controls.

**Remediation:** Decide whether the cross-account DLQ is intentional. If centralized failure handling is the design, document the account relationship and verify the DLQ account applies equivalent or stronger controls than the source account (encryption, policy restrictions, audit logging, monitoring alarms). If the DLQ is in the wrong account by mistake (e.g., copied from a template), repoint the redrive policy to a same-account DLQ (aws sqs set-queue-attributes --queue-url <source> --attributes RedrivePolicy='{"deadLetterTargetArn": "<same-account-dlq-arn>","maxReceiveCount":"5"}').

---

### CTL.SQS.DLQ.001

**SQS Queues Must Have Dead-Letter Queue Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: SI-11, CP-10, AU-2; soc2: PI1.1, A1.2, CC7.4;

SQS queue has no redrive policy and therefore no dead-letter queue. When a consumer fails to process a message — crash, unhandled exception, missed Delete — the message becomes visible again after the visibility timeout and is reprocessed by another consumer. Without a DLQ and maxReceiveCount, the message retries until the retention period expires (default 4 days, max 14) and is then silently deleted. There is no failure record, no investigation surface, and no reprocessing capability. For event-driven architectures, silent message loss means lost transactions, inconsistent state, and missing data. Pair with CTL.SQS.DLQ.NOCONSUMER.001 (DLQ exists but is unconsumed) and CTL.SQS.DLQ.MAXRECEIVE.LOW.001 (DLQ exists but maxReceiveCount = 1).

**Remediation:** Configure a redrive policy targeting a dedicated DLQ: aws sqs set-queue-attributes --queue-url <url> --attributes RedrivePolicy='{"deadLetterTargetArn":"<dlq>", "maxReceiveCount":"5"}'. Set maxReceiveCount to 3-5 (see CTL.SQS.DLQ.MAXRECEIVE.LOW.001) and ensure the DLQ has a consumer (see CTL.SQS.DLQ.NOCONSUMER.001). FIFO queues require an FIFO DLQ; standard queues require a standard DLQ.

---

### CTL.SQS.DLQ.MAXRECEIVE.LOW.001

**SQS Queue maxReceiveCount Set to 1 — No Retry Before DLQ**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: SI-11, CP-10; soc2: A1.2, CC7.4;

SQS queue has a redrive policy whose maxReceiveCount is set to 1. The first processing failure routes the message to the dead-letter queue with no retry. Transient failures — downstream service timeouts, temporary network errors, Lambda cold starts that exceed the visibility timeout — immediately ship messages to the DLQ even though a single retry would have succeeded. The recommended floor is 3-5 retries so transient failures get a chance to resolve without filling the DLQ. maxReceiveCount = 1 is rarely intentional; when it is (strict idempotency boundaries, ordering-sensitive workloads where a retry could violate semantics) the choice should be documented on the queue.

**Remediation:** Raise maxReceiveCount to 3-5 unless there is a documented reason to keep it at 1 (aws sqs set-queue-attributes --queue-url <url> --attributes RedrivePolicy='{"deadLetterTargetArn":"<dlq>", "maxReceiveCount":"5"}'). Pair with an alarm on the DLQ's ApproximateNumberOfMessagesVisible so a sudden DLQ surge surfaces quickly regardless of the threshold.

---

### CTL.SQS.DLQ.NOCONSUMER.001

**SQS Dead-Letter Queue Has No Consumer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: AU-2, SI-11, IR-4; soc2: A1.2, CC7.4, CC7.2;

SQS queue is the target of another queue's redrive policy (so it functions as a dead-letter queue) but has no consumer — no Lambda event-source mapping, no application polling, no redrive-back pipeline. Failed messages arrive in the DLQ and sit there until the retention period expires. Nobody investigates why messages failed. Nobody reprocesses them. The DLQ exists but serves only as a delayed-deletion mechanism, not as a failure-handling surface. Same "appears-to-work" pattern as ghost-DLQ: the organization believes they have DLQ coverage, the console shows DLQ configuration, but the failure-handling chain is broken at the consumer step.

**Remediation:** Attach a consumer that processes or alerts on failed messages — typically a Lambda event-source mapping that ships each message to an incident-management system, re-enqueues it after operator review, or writes it to S3 for forensic analysis. Pair with a CloudWatch alarm on ApproximateNumberOfMessagesVisible so a sudden surge of failures triggers an immediate page even before the consumer gets to them. If the DLQ is intentionally write- only (cold storage), document the choice with a queue tag and exempt explicitly.

---

### CTL.SQS.DLQ.RETENTION.MISMATCH.001

**SQS Dead-Letter Queue Retention Shorter Than Source Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; iso_27001_2022: A.8.15; nist_800_53_r5: AU-11, SI-11; soc2: A1.2, CC7.4;

SQS dead-letter queue's MessageRetentionPeriod is shorter than its source queue's. Messages that fail processing land in the DLQ but expire there before they expire in the source — a message that fails on day 1 of a 14-day source-queue retention has only the DLQ's retention to be investigated, which can be as short as 4 days (the SQS default) or even 1 minute (the configurable floor). The DLQ should retain failed messages at least as long as the source would have retained them: the failure path must not have a shorter visibility window than the success path. AWS does not enforce this relationship; it is purely a configuration choice.

**Remediation:** Raise the DLQ's MessageRetentionPeriod to match or exceed the source queue's (aws sqs set-queue-attributes --queue-url <dlq> --attributes MessageRetentionPeriod=1209600 for 14 days). Verify against every queue using the DLQ as a target; the DLQ must satisfy the longest source-side retention among its sources.

---

### CTL.SQS.ENCRYPT.001

**SQS Queues Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SQS queues must use server-side encryption with a KMS key. Unencrypted queues expose message payloads at rest, which may contain PHI or other sensitive data.

**Remediation:** Enable SSE-KMS on the queue. Run: aws sqs set-queue-attributes --queue-url xxx --attributes KmsMasterKeyId=arn:aws:kms:...

---

### CTL.SQS.ENCRYPT.CMK.001

**SQS Queue Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.1; fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

SQS queue is encrypted but not with a customer-managed KMS key. Stave's encryption hierarchy for SQS: no encryption (worst) → SSE-SQS (SQS-managed keys, free, no key control) → SSE-KMS with the AWS-managed alias/aws/sqs (good — KMS audit trail, but no key policy or revocation control) → SSE-KMS with a CMK (best — full key policy control, audit, revocation). This control fires when the queue is using SSE-SQS or alias/aws/sqs but not a CMK. Same pattern as CTL.S3.ENCRYPT.CMK.001, CTL.RDS.ENCRYPT.CMK.001, CTL.LAMBDA.ENVIRONMENT.CMK.001.

**Remediation:** Create or select a CMK and assign it to the queue (aws sqs set-queue-attributes --queue-url <url> --attributes KmsMasterKeyId=arn:aws:kms:...:key/...). Verify the CMK's key policy allows SQS to decrypt (kms:Decrypt for the SQS service principal). The CMK gives the organization key-policy control, audit visibility via CloudTrail KMS events, and the ability to revoke access by disabling the key — none of which are available with SSE-SQS or alias/aws/sqs.

---

### CTL.SQS.ENCRYPT.TRANSPORT.001

**SQS Queue Policy Does Not Enforce HTTPS (aws:SecureTransport)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.1, 4.2; soc2: CC6.1, CC6.7;

SQS queue policy does not include a Deny statement gated on aws:SecureTransport: false. Without that deny, producers and consumers can send and receive messages over HTTP — message bodies (which often carry application data, customer identifiers, and credentials), message attributes, and SQS API parameters traverse the network unencrypted. SQS at-rest encryption (CTL.SQS.ENCRYPT.001 / .CMK.001) protects the message after it lands; this control protects the message while it is on the wire. Same enforcement pattern as CTL.S3.TLS.001 — a Deny statement with aws:SecureTransport: false is the canonical SQS HTTPS enforcement.

**Remediation:** Add a Deny statement to the queue policy: {"Effect":"Deny","Principal":"*","Action":"sqs:*", "Resource":"<queue-arn>","Condition": {"Bool":{"aws:SecureTransport":"false"}}}. Apply via aws sqs set-queue-attributes --queue-url <url> --attributes Policy=<file://policy.json>. Verify all producers and consumers use the HTTPS endpoint (sqs.<region>.amazonaws.com, not the legacy HTTP sqs-fips-... or vpce HTTP endpoints).

---

### CTL.SQS.ENCRYPTION.001

**SQS Queues Must Use Server-Side Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: SQS.1; mitre_attack: T1530; nist_800_53_r5: SC-28;

SQS queues without server-side encryption store messages in plaintext. An attacker with sqs:ReceiveMessage access can read message contents directly — messages often contain application data, event payloads, and inter-service communication that may include sensitive information. SSE-KMS encryption ensures messages are encrypted at rest and requires kms:Decrypt permission to read.

**Remediation:** Enable SSE-KMS on the queue: aws sqs set-queue-attributes --queue-url <url> --attributes KmsMasterKeyId=alias/aws/sqs

---

### CTL.SQS.GHOST.ALARM.001

**CloudWatch Alarm References Deleted SQS Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: CM-2, SI-4; soc2: CC6.1, CC7.2;

CloudWatch alarm is configured to watch SQS metrics (ApproximateNumberOfMessagesVisible, ApproximateNumberOfMessagesNotVisible, ApproximateAgeOfOldestMessage) for a queue that has been deleted. The alarm definition still exists — metric, threshold, and notification destination — but the queue is gone, so CloudWatch publishes no metrics for it. The alarm will never trigger; it monitors nothing. Operators reading the alarm inventory believe the queue is being watched. It is not.

**Remediation:** Identify the alarm (aws cloudwatch describe-alarms --alarm-names <name>) and either delete the alarm (aws cloudwatch delete-alarms --alarm-names <name>) or repoint it to a live queue if the workload is still running against a replacement. Audit the broader monitoring inventory at the same time — a deleted queue often correlates with stale dashboards and stale runbook entries.

---

### CTL.SQS.GHOST.DLQ.001

**SQS Queue Dead-Letter Queue Target Does Not Exist**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-11; soc2: CC6.1, CC8.1, A1.2;

SQS queue has a redrive policy specifying a dead-letter queue ARN that no longer exists. The DLQ was deleted but the source queue's redrive policy still names it. When a message exceeds maxReceiveCount, SQS attempts to move it to the DLQ — the DLQ doesn't exist, so the message is either silently discarded or retries indefinitely until retention expires. Either way, the DLQ safety net is broken. Same silent-failure pattern as CTL.LAMBDA.GHOST.DLQ.001 (Lambda-side DLQ ghost) but checked at the SQS source-queue surface — the two controls fire on different resources for the same underlying DLQ deletion. Same ghost-reference family as CTL.SQS.POLICY.GHOSTREF.001 (deleted principal) and CTL.SQS.GHOST.POLICY.SOURCEARN.001 (deleted sender resource).

**Remediation:** Identify the offending queue (aws sqs get-queue-attributes --queue-url <url> --attribute-names RedrivePolicy) and either recreate the DLQ at the original ARN, repoint the redrive policy to a live DLQ (aws sqs set-queue-attributes --attributes RedrivePolicy='{"deadLetterTargetArn":"<live-dlq>", "maxReceiveCount":"5"}'), or remove the redrive policy entirely if the workload no longer needs DLQ semantics. Pair with a CloudWatch alarm on ApproximateNumberOfMessagesNotVisible so a future deletion surfaces immediately.

---

### CTL.SQS.GHOST.POLICY.SOURCEARN.001

**SQS Queue Policy SourceArn References Deleted Resource**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.9; nist_800_53_r5: CM-2, CM-3, AC-3; soc2: CC6.1, CC8.1;

SQS queue policy has a condition restricting SendMessage to a specific aws:SourceArn (an SNS topic, S3 bucket, EventBridge rule, or other producer) that has been deleted. The queue is still alive; the producer it expected messages from is gone. The queue policy condition references a non-existent ARN. The queue receives no traffic from the deleted source, and any new source attempting to send is rejected by the stale sourceArn match — dead pipeline. Distinct from CTL.SQS.POLICY.GHOSTREF.001 (deleted IAM principal in the policy's Principal element): this control checks the Condition.aws:SourceArn keys, which name resources, not IAM identities.

**Remediation:** Inspect the queue policy (aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy) and either remove the stale sourceArn condition, repoint it to the actual sender that replaced the deleted resource, or delete the queue if it is no longer in use. If the sender was intentionally migrated, the policy must be updated atomically with the migration so no message-loss window exists.

---

### CTL.SQS.INCOMPLETE.001

**Complete Data Required for SQS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SQS queue properties.

**Remediation:** Ensure the extractor calls aws sqs get-queue-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.SQS.LIFECYCLE.DLQ.ORPHAN.001

**SQS Dead-Letter Queue's Source Queue Was Deleted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3; soc2: CC6.1, CC8.1;

SQS queue is configured as a dead-letter queue (it was the target of a source queue's redrive policy) but the source queue has been deleted. The DLQ persists with its policy, encryption, and any messages already accumulated from the deleted source — but will never receive new messages because nothing redrives to it. This is the DLQ-side mirror of CTL.SQS.GHOST.DLQ.001 (which detects the source queue's redrive pointing at a deleted DLQ); this control catches the inverse — the DLQ outlived its source. The orphaned DLQ often holds historical failure data that needs investigation or cleanup before deletion.

**Remediation:** Inspect the DLQ contents (aws sqs receive-message --queue-url <dlq-url> --max-number-of-messages 10) to determine whether any accumulated messages still need investigation or reprocessing. After triage — replay, archive, or accept loss — delete the DLQ (aws sqs delete-queue --queue-url <dlq-url>). If the decommission of the source was unintentional and the pipeline should be restored, recreate the source queue and re-attach the redrive policy.

---

### CTL.SQS.LIFECYCLE.DORMANT.001

**SQS Queue Has No Activity in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2, 7.2; soc2: CC6.1, CC8.1;

SQS queue has had neither send nor receive activity in more than 90 days. The queue still carries its policy, encryption, DLQ configuration, and consumer permissions — but processes no traffic. Dormant queues are latent infrastructure: the policy still authorizes producers and consumers, the consumer's IAM role still holds queue permissions, and nobody monitors the queue for anomalous messages because it is assumed to be unused. Same 90-day dormancy threshold used across Lambda, IAM, DynamoDB, CloudFront, Route 53, and KMS controls — uniform across domains.

**Remediation:** Audit the queue's CloudTrail history (SendMessage / ReceiveMessage events) to confirm true dormancy. If the queue is truly unused, delete it (aws sqs delete-queue --queue-url <url>). If the queue is held for future use, restrict the policy to a minimal principal set, attach a CloudWatch alarm on NumberOfMessagesSent so any traffic surfaces immediately, and document the planned reactivation date.

---

### CTL.SQS.LIFECYCLE.NOCONSUMER.001

**SQS Source Queue Has No Consumer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.5.30; nist_800_53_r5: CM-2, CM-3, SI-11; pci_dss_v4.0: 1.2, 7.2; soc2: CC6.1, CC8.1, A1.2;

SQS source queue has send activity (NumberOfMessagesSent > 0) but no receive activity — no Lambda event-source mapping, no application polling, no ECS task processing. Producers send messages; nobody reads them. Messages age until the retention period expires (default 4 days) and are permanently deleted. The queue accepts messages but cannot process them. Distinct from CTL.SQS.DLQ.NOCONSUMER.001 (SQS-1) which fires on dead-letter queues; this control fires on source queues (is_dlq = false) so the two never overlap. The combination "queue is producing AND has no consumer" is the data-sink shape — every message is an event/transaction/notification that the architecture intended to be processed but cannot be.

**Remediation:** Identify the original consumer for the queue (CloudTrail history of ReceiveMessage callers). If the consumer was decommissioned, decide whether the queue should also be decommissioned: producers will need to be repointed to a live queue. If the queue is the right destination, restore the consumer — typically a Lambda event-source mapping (aws lambda create-event-source-mapping --function-name <fn> --event-source-arn <queue-arn>) or an ECS task running a polling loop. Pair with CTL.SQS.ALARM.DEPTH.001 so future consumer outages surface within minutes.

---

### CTL.SQS.POLICY.CROSSACCOUNT.001

**SQS Queue Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6;

SQS queue policy grants actions to principals in external AWS accounts without an aws:PrincipalOrgID condition (or an equivalent SourceAccount restriction limited to the organization's account list). Any principal in the external account can perform the granted actions — if the external account is compromised, or leaves the organization, the queue policy still trusts it. PrincipalOrgID ensures only accounts currently in the organization can access the queue. Distinct from CTL.SQS.POLICY.PUBLIC.001 (Principal: "*") — this control fires on policies that name specific external accounts but lack an org boundary.

**Remediation:** Add aws:PrincipalOrgID restricting access to the organization's ID (o-xxxxxxxxxx). For the rare legitimate cross-org grant, use aws:PrincipalAccount with the explicit account ID and document the trust relationship. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>. Companion controls: CTL.SQS.POLICY.PUBLIC.001 covers Principal: "*"; CTL.SQS.POLICY.SNS/S3/EVENTS.NOSOURCE.001 cover service principals; this control covers specific external account principals.

---

### CTL.SQS.POLICY.DELETEBROADLY.001

**SQS Queue Policy Grants DeleteMessage to Broad Principals**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, SI-11; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6, A1.2;

SQS queue policy grants sqs:DeleteMessage to a broad principal class — Principal: "*", account root, wildcard role pattern, or cross-account principals without conditions. DeleteMessage removes individual messages from the queue. Broad DeleteMessage access enables message destruction without reading: a principal that can delete but not receive can destroy messages out from under the legitimate consumer, causing silent message loss. Similar pattern to CTL.SQS.POLICY.RECEIVEMESSAGE.BROAD.001 but on the destruction axis rather than the read axis. Less severe than CTL.SQS.POLICY.PURGE.001 (which mass-deletes the entire queue in a single call) — DeleteMessage is one-message-at-a- time but still allows targeted destruction.

**Remediation:** Restrict DeleteMessage to the consumer roles that legitimately process messages — typically the same role that holds ReceiveMessage, since the standard consume-and-delete pattern requires both. Avoid granting DeleteMessage to producer roles, monitoring roles, or cross-account principals unless there is a documented redrive-back workflow. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>.

---

### CTL.SQS.POLICY.EVENTS.NOSOURCE.001

**SQS Queue Policy Allows EventBridge Without SourceAccount**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SQS queue policy grants sqs:SendMessage to the EventBridge service principal (events.amazonaws.com) without aws:SourceAccount or aws:SourceArn condition. Any EventBridge rule in any account can deliver events to the queue. EventBridge is particularly dangerous without source restriction because rules can match arbitrary event patterns — an attacker creates a rule in their own account that matches high-volume events (CloudTrail API calls, custom events) and routes them to the target queue, flooding it. Counterpart to CTL.SQS.POLICY.SNS.NOSOURCE.001 and CTL.SQS.POLICY.S3.NOSOURCE.001 on the EventBridge surface.

**Remediation:** Add aws:SourceAccount (the account owning the legitimate rules) and ideally aws:SourceArn (each rule's ARN) to every Statement granting events.amazonaws.com SendMessage. If the queue receives events from many rules in the same account, SourceAccount alone is sufficient; if only specific rules should be authorized, list each in SourceArn. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>.

---

### CTL.SQS.POLICY.GHOSTREF.001

**SQS Queue Policy Must Not Reference Deleted Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SQS queue policies must not grant access to principal ARNs that don't exist in the IAM inventory. A recreated principal matching the ghost ARN inherits SendMessage (injection) or ReceiveMessage (interception) access. Resource-based policies evaluate ARN strings, not unique IDs.

**Remediation:** Remove the ghost principal ARN from the queue policy.

---

### CTL.SQS.POLICY.PUBLIC.001

**SQS Queue Policy Must Not Allow Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: SQS.1; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SQS queue resource policies must not grant sqs:SendMessage, sqs:ReceiveMessage, sqs:DeleteMessage, or sqs:* to Principal "*" or to unauthenticated principals without restricting via aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID conditions. Public queue access allows unauthorized message injection (sending malicious payloads to downstream consumers) or message interception (reading messages meant for internal services).

**Remediation:** Restrict the queue policy to specific account IDs, source ARNs, or add an aws:PrincipalOrgID condition. For cross-service integration (e.g., SNS → SQS), restrict via aws:SourceArn to the specific topic ARN.

---

### CTL.SQS.POLICY.PURGE.001

**SQS Queue Policy Grants PurgeQueue to Non-Admin Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-6, SI-11, SI-13; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6, A1.2;

SQS queue policy grants sqs:PurgeQueue to non-administrative principals. PurgeQueue is mass deletion — a single API call removes EVERY message from the queue, instantly, irreversibly. Purged messages bypass the DLQ. There is no recovery surface. Only queue administrators (or the SDK-default account root) should hold PurgeQueue. The control fires when PurgeQueue is granted beyond a small allowlist — to broad principal classes (account root, role-pattern wildcards), to cross-account principals, or to consumer roles that have no legitimate reason to wipe the queue.

**Remediation:** Remove sqs:PurgeQueue from non-administrative principals (consumers, producers, monitoring roles). Restrict it to a named queue-admin role or the account root. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>. If automation needs PurgeQueue (e.g. a test-environment cleanup pipeline), grant it to a specific service role rather than to an entire account or a wildcard pattern.

---

### CTL.SQS.POLICY.RECEIVEMESSAGE.BROAD.001

**SQS Queue Policy Grants ReceiveMessage to Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SQS queue policy grants sqs:ReceiveMessage to overly broad principals — Principal: "*", account root, wildcard role patterns, or cross-account principals without conditions. ReceiveMessage reads message content; broad ReceiveMessage access is broad data access. The queue is a data store — every message holds whatever the producer wrote (customer data, application events, credentials when the application passes them through). A principal with ReceiveMessage can drain the queue, reading every message until the queue is empty. Distinct from CTL.SQS.POLICY.PUBLIC.001 which fires on Principal: "*"; this control fires when the principal is named but the principal class is too broad (account root, wildcard role pattern).

**Remediation:** Replace broad principals (account root, wildcard role patterns) with the specific consumer roles or service accounts that legitimately need to read messages (typically a Lambda execution role or an EC2 instance profile). Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>. Audit consumers against the principal allowlist on a periodic cadence so decommissioned roles drop off.

---

### CTL.SQS.POLICY.S3.NOSOURCE.001

**SQS Queue Policy Allows S3 SendMessage Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SQS queue policy grants sqs:SendMessage to the S3 service principal (s3.amazonaws.com) without aws:SourceArn or aws:SourceAccount condition. Any S3 bucket in any account can configure event notifications targeting the queue and have them accepted. An attacker creates a bucket, sets up a PutObject event notification pointing at the queue ARN, and generates events — the queue receives attacker-controlled S3 event payloads. Counterpart to CTL.SQS.POLICY.SNS.NOSOURCE.001 on the S3 event-notification surface.

**Remediation:** Add aws:SourceArn (the legitimate bucket ARN) or aws:SourceAccount (the bucket-owning account) to every Statement granting s3.amazonaws.com SendMessage. Both conditions can be combined for defense in depth — sourceArn pins the specific bucket; sourceAccount blocks any bucket in foreign accounts. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>.

---

### CTL.SQS.POLICY.SNS.NOSOURCE.001

**SQS Queue Policy Allows SNS SendMessage Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SQS queue policy grants sqs:SendMessage to the SNS service principal (sns.amazonaws.com) without an aws:SourceArn or aws:SourceAccount condition. Any SNS topic in any AWS account can publish to the queue. An attacker creates an SNS topic in their own account, subscribes the queue (the subscription succeeds because the queue's policy authorizes any SNS topic), and publishes attacker-controlled payloads. Same confused- deputy pattern as CTL.LAMBDA.TRIGGER.CONFUSEDDEPUTY.001 but on the SQS receive surface.

**Remediation:** Add an aws:SourceArn condition naming the legitimate SNS topic ARN, or aws:SourceAccount restricting to the publisher account. Apply via aws sqs set-queue-attributes --attributes Policy=<file://policy.json>. Verify that every Statement granting sns.amazonaws.com SendMessage carries one of the two conditions.

---

### CTL.SQS.POLICY.SPRAWL.001

**SQS Queue Policy Has Excessive Permission Statements**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-6, CM-2; soc2: CC6.1, CC8.1;

SQS queue policy has more than ten permission statements. Each service integration adds a Statement: the SNS topic from initial setup, the S3 bucket notification from a migration project, the EventBridge rule from a monitoring pipeline, the Lambda DLQ configuration from a decommissioned function. Statements are rarely removed. The policy accumulates until it is unauditable — too many entries to review, each granting SendMessage from a different source. Same accumulation pattern as CTL.LAMBDA.POLICY.ACCUMULATED.001. The threshold of ten is a heuristic; configurable per workload.

**Remediation:** Audit the policy (aws sqs get-queue-attributes --queue-url <url> --attribute-names Policy) and remove statements for sources that no longer exist or no longer need to write to the queue. Pair the cleanup with an inventory check against CTL.SQS.GHOST.POLICY.SOURCEARN.001 to identify deleted sources still referenced. After cleanup, gate future additions through an automated policy review so the count stays under the threshold.

---

