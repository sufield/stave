# Control Reference — SNS

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.SNS.ALARM.DELETETOPIC.001

**No CloudWatch Alarm for SNS DeleteTopic**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.8.16, A.5.30; nist_800_53_r5: AU-6, IR-4, SI-4, CP-10; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, A1.2;

No CloudWatch alarm is wired to a CloudTrail metric filter on the DeleteTopic API call. DeleteTopic permanently removes the topic and all its subscriptions; if the topic is an alarm notification target, every CloudWatch alarm that references it becomes a ghost reference. Without an alarm, topic deletion is invisible until alarms fail to notify — which may be hours or days later. Companion to CTL.SNS.GHOST.ALARM.001 (SNS-1): the ghost-alarm control detects the STATE (topic already deleted, alarms reference it); this control detects the EVENT (deletion happening now), enabling immediate response before the notification chain breaks.

**Remediation:** Create a CloudTrail metric filter on eventName = DeleteTopic scoped to the topic's ARN, then a CloudWatch alarm with threshold 1 and a 60-second period so the deletion call pages on-call within seconds: aws logs put-metric-filter --filter-pattern '{ $.eventName = "DeleteTopic" && $.requestParameters.topicArn = "*<topic-name>*" }' followed by aws cloudwatch put-metric-alarm. Deletion cannot be undone, but a fast notification lets the team capture context for forensics, recreate the topic, and repoint alarm actions before the next alarm fires into a ghost reference.

---

### CTL.SNS.ALARM.DELIVERYFAILURE.001

**No CloudWatch Alarm for SNS Delivery Failures**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 4.4; fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, IR-4, IR-5; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3;

No CloudWatch alarm is wired to the SNS metric NumberOfNotificationsFailed for this topic. Delivery failures indicate that subscribers are not receiving messages — the publish API returned success (SNS accepted the message) but delivery to one or more subscribers failed: HTTP endpoint down, Lambda erroring, SQS permission denied, endpoint throttled. Without an alarm, delivery failures accumulate without notification. Companion to the per- subscription DLQ control (CTL.SNS.SUBSCRIPTION.NODLQ.001) and the delivery status logging control (CTL.SNS.DELIVERY.STATUS.DISABLED.001): the alarm provides real-time signal; the DLQ preserves the failed messages; the logging records the per-attempt detail.

**Remediation:** Create a CloudWatch alarm on AWS/SNS NumberOfNotificationsFailed dimensioned by the topic ARN with a non-zero threshold and a short evaluation period (5 minutes is a reasonable starting point): aws cloudwatch put-metric-alarm --alarm-name sns-<topic>-delivery-failures --metric-name NumberOfNotificationsFailed --namespace AWS/SNS --dimensions Name=TopicName,Value=<name> --statistic Sum --threshold 1 --period 300 --evaluation-periods 1 --comparison-operator GreaterThanOrEqualToThreshold.

---

### CTL.SNS.ALARM.PUBLISHED.001

**No CloudWatch Alarm for SNS Messages Published Spike**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.8.16; nist_800_53_r5: SI-4, IR-4; pci_dss_v4.0: 10.6; soc2: CC7.2, CC7.3;

No CloudWatch alarm monitors the SNS NumberOfMessagesPublished metric for anomalous spikes. A sudden spike may indicate upstream system failure (error events flooding the topic), confused deputy exploitation (an attacker injecting messages through an over-permissive topic policy), application bug (an infinite loop publishing notifications), or a legitimate traffic burst. Without an alarm the anomaly is invisible — by the time the team notices through downstream effects (subscriber overload, cost, throttling) the volume has already done its damage. Same anomaly-detection pattern as CTL.SQS.ALARM.SENT.001 for queues.

**Remediation:** Create a CloudWatch anomaly-detection alarm on AWS/SNS NumberOfMessagesPublished dimensioned by topic ARN. Anomaly detection adapts to the topic's normal traffic pattern; static thresholds are inappropriate because legitimate publish volume varies widely between low-traffic alarm notification topics and high-traffic event fan-out topics. Use aws cloudwatch put-metric-alarm with --threshold-metric-id pointing to an anomaly detection band.

---

### CTL.SNS.ALARM.SMSSPEND.001

**No CloudWatch Alarm for SNS SMS Spending**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-4; iso_27001_2022: A.5.30, A.8.16; nist_800_53_r5: SI-4, AU-12; pci_dss_v4.0: 10.6; soc2: CC7.2, A1.2;

No CloudWatch alarm monitors the SNS SMSMonthToDateSpentUSD metric. SNS SMS delivery incurs per-message cost that varies by destination country and can be substantially higher than the cost of any other SNS protocol. Without a spend alarm: a misconfigured application can publish thousands of SMS notifications, an attacker exploiting a confused-deputy gap can trigger SMS to every E.164 they control, a traffic burst into an SMS topic incurs proportional cost. AWS provides a monthly SMS spend limit but without an alarm the limit is hit without warning. Fires only on topics with SMS subscriptions or accounts using SNS SMS — most topics use SQS/Lambda/HTTP and SMS spend is irrelevant.

**Remediation:** Create a CloudWatch alarm on AWS/SNS SMSMonthToDateSpentUSD with a threshold below the monthly SMS spend limit (so the alarm fires before the limit is reached): aws cloudwatch put-metric-alarm --alarm-name sns-sms-spend --metric-name SMSMonthToDateSpentUSD --namespace AWS/SNS --statistic Maximum --threshold <budget-fraction> --period 3600 --evaluation-periods 1 --comparison-operator GreaterThanThreshold. Pair with the account-level monthly SMS spend limit (aws sns set-sms-attributes MonthlySpendLimit) so the alarm gives advance warning before delivery is hard-stopped.

---

### CTL.SNS.AUDIT.DATAEVENTS.001

**CloudTrail Data Events Not Enabled for SNS**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** cis_aws_v3.0: 3.2; fedramp_moderate: AU-2; hipaa: 164.312(b); iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-12; pci_dss_v4.0: 10.1, 10.2; soc2: CC7.1, CC7.2;

CloudTrail is not configured to log SNS data events (Publish). Management events (CreateTopic, DeleteTopic, SetTopicAttributes, Subscribe) are recorded by default but Publish operations are not. For alarm notification topics, data events answer the legitimacy question: was that notification published by a real CloudWatch alarm or by an attacker leveraging an over-permissive topic policy? For topics carrying business events, data events provide the per-message audit trail required for compliance regimes that require knowing who sent what. Cost note: SNS Publish data events generate moderate log volume — lower than SQS (which has both Send and Receive per message) but still significant for high-traffic topics; the control is medium severity because the cost tradeoff is real.

**Remediation:** Add an SNS data-event selector to a CloudTrail trail covering this topic: aws cloudtrail put-event-selectors --trail-name <trail> --advanced-event-selectors '[{"Name":"SNS data events","FieldSelectors": [{"Field":"eventCategory","Equals":["Data"]}, {"Field":"resources.type","Equals":["AWS::SNS::Topic"]}, {"Field":"resources.ARN","Equals":["<topic-arn>"]}]}]'. Restrict the resource ARN selector to security-sensitive topics (alarm-notification, financial-event, compliance-event topics) so the data-event volume cost stays bounded. Verify the trail's S3 destination is in the same organization with appropriate access controls.

---

### CTL.SNS.CROSSACCOUNT.SUBSCRIPTION.001

**SNS Topic Has Subscription Delivering to External Account**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SNS topic has a subscription that delivers messages to an endpoint in an external account — SQS queue in another account, Lambda function in another account, or HTTP endpoint controlled by another party. Message content crosses the account boundary on every publish. If the receiving account has different security controls (less monitoring, broader access), messages are less protected after delivery than they were inside the publishing account. Distinct from CTL.SNS.POLICY.CROSSACCOUNT.001 (SNS-2): the policy control checks who can ACT on the topic (Subscribe / Publish from external accounts); this control checks where messages are DELIVERED.

**Remediation:** Audit the cross-account subscriptions. If the delivery is intentional (centralized logging account, shared notification pipeline), confirm: (a) the receiving account has equivalent or stronger encryption / IAM / monitoring controls, (b) the messages do not contain data that violates the publishing account's data-residency or compartmentalization requirements, and (c) the cross-account subscription is documented and authorized. If the delivery is unintentional, unsubscribe the external endpoint and route through an account-internal relay if cross-account delivery is needed.

---

### CTL.SNS.DATAPROTECTION.001

**SNS Topic Has No Data Protection Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-28; scs_c02: 8.12; soc2: CC6.7;

An SNS topic has no data protection policy configured. Data protection policies detect and optionally redact or deny messages containing sensitive data (PII, PHI, financial data). Without a policy, sensitive data published to the topic flows to all subscribers unfiltered.

**Remediation:** Add a data protection policy: aws sns put-data-protection-policy --resource-arn <topic-arn> --data-protection-policy file://policy.json.

---

### CTL.SNS.DELIVERY.LOG.RETENTION.001

**SNS Delivery Status Log Group Has Insufficient Retention**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.312(b); nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

SNS delivery status CloudWatch log group has no retention policy (logs retained forever — costly) or retention shorter than 365 days (forensic horizon insufficient). Same baseline pattern as CTL.LAMBDA.LOG.RETENTION.001 and CTL.RDS.LOG.RETENTION.001 — consistent retention floor for every CloudWatch log group across the catalog. Fires only when delivery status logging is enabled (otherwise CTL.SNS.DELIVERY.STATUS.DISABLED.001 covers the wider failure of having no logs at all).

**Remediation:** Set retentionInDays on the delivery status log group to 365 or higher (3653 = 10 years for long-retention compliance workloads). Use put-retention-policy on the log group, or set retention via the CloudFormation/ Terraform resource that owns it. The 365-day floor matches the catalog-wide retention baseline used by Lambda, RDS, ECS, API Gateway, and Route 53 query logs.

---

### CTL.SNS.DELIVERY.STATUS.DISABLED.001

**SNS Topic Has No Delivery Status Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-6, AU-11; pci_dss_v4.0: 10.1, 10.7; soc2: CC7.1, CC7.2;

SNS topic does not have delivery status logging enabled for any subscription protocol (HTTP/HTTPS, SQS, Lambda, application/mobile push). Without delivery status logging there is no SNS-side record of whether messages reached subscribers — delivery successes and failures are invisible. A subscription to a failing endpoint (HTTP timeout, Lambda error, SQS permission denied) fails silently; the publish API returned success, the subscriber never received the message, and nothing was logged in between. The publisher has no signal of delivery failure; the only way to know whether messages reached subscribers is to inspect the subscriber side, which is impossible if the subscriber is itself failing.

**Remediation:** Enable delivery status logging per protocol on the topic: aws sns set-topic-attributes --topic-arn <arn> --attribute-name HTTPSuccessFeedbackRoleArn --attribute-value <role-arn> (and FailureFeedbackRoleArn, SuccessFeedbackSampleRate). Repeat for SQS, Lambda, and Application protocols by setting SQSSuccessFeedbackRoleArn, LambdaSuccessFeedbackRoleArn, etc. Each protocol is configured independently; enable logging for every protocol that the topic uses. Delivery status logs go to CloudWatch Logs and record outcome, error code, and delivery time.

---

### CTL.SNS.DELIVERY.STATUS.PARTIAL.001

**SNS Topic Has Delivery Status Logging for Some Protocols But Not All**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-6; pci_dss_v4.0: 10.1, 10.7; soc2: CC7.1, CC7.2;

SNS topic has delivery status logging enabled for some subscription protocols but not all. For example: delivery logging is configured for SQS subscriptions but not for HTTP/HTTPS subscriptions, or for Lambda but not for SQS. Delivery failures on the unlogged protocols are invisible while the logged protocols have full visibility — the gap is systematically uneven across protocols, not absent. Distinct from CTL.SNS.DELIVERY.STATUS.DISABLED.001 (no logging at all): this control fires when at least one protocol IS logged but at least one protocol used by the topic is NOT.

**Remediation:** For each subscription_protocol used by the topic, configure the matching SuccessFeedbackRoleArn and FailureFeedbackRoleArn on the topic. Aim for parity: every protocol the topic delivers to should record delivery outcomes. Inspect properties.messaging.sns.unlogged_protocols to identify which protocols are missing coverage.

---

### CTL.SNS.ENCRYPT.001

**SNS Topics Must Be Encrypted with KMS**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(2)(iv); soc2: CC6.7;

SNS topics must use server-side encryption with a KMS key. Unencrypted topics expose message payloads at rest, which may contain PHI or other sensitive notification data.

**Remediation:** Enable SSE-KMS on the topic. Run: aws sns set-topic-attributes --topic-arn xxx --attribute-name KmsMasterKeyId --attribute-value arn:aws:kms:...

---

### CTL.SNS.ENCRYPT.CMK.001

**SNS Topic Not Encrypted with Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.1; fedramp_moderate: SC-12; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.8.24; nist_800_53_r5: SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5; soc2: CC6.1, CC6.7;

SNS topic is encrypted, but with the AWS-managed alias alias/aws/sns instead of a customer-managed KMS key. The AWS-managed alias gives KMS audit visibility and at-rest encryption but no key-policy control, no audit visibility against an account-owned key, and no ability to revoke access by disabling the key. Stave's encryption hierarchy for SNS: no encryption (worst) → SSE with alias/aws/sns (good) → SSE with a CMK (best). Same pattern as CTL.S3.ENCRYPT.CMK.001, CTL.RDS.ENCRYPT.CMK.001, CTL.LAMBDA.ENVIRONMENT.CMK.001, CTL.SQS.ENCRYPT.CMK.001.

**Remediation:** Create or select a CMK and assign it to the topic (aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value arn:aws:kms:...:key/...). Verify the CMK's key policy allows SNS to decrypt for the publisher and subscribers that need the message content.

---

### CTL.SNS.ENCRYPT.TRANSPORT.001

**SNS Topic Policy Does Not Enforce HTTPS (aws:SecureTransport)**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 2.1.2; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.1, 4.2; soc2: CC6.1, CC6.7;

SNS topic policy does not include a Deny statement gated on aws:SecureTransport: false. Without that deny, publishers can call sns:Publish over HTTP — message body, message attributes, and SNS API parameters traverse the network unencrypted. SNS at-rest encryption (CTL.SNS.ENCRYPT.001 / .CMK.001) protects the message after it lands in the topic; this control protects the message while it is on the wire from publisher to SNS. Same enforcement pattern as CTL.S3.TLS.001 and CTL.SQS.ENCRYPT.TRANSPORT.001 — a Deny statement with aws:SecureTransport: false is the canonical SNS HTTPS enforcement.

**Remediation:** Add a Deny statement to the topic policy: {"Effect":"Deny","Principal":"*","Action":"sns:*", "Resource":"<topic-arn>","Condition": {"Bool":{"aws:SecureTransport":"false"}}}. Apply via aws sns set-topic-attributes --topic-arn <arn> --attribute-name Policy --attribute-value <policy-json>. Verify all publishers use the HTTPS endpoint.

---

### CTL.SNS.ENCRYPTION.001

**SNS Topics Must Use Server-Side Encryption**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** aws_security_hub: SNS.1; mitre_attack: T1530; nist_800_53_r5: SC-28;

SNS topics without server-side encryption transmit and store messages in plaintext. An attacker with sns:Subscribe access can create a subscription to harvest all messages flowing through the topic. Messages often contain application events, alerts, and inter-service data that may include sensitive information. SSE-KMS encryption ensures messages are encrypted at rest and requires kms:Decrypt permission to read.

**Remediation:** Enable SSE-KMS on the topic: aws sns set-topic-attributes --topic-arn <arn> --attribute-name KmsMasterKeyId --attribute-value alias/aws/sns

---

### CTL.SNS.FIFO.NONFIFO.SUBSCRIPTION.001

**FIFO SNS Topic Has Subscription to Non-FIFO SQS Queue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-10; iso_27001_2022: A.8.32; nist_800_53_r5: SI-10; pci_dss_v4.0: 10.2; soc2: CC6.1, PI1.1;

FIFO SNS topic has a subscription delivering to a standard (non-FIFO) SQS queue. FIFO topics guarantee message ordering and deduplication; standard SQS queues guarantee neither. The FIFO ordering guarantee is broken at the subscription boundary — messages arrive at the standard queue in publish order but the queue may deliver them out of order to consumers. Applications that rely on FIFO semantics (event sourcing, state-machine transitions, transaction sequencing) silently lose ordering at this hop. Fires only on FIFO topics; standard topic → standard queue is fine.

**Remediation:** Either: (a) replace the standard SQS queue with a FIFO SQS queue (queue name must end in .fifo, FifoQueue=true, ContentBasedDeduplication or per-message group ID configured) and resubscribe the topic; or (b) if FIFO ordering is not actually required, change the SNS topic from FIFO to standard, accepting that ordering is not preserved end-to-end. Mixed topologies (FIFO topic + standard queue) have no correct semantics — the FIFO promise is unenforced past the topic.

---

### CTL.SNS.GHOST.ALARM.001

**CloudWatch Alarm Action References Deleted SNS Topic**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** cis_aws_v3.0: 4.1, 4.13; fedramp_moderate: SI-4; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, CM-3, IR-4, SI-4; pci_dss_v4.0: 10.6, 10.7; soc2: CC7.2, CC7.3, CC8.1;

CloudWatch alarm has an action (AlarmActions, OKActions, or InsufficientDataActions) that references an SNS topic which has been deleted. The alarm fires; the action attempts to publish to the deleted topic; the publish fails; nobody is notified. This is the notification-chain ghost — the most impactful ghost reference after KMS pending-deletion. It doesn't break a single service: it breaks the detection-to- response chain for every alarm in the account that routes through this topic. Every other alarm control across the catalog (RDS, Lambda, ECS, API Gateway, CloudFront, DynamoDB, SQS, Route 53, KMS) depends on a working SNS topic to deliver. When the topic is gone, the alarms fire and the notifications go nowhere. The detection works perfectly. The notification is silently broken.

**Remediation:** Identify the alarm (aws cloudwatch describe-alarms --alarm-names <name>) and repoint the action to a live SNS topic (aws cloudwatch put-metric-alarm --alarm-name <name> --alarm-actions <live-topic-arn>). Audit every alarm in the account against the topic inventory at the same time — a deleted topic typically had multiple alarms pointing at it. Add a CloudWatch metric on AWS/SNS NumberOfMessagesPublished == 0 for every notification topic so accidental deletions surface immediately.

---

### CTL.SNS.GHOST.POLICY.SOURCEARN.001

**SNS Topic Policy SourceArn References Deleted Resource**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.9; nist_800_53_r5: CM-2, CM-3, AC-3; soc2: CC6.1, CC8.1;

SNS topic policy has a condition restricting Publish to a specific aws:SourceArn (S3 bucket, CloudWatch alarm, EventBridge rule, or other publisher) that has been deleted. The policy still names the deleted resource. The topic is alive and authorized to receive messages from a publisher that no longer exists. Distinct from CTL.SNS.POLICY.GHOSTREF.001 (which checks the policy's Principal element for deleted IAM principals); this control checks the Condition.aws:SourceArn keys, which name resources, not identities. Same pattern as CTL.SQS.GHOST.POLICY.SOURCEARN.001 on the SQS side.

**Remediation:** Inspect the topic policy (aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy') and either remove the stale sourceArn condition, repoint it to the actual sender that replaced the deleted resource, or delete the topic if it is no longer in use.

---

### CTL.SNS.GHOST.SUBSCRIPTION.DLQ.001

**SNS Subscription Dead-Letter Queue Does Not Exist**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-11; soc2: CC6.1, CC7.4, A1.2;

SNS subscription has a redrive policy specifying a dead- letter queue ARN that does not exist. When delivery to the subscription endpoint fails, SNS attempts to send the failed message to the DLQ; the DLQ is gone, so the failed message is silently discarded. Same silent-failure pattern as CTL.SQS.GHOST.DLQ.001 but for SNS subscription delivery failures rather than SQS source-queue failures. This is a double-failure setup: the primary subscription path may fail, and the safety-net DLQ is also broken.

**Remediation:** Recreate the DLQ at the original ARN, repoint the subscription's redrive policy to a live DLQ (aws sns set-subscription-attributes --subscription-arn <sub> --attribute-name RedrivePolicy --attribute-value '{"deadLetterTargetArn":"<live-dlq>"}'), or remove the redrive policy entirely if the workload accepts permanent loss on delivery failure (rare — document the choice).

---

### CTL.SNS.GHOST.SUBSCRIPTION.HTTP.001

**SNS Subscription Delivers to Unreachable HTTP/HTTPS Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, IR-4; soc2: CC6.1, CC7.4, CC8.1;

SNS topic has a subscription delivering to an HTTP or HTTPS endpoint that is persistently unreachable — the server was decommissioned, the URL changed, the certificate expired, or the endpoint returns errors on every delivery attempt. Unlike SQS and Lambda ghosts (where the AWS resource is gone), HTTP ghosts are usually partial: the endpoint may exist but never respond, or respond with errors. The control fires on PERSISTENT failure (sustained low success rate), not on transient outages — observers should threshold delivery_success_rate below a workload-specific level (e.g., 50% over the past 24h).

**Remediation:** Inspect the subscription's delivery-status logs in CloudWatch (the AWS/SNS NumberOfNotificationsFailed metric scoped to the subscription) to confirm the failure pattern. If the endpoint was decommissioned, unsubscribe; if the URL changed, repoint the subscription. Add a CloudWatch alarm on the failure metric so future endpoint regressions surface within minutes rather than days.

---

### CTL.SNS.GHOST.SUBSCRIPTION.LAMBDA.001

**SNS Subscription Delivers to Deleted Lambda Function**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, IR-4; soc2: CC6.1, CC8.1, CC7.4;

SNS topic has a subscription whose endpoint is a Lambda function ARN that no longer exists. Every publish triggers a delivery attempt to the deleted function; every delivery fails. After the protocol's retry policy exhausts (three retries over 20 seconds for Lambda), the message is either redirected to the subscription's DLQ or discarded. Same silent-failure pattern as CTL.SNS.GHOST.SUBSCRIPTION.SQS.001 but on the SNS-to-Lambda fan-out path.

**Remediation:** Recreate the Lambda function at the original ARN, repoint the subscription to a live function, or unsubscribe. If the function was decommissioned intentionally, also remove the related Lambda resource policy entry that authorized SNS invocation.

---

### CTL.SNS.GHOST.SUBSCRIPTION.SQS.001

**SNS Subscription Delivers to Deleted SQS Queue**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, IR-4; soc2: CC6.1, CC8.1, CC7.4;

SNS topic has a subscription whose endpoint is an SQS queue ARN that no longer exists in the inventory. The subscription persists; SNS attempts delivery on every publish; every delivery fails because the queue is gone. After the protocol's retry policy exhausts (three retries over 20 seconds for SQS), the message is either redirected to the subscription's DLQ (if one is configured) or discarded permanently. The topic appears to have a healthy subscriber. Messages are silently undelivered. Same ghost-reference pattern as CTL.SQS.GHOST.DLQ.001 but on the SNS side of the SNS-to-SQS fan-out.

**Remediation:** Either recreate the SQS queue at the original ARN, or repoint the subscription to a live queue (aws sns subscribe --topic-arn <topic> --protocol sqs --notification-endpoint <live-queue-arn>), or unsubscribe (aws sns unsubscribe --subscription-arn <subscription>) if the workload no longer needs the integration. Pair with a delivery-status- failure alarm on the topic so future endpoint deletions surface immediately.

---

### CTL.SNS.INCOMPLETE.001

**Complete Data Required for SNS Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required SNS topic properties.

**Remediation:** Ensure the extractor calls aws sns get-topic-attributes and maps the KmsMasterKeyId to the messaging.encryption observation properties.

---

### CTL.SNS.LIFECYCLE.DORMANT.001

**SNS Topic Has No Publish Activity in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.32; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2, 7.2; soc2: CC6.1, CC8.1;

SNS topic has no messages published in more than 90 days. The topic exists with its policy, subscriptions, encryption, and delivery configuration — but receives no messages. Dormant topics are latent infrastructure: the topic policy still permits publishing, the subscriptions still exist (and may reference deleted endpoints — ghost subscriptions), and nobody monitors for anomalous publishes. Same 90-day dormancy threshold used across Lambda, IAM, DynamoDB, CloudFront, Route 53, KMS, and SQS controls — uniform across domains.

**Remediation:** Audit the topic's CloudTrail history (Publish events) to confirm true dormancy. If the topic is truly unused, delete it (aws sns delete-topic --topic-arn <arn>) along with all its subscriptions. If the topic is held for future use, restrict the policy to a minimal principal set, remove stale subscriptions, attach a CloudWatch alarm on NumberOfMessagesPublished so any publish activity surfaces immediately, and document the planned reactivation date.

---

### CTL.SNS.LIFECYCLE.NOSUBSCRIBERS.001

**SNS Topic Has No Subscriptions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2; soc2: CC6.1, CC8.1;

SNS topic exists but has zero subscriptions. Messages published to the topic go nowhere — no SQS queue, no Lambda function, no HTTP endpoint, no email, no SMS. The topic accepts messages (Publish succeeds) but doesn't deliver them. This typically indicates: the topic was created but subscriptions were never added (deployment incomplete), all subscriptions were removed (decommissioning incomplete — topic left behind), or the topic is used only for its policy (unusual). If the topic is referenced by a CloudWatch alarm action, alarms publish to a topic with no delivery — the same effect as a ghost alarm action, but the topic still exists.

**Remediation:** Determine the topic's intended purpose. If the topic was created for a deployment that never completed, finish the deployment by adding the intended subscriptions. If the topic was decommissioned but left behind, delete it and update any CloudWatch alarm actions that reference it. If the topic is referenced by alarm actions, repoint those alarms to a topic with subscribers immediately — alarms that publish here today are silently lost.

---

### CTL.SNS.LIFECYCLE.ORPHAN.ALARM.001

**SNS Topic Used for CloudWatch Alarm Notifications But Referenced Alarm Deleted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16; nist_800_53_r5: CM-2, CM-3, SA-22; pci_dss_v4.0: 1.2; soc2: CC6.1, CC8.1;

SNS topic was the notification target for a CloudWatch alarm that has been deleted. The topic still exists with its subscriptions (Slack webhook, PagerDuty endpoint, email distribution list) but the alarm that published to it no longer exists. The topic serves no notification purpose — it exists only because the alarm was deleted without cleaning up the notification chain. Inverse perspective of CTL.SNS.GHOST.ALARM.001 (SNS-1): GHOST.ALARM checks the alarm side (alarm action references a deleted topic); ORPHAN.ALARM checks the topic side (topic was an alarm target, alarm has been deleted). Both can exist simultaneously because they check different resources.

**Remediation:** Audit the topic's referencing alarms; if all referencing alarms have been deleted and no new alarms are planned to use the topic, delete the topic (aws sns delete-topic --topic-arn <arn>) and clean up its subscriptions. If a replacement alarm is planned, document the dependency so the topic isn't deleted before the new alarm is wired. Pair this control with CTL.SNS.GHOST.ALARM.001 — together they identify both sides of the broken notification-chain pattern.

---

### CTL.SNS.LIFECYCLE.UNCONFIRMED.001

**SNS Topic Has Only Unconfirmed Subscriptions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; iso_27001_2022: A.5.16, A.8.16; nist_800_53_r5: CM-2, CM-3, SI-4; pci_dss_v4.0: 1.2, 10.6; soc2: CC6.1, CC7.2, CC8.1;

SNS topic has subscriptions but ALL of them are in PendingConfirmation state — none are confirmed. For HTTP/HTTPS and email subscriptions, the endpoint owner must confirm the subscription before SNS delivers messages. If every subscription is pending, the topic accepts messages but delivers to nobody — same delivery effect as having no subscriptions, but with the appearance of having subscribers (subscription count > 0). This is the worst observability failure on the notification chain: the topic appears configured (auditor sees "5 subscribers") yet delivers zero messages.

**Remediation:** For each pending subscription, contact the endpoint owner to confirm the subscription request. HTTP/HTTPS endpoints confirm by sending a request to the SubscribeURL provided in the SubscriptionConfirmation message; email endpoints confirm by clicking the confirmation link. If the endpoint owner cannot or will not confirm, delete the pending subscription (aws sns unsubscribe --subscription-arn <arn>) so the topic accurately reflects its actual subscriber count. Audit alarm actions and other consumers of this topic — they are silently failing.

---

### CTL.SNS.POLICY.CLOUDWATCH.NOSOURCE.001

**SNS Topic Policy Allows CloudWatch / EventBridge Publish Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, AC-4, SI-4; pci_dss_v4.0: 1.2, 7.1, 10.6; soc2: CC6.1, CC6.6, CC7.2;

SNS topic policy grants sns:Publish to the CloudWatch service principal (cloudwatch.amazonaws.com) or the EventBridge service principal (events.amazonaws.com) without aws:SourceArn or aws:SourceAccount conditions. Any CloudWatch alarm or EventBridge rule in any account can publish to the topic. Particularly dangerous for alarm-notification topics: an attacker can inject fake alarm notifications — fake ALARM states (causing alert fatigue), fake OK states (suppressing real alarm responses), or crafted payloads that trigger automated remediation. Counterpart to CTL.SNS.POLICY.S3.NOSOURCE.001 on the alarm/event surface.

**Remediation:** Add aws:SourceArn (each legitimate alarm or rule ARN) or aws:SourceAccount (the publisher account) to every Statement granting cloudwatch.amazonaws.com or events.amazonaws.com Publish. For alarm-notification topics, the ARN allowlist is preferred — the publisher set is small and stable, and the explicit list rejects any alarm not on it.

---

### CTL.SNS.POLICY.CROSSACCOUNT.001

**SNS Topic Policy Grants Cross-Account Access Without Organizational Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-3, AC-4, AC-6; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6;

SNS topic policy grants actions to principals in external AWS accounts without an aws:PrincipalOrgID condition. Any principal in the external account can perform the granted actions; if the account leaves the organization, access persists. For sns:Publish, the external account can inject messages into the notification pipeline. For sns:Subscribe, the external account can subscribe and receive every future message. Distinct from CTL.SNS.POLICY.PUBLIC.001 (Principal: "*") — this control fires on policies that name specific external accounts but lack an org boundary. Same shape as CTL.SQS.POLICY.CROSSACCOUNT.001 on the notification side.

**Remediation:** Add aws:PrincipalOrgID restricting access to the organization's ID. For the rare legitimate cross-org grant, use aws:PrincipalAccount with the explicit account ID and document the trust relationship.

---

### CTL.SNS.POLICY.DELETETOPIC.BROAD.001

**SNS Topic Policy Grants DeleteTopic to Non-Admin Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-6, SI-11, SI-13, IR-4; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6, A1.2;

SNS topic policy grants sns:DeleteTopic to non-administrative principals. DeleteTopic permanently removes the topic and every subscription attached to it. Cascading impact: every CloudWatch alarm referencing the topic instantly becomes a ghost reference (CTL.SNS.GHOST.ALARM.001), so a single DeleteTopic call breaks alerting for every alarm that routed through it. This is the SNS analogue of CTL.SQS.POLICY.PURGE.001 — but worse, because it also destroys the subscription topology, not just the queued data. Only topic administrators (or the SDK-default account root) should hold DeleteTopic.

**Remediation:** Restrict sns:DeleteTopic to a named topic-admin role or the account root. Audit the policy (aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy') and remove DeleteTopic from consumer roles, integration roles, and cross-account principals. If automation needs DeleteTopic (e.g., an environment-teardown pipeline), grant it to a specific service role rather than to an entire account or wildcard pattern.

---

### CTL.SNS.POLICY.GHOSTREF.001

**SNS Topic Policy Must Not Reference Deleted Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

SNS topic policies must not grant access to principal ARNs that don't exist in the IAM inventory. A recreated principal matching the ghost ARN inherits Publish (injection) or Subscribe (interception) access. Resource-based policies evaluate ARN strings, not unique IDs.

**Remediation:** Remove the ghost principal ARN from the topic policy.

---

### CTL.SNS.POLICY.LAMBDA.NOSOURCE.001

**SNS Topic Policy Allows Lambda Publish Without SourceArn**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SNS topic policy grants sns:Publish to the Lambda service principal (lambda.amazonaws.com) without aws:SourceArn or aws:SourceAccount conditions. Any Lambda function in any account can publish to the topic. Less common than S3/CloudWatch integration patterns — Lambda functions usually publish via the SDK using their execution role's credentials, not as the service principal — so this control is rated medium severity. Where it does occur, the exposure is the same: cross-account confused deputy on the publish path.

**Remediation:** Add aws:SourceArn (the legitimate function ARN) or aws:SourceAccount (the function-owning account) to every Statement granting lambda.amazonaws.com Publish. If the topic should not accept Lambda service-principal publishes at all (i.e., Lambdas in your account use their execution role's identity to publish), remove the Lambda principal entirely.

---

### CTL.SNS.POLICY.PUBLIC.001

**SNS Topic Policy Must Not Allow Public Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: SNS.1; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

SNS topic resource policies must not grant sns:Subscribe, sns:Publish, or sns:* to Principal "*" or to unauthenticated principals without restricting via aws:SourceArn, aws:SourceAccount, or aws:PrincipalOrgID conditions. Public topic access allows unauthorized subscription (receiving all published messages) or publishing (injecting messages that reach all subscribers, potentially triggering downstream Lambda functions, SQS queues, or HTTP endpoints).

**Remediation:** Restrict the topic policy to specific account IDs, source ARNs, or add an aws:PrincipalOrgID condition. For cross-service integration (e.g., S3 event → SNS), restrict via aws:SourceArn to the specific source ARN.

---

### CTL.SNS.POLICY.S3.NOSOURCE.001

**SNS Topic Policy Allows S3 Publish Without SourceArn**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.9; nist_800_53_r5: AC-3, AC-4, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SNS topic policy grants sns:Publish to the S3 service principal (s3.amazonaws.com) without an aws:SourceArn or aws:SourceAccount condition. Any S3 bucket in any AWS account can configure event notifications targeting the topic and have them accepted. Same confused-deputy pattern as CTL.SQS.POLICY.S3.NOSOURCE.001 — but the SNS version is more dangerous because the topic fans out: the attacker's payload reaches every subscribed SQS queue, Lambda function, and HTTP endpoint.

**Remediation:** Add aws:SourceArn (the legitimate bucket ARN) or aws:SourceAccount (the bucket-owning account) to every Statement granting s3.amazonaws.com Publish. Both conditions can be combined for defense in depth — sourceArn pins the specific bucket; sourceAccount blocks any bucket in foreign accounts.

---

### CTL.SNS.POLICY.SETTOPICATTRS.BROAD.001

**SNS Topic Policy Grants SetTopicAttributes to Non-Admin Principals**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-6, AC-3, CM-3; pci_dss_v4.0: 1.2, 7.1, 7.2; soc2: CC6.1, CC6.6;

SNS topic policy grants sns:SetTopicAttributes to non- administrative principals. SetTopicAttributes can modify the topic's access policy (grant arbitrary principals Publish or Subscribe), encryption settings (disable SSE), delivery policy (change retry behavior), and display name. A principal with SetTopicAttributes can effectively take over the topic by editing its policy to grant themselves any action — a privilege-escalation primitive on the notification surface. Only topic administrators should hold this permission.

**Remediation:** Restrict sns:SetTopicAttributes to a named topic-admin role or the account root. Audit the policy (aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy') and remove SetTopicAttributes from any non-admin principal. Add CloudTrail metric-filter monitoring on the SetTopicAttributes API event so unexpected modifications surface in real time.

---

### CTL.SNS.POLICY.SPRAWL.001

**SNS Topic Policy Has Excessive Permission Statements**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.5.15, A.5.19; nist_800_53_r5: AC-6, CM-2; soc2: CC6.1, CC8.1;

SNS topic policy has more than ten permission statements. Each service integration adds a Statement: the S3 bucket notification, the CloudWatch alarm action, the EventBridge rule target, the cross-account subscription. Statements are rarely removed. The policy accumulates until the access surface is unauditable — too many entries to review with confidence, each granting Publish or Subscribe from a different surface. Same accumulation pattern as CTL.SQS.POLICY.SPRAWL.001 and CTL.LAMBDA.POLICY.ACCUMULATED.001; threshold of ten is consistent across the three resource-policy sprawl controls.

**Remediation:** Inspect the policy (aws sns get-topic-attributes --topic-arn <arn> --query 'Attributes.Policy') and remove statements for sources that no longer exist or no longer need to publish/subscribe. Pair with CTL.SNS.GHOST.POLICY.SOURCEARN.001 to identify deleted sources still referenced. After cleanup, gate future additions through an automated policy review so the count stays under the threshold.

---

### CTL.SNS.POLICY.SUBSCRIBE.BROAD.001

**SNS Topic Policy Grants Subscribe to Broad Principals**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: AC-3; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.6;

SNS topic policy grants sns:Subscribe to overly broad principals — Principal: "*", account root, wildcard role patterns, or cross-account principals without conditions. Subscribe creates a subscription that receives EVERY future message published to the topic. Broad Subscribe access is data-exfiltration capability: the attacker does not need to read existing messages — they receive every new one until the subscription is removed. Distinct from CTL.SNS.POLICY.PUBLIC.001 (Principal: "*"); this control fires when the principal is named but the principal class is too broad (account root, wildcard role pattern).

**Remediation:** Replace broad principals (account root, wildcard role patterns) with the specific service accounts or roles that legitimately need to subscribe (typically a small fixed set: the Lambda execution role, the SQS poller's role, the third-party webhook integration). Audit subscribers periodically against the principal allowlist so decommissioned roles drop off.

---

### CTL.SNS.SIGNATURE.SHA1.001

**SNS Topics Must Use SHA256 Message Signing**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1;

SNS topics must use SignatureVersion 2 (SHA256) for message signing, not SignatureVersion 1 (SHA1). SHA1 is cryptographically weakened — practical collision attacks exist since 2017 (SHAttered). SNS message signatures allow subscribers to verify that a message originated from SNS and was not tampered with in transit. A SHA1-signed message can be forged by an attacker who can produce a collision, allowing spoofed notifications to endpoints that verify signatures. AWS defaults new topics to SHA1 (SignatureVersion 1) unless explicitly set to 2, so any topic created without specifying the attribute uses the weaker algorithm. This is a silent unsafe default — the topic appears functional but its message authentication is cryptographically degraded.

**Remediation:** Set the topic's SignatureVersion attribute to 2 (SHA256): aws sns set-topic-attributes --topic-arn <arn> --attribute-name SignatureVersion --attribute-value 2. Verify that all subscribers that check message signatures support SHA256 verification before switching.

---

### CTL.SNS.SUBSCRIPTION.HTTP.001

**SNS Subscription Uses HTTP (Not HTTPS) for Message Delivery**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** cis_aws_v3.0: 1.20; fedramp_moderate: SC-8; hipaa: 164.312(e)(1); iso_27001_2022: A.8.20; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.1, 4.2; soc2: CC6.1, CC6.7;

SNS subscription delivers messages to an HTTP endpoint — not HTTPS. Message body, message attributes, and SNS metadata are transmitted in plaintext from SNS to the endpoint. If messages contain PII, credentials, application events, or system alerts, the content is readable by anyone on the network path between AWS's SNS infrastructure and the endpoint. The topic itself may be encrypted at rest; delivery to HTTP defeats the at-rest protection. Same false-encryption pattern as CTL.S3.CDN.TRANSPORT, CTL.APIGATEWAY.INTEGRATION.HTTP, and CTL.CLOUDFRONT.ORIGIN.HTTP — at-rest encryption without in-transit encryption protects only the resting state.

**Remediation:** Re-create the subscription against the HTTPS form of the endpoint (aws sns subscribe --topic-arn <topic> --protocol https --notification-endpoint https://...) and unsubscribe the HTTP form. If the receiver only supports HTTP, terminate TLS on a fronting load balancer or API gateway and target the TLS endpoint from SNS. Pair with CTL.SNS.ENCRYPT.TRANSPORT.001 so the topic policy also rejects plaintext publish operations end-to-end.

---

### CTL.SNS.SUBSCRIPTION.NODLQ.001

**SNS Subscription Has No Dead-Letter Queue for Failed Deliveries**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-11; iso_27001_2022: A.5.30, A.8.32; nist_800_53_r5: SI-11, CP-10, AU-2; soc2: PI1.1, A1.2, CC7.4;

SNS subscription does not have a redrive policy (dead-letter queue) configured. When delivery fails — endpoint down, Lambda error, SQS queue full, HTTP timeout — SNS retries according to the protocol's delivery policy. After all retries exhaust the message is permanently discarded; there is no DLQ, no preservation, no investigation. Same severity rationale as CTL.SQS.DLQ.001 (no DLQ on the source queue): without a failure-preservation surface, every delivery failure becomes silent message loss.

**Remediation:** Attach a redrive policy targeting a dedicated DLQ (aws sns set-subscription-attributes --subscription-arn <sub> --attribute-name RedrivePolicy --attribute-value '{"deadLetterTargetArn":"<dlq-arn>"}'). The DLQ should have a consumer (so failed messages are investigated, not just stored — see CTL.SQS.DLQ.NOCONSUMER.001) and a depth alarm (CTL.SQS.ALARM.DLQ.DEPTH.001) so accumulation surfaces immediately.

---

