# Control Reference — LAMBDA

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.LAMBDA.ALARM.DURATION.001

**Lambda Function Must Have a CloudWatch Alarm on Duration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

Lambda functions must have a CloudWatch alarm on the Duration metric, threshold set near the configured function timeout. A function with a 30-second timeout that regularly executes for 25 seconds is approaching its limit — any incremental downstream latency, payload size growth, or cold-start variability tips it into timeout-class errors. Duration alarms catch the approaching-cliff condition before it becomes a cliff: by the time the function starts timing out, the real failure is already in production. The alarm threshold should fire when sustained duration exceeds 80% of the configured timeout, giving response time before the function is failing outright.

**Remediation:** Create a CloudWatch alarm on AWS/Lambda Duration with threshold at 80% of the function's configured timeout, and an SNS notification action.

---

### CTL.LAMBDA.ALARM.ERRORS.001

**Lambda Function Must Have a CloudWatch Alarm on Errors**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; pci_dss_v4.0: 10.4.1; soc2: CC7.2;

Lambda functions must have a CloudWatch alarm on the Errors metric. Errors counts invocations that result in a function error — runtime exceptions, timeouts, out-of-memory kills, missing handler. Without an alarm, errors accumulate in CloudWatch metrics with no notification path. A function that begins failing 100% of invocations — from a code bug, a downstream outage, a permission drift, or a ghost reference — fails repeatedly and silently. The Errors graph exists, but nobody watches it in real time. The first signal is a downstream user complaint or a reconciliation gap discovered hours later. The Errors alarm is the single most important serverless alarm — every other Lambda alarm is secondary to knowing that the function is failing.

**Remediation:** Create a CloudWatch alarm on AWS/Lambda Errors with an SNS notification action — aws cloudwatch put-metric-alarm --metric-name Errors --namespace AWS/Lambda --dimensions Name=FunctionName,Value=<fn>.

---

### CTL.LAMBDA.ALARM.ITERATORAGE.001

**Stream-Triggered Lambda Must Have an IteratorAge Alarm**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

Lambda functions triggered by Kinesis or DynamoDB Streams must have a CloudWatch alarm on the IteratorAge metric. IteratorAge measures how far behind the function is in processing the stream — a growing iterator age means the function cannot keep up with event volume. Events are processed with increasing delay; eventually records expire from the stream before the function reaches them and are lost. Without the alarm, the only signal is a downstream consumer noticing stale data. The control fires only on functions with stream-type triggers (Kinesis, DynamoDB Streams) — IteratorAge does not exist for SQS, API Gateway, S3, or SNS-triggered functions.

**Remediation:** Create a CloudWatch alarm on AWS/Lambda IteratorAge with an SNS notification action; threshold should reflect acceptable processing lag for the stream (typically 60000 ms for low-latency streams).

---

### CTL.LAMBDA.ALARM.THROTTLES.001

**Lambda Function Must Have a CloudWatch Alarm on Throttles**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: SI-4; nist_800_53_r5: SI-4; soc2: CC7.2;

Lambda functions must have a CloudWatch alarm on the Throttles metric. Throttled invocations are rejected: for synchronous callers (API Gateway, ALB) the caller receives a 429 and the upstream request fails. For async invocations the event is retried for six hours and then sent to the DLQ if configured or discarded. Throttling indicates one of: account-level concurrency exhaustion (a noisy neighbor function consuming the shared limit), reserved-concurrency cap reached (the function's own ceiling is too low for current traffic), or a deliberate denial-of-service against a public function URL. Each cause requires a different response, but all require notification before user impact compounds.

**Remediation:** Create a CloudWatch alarm on AWS/Lambda Throttles with an SNS notification action.

---

### CTL.LAMBDA.CODESIGN.001

**Lambda Functions Must Enforce Code Signing**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** aws_security_hub: Lambda.5; mitre_attack: T1059; nist_800_53_r5: SI-7;

Lambda code signing ensures only code signed by an approved entity can be deployed. Without code signing, an attacker with lambda:UpdateFunctionCode permission can replace function code with malicious payloads — exfiltrating environment variables, reading /tmp, or establishing outbound connections. Code signing uses AWS Signer to create cryptographic signatures. Lambda verifies signatures on deployment and rejects unsigned or invalidly-signed packages. This prevents supply chain attacks where a compromised CI/CD pipeline pushes malicious Lambda code to production.

**Remediation:** Create an AWS Signer signing profile, create a code signing config referencing the profile, and attach it to the function: aws lambda put-function-code-signing-config --function-name <n> --code-signing-config-arn <config-arn>

---

### CTL.LAMBDA.CODESIGN.ENFORCE.001

**Lambda Code Signing Must Be Enabled and in Enforce Mode**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; hipaa: 164.312(c)(1); nist_800_53_r5: SI-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

Lambda functions must have a code signing configuration attached with the policy mode set to Enforce. Lambda code signing uses AWS Signer to cryptographically verify that deployment packages were signed by a trusted publisher before the function accepts them. Without a code signing configuration, any package from any source is deployed without integrity verification. In Warn mode, unsigned packages generate a finding but are deployed successfully — this provides observability without protection, the same failure mode as WAF COUNT mode and ECR image signing in audit mode. Only Enforce mode prevents unsigned or invalidly signed packages from being deployed. A supply chain attack that replaces a legitimate package executes immediately with the function's full IAM execution role permissions.

**Remediation:** Create an AWS Signer signing profile for your build pipeline. Create a Lambda code signing configuration referencing the signing profile. Attach the code signing configuration to the function with the policy mode set to Enforce. Update the CI/CD pipeline to sign packages with the Signer profile before deployment. Verify that unsigned deployment attempts are rejected.

---

### CTL.LAMBDA.CONCURRENCY.001

**Lambda Functions Must Have Reserved Concurrency Configured**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; pci_dss_v4.0: 1.3.2; soc2: A1.1;

Lambda functions must have reserved concurrency set to a non-zero value. Without reserved concurrency, a function competes for the account-wide concurrency pool with every other function. A single function experiencing a traffic spike can exhaust the account limit and prevent all other functions from executing. Reserved concurrency provides both a ceiling (blast radius limitation) and a floor (availability guarantee) for each function.

**Remediation:** Set reserved concurrency via aws lambda put-function-concurrency --reserved-concurrent-executions <value>. Choose a value that bounds the function's maximum invocations while leaving headroom for other critical functions.

---

### CTL.LAMBDA.CONFIG.CONCURRENCY.NOLIMIT.001

**Publicly Invocable Lambda Has No Concurrency Limit**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; pci_dss_v4.0: 1.3.2; soc2: A1.1;

Lambda functions that are publicly invocable (Function URL with AuthType NONE, or API Gateway route with no authorizer) must have reserved concurrency configured. Without reserved concurrency the function competes with every other function in the account for the account-wide concurrency limit (default: 1000). For a publicly invocable function, an attacker can drive thousands of concurrent invocations from the open endpoint and exhaust the entire account's concurrency budget — every other function in the account is throttled and effectively denied service. Reserved concurrency caps the function's maximum simultaneous executions (a ceiling that contains the blast radius) and reserves capacity for the function (a floor that guarantees minimum throughput). Distinct from CTL.LAMBDA.CONCURRENCY.001 which fires for any function without reserved concurrency at low severity; this control gates on public invocability and treats the combination as the high-severity DDoS surface.

**Remediation:** Set reserved concurrency to a value that bounds the function's maximum simultaneous executions and preserves headroom for other functions in the account via aws lambda put-function-concurrency --reserved-concurrent-executions <value>. If public invocability is not intended, remove the public surface first (Function URL AuthType to AWS_IAM, or attach an authorizer to the API Gateway route).

---

### CTL.LAMBDA.CONFIG.MEMORY.EXCESSIVE.001

**Lambda Function Memory Set to Maximum**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.308(a)(7); nist_800_53_r5: CM-6; soc2: CC6.1;

Lambda functions must not have memory_size set to the 10240MB maximum without justification. Memory in Lambda is also CPU and network allocation — increasing memory proportionally increases CPU share and network bandwidth — and the per-millisecond billing rate scales with the memory allocation. A function provisioned at 10240MB pays 64x the rate of a function provisioned at 160MB. Provisioning at the maximum is a governance signal in most environments: memory was raised once during incident response or capacity tuning and never reduced when the workload changed, or the workload genuinely needs the ceiling (large in-memory data processing, ML inference) in which case the value should be tagged and tracked. The finding is "review whether the maximum is intended" rather than "this is unsafe."

**Remediation:** Reduce memory_size to the lowest value at which the function meets its latency SLO via aws lambda update-function-configuration --memory-size <MB>. Use Lambda Power Tuning or measured invocation duration to find the cost-optimal allocation. If 10240MB is required, tag the function stave/lambda-memory-justified with the workload reason.

---

### CTL.LAMBDA.CONFIG.TIMEOUT.EXCESSIVE.001

**Lambda Function Timeout Set to Maximum**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.308(a)(7); nist_800_53_r5: CM-6; soc2: CC6.1;

Lambda functions must not have their timeout set to the 900-second maximum without justification. For most functions, normal execution completes in seconds; the 900-second ceiling is the configured guardrail value AWS allows, not a default. A 15-minute timeout means: a stuck function consumes compute for 15 minutes before being killed (cost), a runaway function or injection attack runs for 15 minutes before termination (blast radius duration), and the function's concurrent execution slot is held for up to 15 minutes per invocation (capacity waste reducing available concurrency for other invocations). Distinct from CTL.LAMBDA.TIMEOUT.001 which fires when timeout exceeds the configurable safe threshold (default 60s); this control specifically catches the at-maximum value as a governance signal — review whether 900s is actually needed or whether the timeout was raised once and never tightened.

**Remediation:** Reduce the timeout to the lowest value that accommodates the function's actual runtime — most workloads complete in well under 60 seconds — via aws lambda update-function-configuration --timeout <seconds>. If 900s is required (long-running ETL, batch processing), tag the function stave/lambda-timeout-justified with the reason.

---

### CTL.LAMBDA.DLQ.001

**Lambda Async Invocations Must Have a Dead Letter Queue**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.308(a)(7); soc2: PI1.1;

Lambda functions with asynchronous invocation sources must have a dead-letter queue (SQS or SNS) configured. Without a DLQ, failed async invocations are silently discarded after retries. For functions processing PHI events or compliance-relevant data, silent discard is an undetectable data integrity violation.

**Remediation:** Configure a dead-letter queue (SQS queue or SNS topic) for the function via aws lambda update-function-configuration --dead-letter-config.

---

### CTL.LAMBDA.DLQ.MISSING.001

**Lambda With Async Triggers Must Have a DLQ or Failure Destination**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-10; hipaa: 164.308(a)(7); nist_800_53_r5: CP-10; soc2: A1.2;

Lambda functions with asynchronous triggers (S3, SNS, EventBridge, async invoke) must have either a dead-letter queue or an on-failure destination configured. Asynchronous invocations are retried twice on failure; after the retries the event is sent to the DLQ if configured, sent to the failure destination if configured, or discarded if neither is configured. Discarded events are gone — no reprocessing path, no audit, no record. For event-driven architectures, lost events mean lost data, missed transactions, or inconsistent state across consumers that share the upstream event source. Distinct from CTL.LAMBDA.DLQ.001 which is ungated; this control fires only when the function has at least one async trigger and neither a DLQ nor a failure destination, which is the actual data loss case.

**Remediation:** Configure a dead-letter queue via aws lambda update-function-configuration --dead-letter-config TargetArn=<sqs-or-sns-arn>, or attach an EventInvokeConfig OnFailure destination via aws lambda put-function-event-invoke-config.

---

### CTL.LAMBDA.ENV.ENCRYPT.001

**Lambda Environment Variables Must Be Encrypted with CMK**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.4.1; soc2: CC6.7;

Lambda functions with environment variables must encrypt them using a customer-managed KMS key, not the default AWS-managed key. Without CMK encryption, environment variable values are encrypted with a default key that any principal with lambda:GetFunction can decrypt. A CMK provides fine-grained access control over decryption — only principals with kms:Decrypt on the specific key can read the values.

**Remediation:** Create a KMS key and configure the function to use it for environment variable encryption via the aws lambda update-function-configuration --kms-key-arn command.

---

### CTL.LAMBDA.ENV.EXCESSIVE.001

**Lambda Functions Should Not Have Excessive Environment Variables**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** owasp_nhi: NHI2;

Lambda functions should carry no more than the configured environment-variable threshold (default 20). Functions whose env-var count exceeds the threshold are almost always misconfigured: they hold a mix of credentials, endpoint URLs, feature flags, retry parameters, and per-deploy configuration that should live in a configuration service (AWS AppConfig, SSM Parameter Store with hierarchies, or a layer-resident config file) rather than in the function's environment block. Three problems compound at scale. (1) Audit cost: a 30-variable env block is past the size a human reviewer can hold in working memory; identifying which entries are credentials versus URLs versus flags becomes a per-variable pattern-matching exercise. (2) Rotation cost: every change to any one variable requires a function configuration update and (for raw credentials) a published-version churn that retains the historical value. (3) Disclosure surface: every additional variable is one more value exposed by lambda:GetFunctionConfiguration. The threshold is a heuristic; some functions legitimately carry many flags, and the threshold is configurable.

**Remediation:** Move configuration values to AppConfig / SSM Parameter Store; keep only runtime-essential variables in the function's env block.

---

### CTL.LAMBDA.ENV.KMS.EXTERNAL.001

**Lambda Functions Must Not Use KMS Keys Owned by External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12; pci_dss_v4: 3.6;

Lambda functions must not encrypt their environment variables with a KMS key owned by an AWS account other than the function's own (or an account explicitly within the same AWS Organization that the team controls). The external account holds key-policy authority — they can disable the key (every cold-start KMS:Decrypt fails and the function stops initializing), schedule the key for deletion (the failure becomes permanent at the deletion date), or modify the key policy to revoke this account's decrypt rights at any time. The function's continued operation therefore depends on a relationship the team does not control. Same architectural pattern that CTL.S3.ENCRYPT.KMS.OWNERSHIP.001 catches on S3 buckets and the RDS external-key concept catches on databases: encryption is in place, but the key-control plane is outside the team's organizational boundary. Most common origins are partner-account integrations where the partner's CMK was reused for convenience, account migrations where the function moved without re-pointing at a same-account key, and IaC modules copied across accounts that did not refresh the KMS reference.

**Remediation:** Re-encrypt the environment under a same-account (or same-org) CMK and update the function's KMSKeyArn.

---

### CTL.LAMBDA.ENV.SECRETS.001

**Lambda Functions Must Not Store Secrets in Environment Variables**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; owasp_nhi: NHI2; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

Lambda function environment variables must not contain plaintext secrets such as database credentials, API keys, or tokens. Environment variables are visible in plaintext to anyone with lambda:GetFunction permission, are included in CloudTrail logs for UpdateFunctionConfiguration events, and are stored in the Lambda service's configuration store without application-level encryption. AWS Secrets Manager and SSM Parameter Store SecureString provide encrypted storage with rotation, audit logging, and fine-grained access control. Moving secrets out of environment variables is the single most impactful Lambda security improvement for most functions.

**Remediation:** Move secrets to AWS Secrets Manager or SSM Parameter Store SecureString. Update the function code to retrieve secrets at runtime via the AWS SDK. Remove the plaintext values from the environment variable configuration. Use the Lambda Secrets Manager extension for cached retrieval with minimal latency impact.

---

### CTL.LAMBDA.ENV.VISIBLE.VERSIONS.001

**Lambda Published Versions Must Not Retain Stale Environment Variables**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** secrets
- **Compliance:** nist_800_53_r5: MP-6; owasp_nhi: NHI2; pci_dss_v4: 3.5;

Lambda functions with multiple published versions whose older versions hold environment variables that differ from the current ($LATEST) version are surfaced for cleanup. Published Lambda versions are immutable snapshots of the function configuration — including the full environment-variable map at the moment the version was published — and the snapshot persists even after the live function rotates the credential, removes the variable, or migrates to a Secrets Manager reference. Anyone with `lambda:GetFunction` against the version- qualified ARN can read the historical environment block. A database password that was a raw value in version 3 is still readable from version 3 a year later, even if version 14 is the live one and the password has been rotated three times in the meantime. The pattern is benign for non-credential env vars (feature flags, service URLs); it is a leak when the env var ever held a credential. Published-version cleanup (DeleteFunction with version qualifier) is the remediation; the control is medium because the leak requires both `GetFunction` rights AND awareness that versions retain history.

**Remediation:** Delete unused published versions; for versions still in use, audit the environment for stale credentials and delete after migration.

---

### CTL.LAMBDA.ESM.BISECT.001

**Stream Event Source Mapping Must Bisect on Error**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-11; nist_800_53_r5: SI-11; soc2: A1.2;

Lambda event source mappings for Kinesis or DynamoDB Streams must have BisectBatchOnFunctionError enabled. Without bisect, the entire batch is retried when a single record fails — one poisonous record blocks every record alongside it. With bisect, Lambda splits the failing batch in half and retries each half independently, recursively isolating the bad record while letting the good ones drain. For high-throughput streams, the difference is between minutes of blocked processing and minutes of normal processing with one isolated failure. Bisect is stream-only: SQS event source mappings handle individual messages, not stream shards, and have no bisect setting. The control fires only on Kinesis and DynamoDB Stream ESMs.

**Remediation:** Enable bisect on the event source mapping via aws lambda update-event-source-mapping --bisect-batch-on-function-error.

---

### CTL.LAMBDA.ESM.NODLQ.001

**Event Source Mapping Must Have a Failure Destination**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CP-10; nist_800_53_r5: CP-10; soc2: A1.2;

Lambda event source mappings (Kinesis, DynamoDB Streams, SQS) must have an on-failure destination configured. Without one, error handling depends on the source type and is uniformly bad. For Kinesis and DynamoDB Streams: the failed batch is retried until it succeeds or the record's maximum age expires — and meanwhile the shard is blocked. Every record behind the poisonous one is stuck. The function processes the same failed batch repeatedly and the stream cannot drain. For SQS: the message returns to the queue, the receive count increments, and the message retries until the queue's retention expires. Without a queue-level DLQ, the message is discarded with no record. A failure destination (SQS, SNS, S3, or EventBridge) captures the failed record for investigation, unblocks the stream, and preserves the data for reprocessing.

**Remediation:** Add a failure destination to the event source mapping via aws lambda update-event-source-mapping --destination-config OnFailure={Destination=<arn>}.

---

### CTL.LAMBDA.GHOST.DLQ.001

**Lambda Function DLQ Must Not Reference Deleted Targets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.2;

Lambda function dead-letter queue configurations must reference SQS queues or SNS topics that currently exist. The DLQ is the safety net for failed asynchronous invocations: after a function exhausts its retry policy (default 2 retries on async invocation), the failed event is published to the DLQ for investigation and reprocessing. When the DLQ target has been deleted, the publish call fails silently — Lambda does not propagate the publish error to the invoker (the original async invocation has already been acknowledged), does not retry the publish, and does not flag the function as misconfigured. The event is discarded. The console shows the DLQ ARN configured; CloudWatch metrics show the function failing as expected; nobody notices that the failed events are not making it to the DLQ for review. Distinct from CTL.LAMBDA.DLQ.001 which catches the "no DLQ configured at all" case; this control catches the "DLQ configured but pointing at a deleted target." Same pattern as CTL.CLOUDWATCH.ALARM.GHOST.001 (alarm action targeting a deleted SNS topic) on the Lambda DLQ channel.

**Remediation:** Re-point the DLQ at a current target, or recreate the deleted queue/topic if it should still exist.

---

### CTL.LAMBDA.GHOST.KMS.001

**Lambda Functions Must Not Reference Deleted KMS Keys**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-12;

Lambda functions that use a KMS key for environment-variable encryption must reference a key that currently exists and is not pending deletion. On every cold start, Lambda calls KMS:Decrypt against the configured key to produce the plaintext environment for the execution environment; if the key has been deleted (or has entered the 7-30 day pending-deletion window with the function unable to re-encrypt the variables under a different key), the decrypt call fails and the function fails at initialization. Functions whose environment variables contain runtime configuration (database endpoints, service URLs, feature flags, secret-fetch ARNs) have no fallback path — the configuration is unreachable and the handler does not start. The console reports the function configured; the function fails on every cold start. The most common origins are a KMS-cleanup workflow that scheduled deletion of keys believed unused, and a key- rotation procedure that destroyed the prior key version before all consumers were re-pointed at the new one.

**Remediation:** Cancel the key deletion (within the 7-30 day window) or re-encrypt environment variables under a current key.

---

### CTL.LAMBDA.GHOST.ROLE.001

**Lambda Functions Must Not Reference Deleted Execution Roles**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: CM-2; soc2: CC8.1;

Lambda functions must reference an IAM execution role that currently exists. The execution role is the function's identity — every AWS API call the function makes uses credentials issued for that role. When the role is deleted, Lambda cannot assume it on the next invocation; the function fails before its code starts with "The role defined for the function cannot be assumed by Lambda." Critically, the function continues to exist in the inventory: triggers remain configured, EventSourceMappings remain attached, the console shows the function as "Active." Events keep arriving — SQS messages, S3 notifications, EventBridge rules, API Gateway requests — and every invocation fails. SQS retries to the DLQ and then to disposal. S3 events drop. API Gateway returns 500 to callers. The most common origins are an IAM cleanup that removed roles believed unused, an infrastructure-as-code apply that deleted the role resource while keeping the function resource, and a cross-team change where the role-owning team did not know the function-owning team still depended on it. This is the most severe ghost reference in the Lambda set: the function does not degrade, it stops working entirely.

**Remediation:** Recreate the role with equivalent trust and permissions, or repoint the function at a current role.

---

### CTL.LAMBDA.GHOST.VPC.001

**VPC-Configured Lambda Functions Must Not Reference Deleted Subnets or SGs**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: CM-2; soc2: A1.2;

Lambda functions configured for VPC access must reference subnets and security groups that currently exist. When the function provisions a new execution environment (cold start, scale-out, post-deployment), Lambda creates a Hyperplane ENI in one of the configured subnets with the configured security groups. If any referenced subnet or SG is deleted, the ENI creation fails and the cold start fails — the function returns an EC2AccessDeniedException-class error to the invoker. Warm invocations (reusing a previously-created ENI) continue serving requests, so the failure is intermittent and frustrating to diagnose: the function "sometimes works," depending entirely on whether a warm execution environment exists. Cold-start failures arrive at every scale event, every deployment, every idle-timeout recovery. The most common origins are a network refactor that recycled subnet IDs, a security-group consolidation that did not coordinate with the function's owners, and IaC drift that removed VPC resources without removing the function's reference to them.

**Remediation:** Update the function's VPC configuration to current subnets and SGs, or remove VPC configuration if no longer needed.

---

### CTL.LAMBDA.INVOKE.PUBLIC.001

**Lambda Functions Must Not Have Public Invoke Permissions**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: Lambda.1; mitre_attack: T1648; nist_800_53_r5: AC-3;

Lambda resource-based policies must not grant lambda:InvokeFunction to "*" (all principals). A publicly invokable Lambda function allows any AWS account or unauthenticated caller to trigger execution — the function runs with its full IAM execution role, providing code execution and credential access to any internet user. This is MITRE ATT&CK T1648 (Serverless Execution).

**Remediation:** Remove the public invoke permission from the function policy: aws lambda remove-permission --function-name <name> --statement-id <sid>

---

### CTL.LAMBDA.LAYER.GHOST.001

**Lambda Functions Must Not Reference Deleted Layer Versions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-7; soc2: CC6.1;

Lambda functions must not reference layer versions that have been deleted. A missing layer means the function runs without the expected dependency — potentially losing security-relevant libraries, encryption modules, or authentication middleware.

**Remediation:** Update the function to reference an existing layer version or remove the layer.

---

### CTL.LAMBDA.LAYER.ORIGIN.001

**Lambda Layers Must Originate from Trusted Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-7; gdpr: Art.32; nist_800_53_r5: SI-7; soc2: CC7.1;

All Lambda layers referenced by a function must have ARNs whose account IDs are in the organization's trusted account list. Lambda layers execute in the function runtime with the function's execution role permissions. A layer from an untrusted account is unaudited code executing with full function permissions — a supply chain risk independent of the function's own code.

**Remediation:** Replace external layers with organization-owned layers. If third-party layers are required, vendor them into an organization-owned account and reference the vendored copy.

---

### CTL.LAMBDA.LAYER.SECRETS.001

**Lambda Layers Must Not Contain Embedded Secrets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; owasp_nhi: NHI2; pci_dss_v4.0: 8.3.4; soc2: CC6.1;

Lambda layers must not contain embedded secrets (API keys, database credentials, certificates, private keys). Unlike environment variables (detectable via ENV.SECRETS.001), layer contents are opaque archives accessible to anyone with lambda:GetLayerVersion permission. Secrets in layers persist across function versions and are not encrypted by KMS.

**Remediation:** Remove secrets from layer contents. Use Secrets Manager or SSM Parameter Store for credentials retrieved at runtime. Republish the layer without sensitive files.

---

### CTL.LAMBDA.LIFECYCLE.DORMANT.001

**Lambda Function Not Invoked in 90+ Days**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; hipaa: 164.308(a)(1)(ii)(B); nist_800_53_r5: CM-2; soc2: CC6.1;

Lambda functions that have not been invoked in 90 or more days are dormant. The function still exists with its execution role, environment variables, VPC configuration, and triggers — but serves no active purpose. Dormant functions are a latent attack surface: the execution role carries IAM permissions, the environment variables may contain credentials, the VPC config grants a network position, and the triggers (event sources) may still be active and routable. Nobody monitors a dormant function for anomalous invocations because it is assumed to be unused, so any invocation that does occur — by the attacker who finds it — goes unnoticed. The 90-day threshold matches the dormancy threshold used for unused IAM roles and aged stopped EC2 instances, so dormancy is consistent across services.

**Remediation:** Decommission the function if it is no longer needed — aws lambda delete-function — and remove its triggers, DLQ, log group, and execution role to eliminate the latent surface. If the function must be retained, tag it stave/lambda-dormancy-justified with the reason and add monitoring for any invocation.

---

### CTL.LAMBDA.LIFECYCLE.NOTRIGGER.001

**Lambda Function Has No Event Source**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-3; hipaa: 164.308(a)(1)(ii)(B); nist_800_53_r5: CM-3; soc2: CC8.1;

Lambda functions must have at least one configured trigger — an event source mapping (SQS, Kinesis, DynamoDB Streams), a resource-policy invoke statement (S3, SNS, EventBridge, API Gateway), a Function URL, or a CloudWatch schedule. A function with zero triggers can only be invoked via direct lambda:InvokeFunction API calls, meaning either the function was partially deployed (triggers not yet configured), the triggers were removed (cleanup left the function behind), or the function is invoked manually with no automated path. In each case the fully configured function — with execution role, environment variables, and VPC access — is sitting idle with no observable invocation channel and so no detection for misuse.

**Remediation:** Remove the function if no invocation path is intended, or attach the missing trigger (event source mapping, resource policy statement, Function URL, or scheduled rule) and document the invocation channel.

---

### CTL.LAMBDA.LIFECYCLE.ORPHANLOG.001

**CloudWatch Log Group Exists for Deleted Lambda Function**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SA-22; hipaa: 164.308(a)(1)(ii)(B); nist_800_53_r5: SA-22; soc2: CC8.1;

A CloudWatch log group with the Lambda naming pattern (/aws/lambda/<function-name>) must not persist after the corresponding Lambda function is deleted. When the function is removed but its log group is not, the log group accumulates no new logs but retains historical logs with potentially sensitive output (request/response payloads, IDs, error stack traces, environment-variable echoes). The orphaned log group is a low-severity finding — there is no active invocation surface — but it represents three governance signals: cost (logs retained past their useful life), data exposure (historical logs may contain sensitive content past the retention intention of the deleted function), and serverless cleanup failure (the decommission script removed the function but not its dependent resources).

**Remediation:** Delete the orphaned log group via aws logs delete-log-group --log-group-name /aws/lambda/<name>, or transfer historical logs to long-term storage (S3 + Glacier) before deletion if the data is retention-required.

---

### CTL.LAMBDA.LIST.RESTRICT.001

**Lambda Function List Permissions Must Be Restricted**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** mitre_attack: T1526; nist_800_53_r5: AC-6;

Lambda function list permissions must be restricted to administrative roles. Unrestricted lambda:ListFunctions access reveals the entire serverless architecture including function names, runtimes, memory allocations, environment variable keys, and VPC configurations. Attackers use this to identify functions with overprivileged roles, outdated runtimes, or exposed environment variables for targeting.

**Remediation:** Restrict lambda:ListFunctions and lambda:GetFunction to administrative roles only. Apply tag-based access control to limit function enumeration scope. Use AWS Organizations SCPs to enforce lambda list restrictions across accounts.

---

### CTL.LAMBDA.LOG.001

**Lambda Functions Must Have CloudWatch Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Lambda functions must have CloudWatch Logs enabled. Without logging, function invocations — including unauthorized or malicious invocations — produce no observable output. Error conditions, security events, and application behavior are invisible. For functions with public function URLs, missing logging means a Denial of Wallet attack generates AWS costs with no audit trail. Lambda logging requires the execution role to have logs:CreateLogGroup, logs:CreateLogStream, and logs:PutLogEvents permissions — a missing log group or insufficient permissions silently disables logging without failing the function invocation.

**Remediation:** Grant the execution role CloudWatch Logs permissions: logs:CreateLogGroup, logs:CreateLogStream, logs:PutLogEvents. Verify the log group exists in CloudWatch Logs. If using a custom log group name via the function's logging configuration, ensure the log group is created and the retention policy is set.

---

### CTL.LAMBDA.LOG.ENCRYPT.001

**Lambda CloudWatch Log Group Not Encrypted with CMK**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-9; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: AU-9; pci_dss_v4.0: 10.3.2; soc2: CC6.1;

Lambda function CloudWatch log groups must be encrypted with a customer-managed KMS key. Log groups are encrypted by default with the CloudWatch service key, but a CMK provides explicit key policy control, CloudTrail-level audit on key use, and revocation capability. Lambda logs frequently contain sensitive data — request and response payloads, error stacks with PII, debug output that captures credentials. The service key cannot be revoked, has no caller-specific audit, and is shared across the account; a CMK is the only way to limit log access to specific principals and to detect anomalous access via CloudTrail key events.

**Remediation:** Associate a CMK with the log group via aws logs associate-kms-key --log-group-name /aws/lambda/<function> --kms-key-id <cmk-arn>. Ensure the CMK key policy permits logs.<region>.amazonaws.com to use the key.

---

### CTL.LAMBDA.LOG.MISSING.001

**Lambda Function Has No CloudWatch Log Group**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** fedramp_moderate: AU-2; hipaa: 164.312(b); nist_800_53_r5: AU-2; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Lambda functions must have an associated CloudWatch log group. Lambda creates the log group automatically on first invocation — provided the execution role has logs:CreateLogGroup, logs:CreateLogStream, and logs:PutLogEvents. If the role lacks log permissions, the function still executes — its code runs, side effects occur, downstream calls happen — but every console output, error stack, and log statement is silently discarded. Debugging is impossible. Error tracking is impossible. The function becomes a black box. The control fires only when the function has been invoked at least once: an uninvoked function with no log group is expected (the log group will be created on first call) and the finding instead signals a stale or never-deployed function. Two distinct causes, distinguishable in triage: function invoked but role missing log permissions (real silent failure) versus function never invoked (deployment never completed or zombie function).

**Remediation:** Attach AWSLambdaBasicExecutionRole or an equivalent policy granting logs:CreateLogGroup, logs:CreateLogStream, and logs:PutLogEvents to the function's execution role. Re-invoke the function to trigger log group creation.

---

### CTL.LAMBDA.LOG.RETENTION.001

**Lambda CloudWatch Log Group Has No Retention or Retention Too Short**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-11; hipaa: 164.312(b); nist_800_53_r5: AU-11; pci_dss_v4.0: 10.5.1; soc2: CC7.2;

Lambda function CloudWatch log groups must have an explicit retention policy of at least 365 days. Lambda creates the log group on first invocation but does not set a retention policy — the default is "Never expire," which accumulates storage cost indefinitely and may violate data deletion policies (GDPR right to erasure, internal retention rules requiring deletion after a period). Retention shorter than 365 days fails compliance audit windows that require log preservation across investigation cycles. Two failure modes, one control: unbounded accumulation (no retention set — cost and compliance) and premature deletion (retention below the audit window — investigation gap).

**Remediation:** Set CloudWatch log group retention to 365 days or more via aws logs put-retention-policy --log-group-name /aws/lambda/<function> --retention-in-days 365.

---

### CTL.LAMBDA.MARKER.BEDROCK.TOOL.001

**Lambda Function Registered as Bedrock Agent Tool (Marker)**

- **Severity:** low
- **Type:** marker
- **Domain:** governance
- **Compliance:** hipaa: 164.312(c)(1);

Fact-recording marker for Lambda functions that are registered as a Bedrock agent action group (the agent's tool list). Emits an informational finding (NOT a violation) so cross-service chains can compose this fact with overpermission markers on the Lambda's execution role. Same pattern as CTL.S3.MARKER.PHI.001 + CTL.BEDROCK.KB.MARKER.INDEXES.001 applied to Lambda. A Lambda being a Bedrock tool is the desired state — never a finding to triage. The marker exists so the chain engine can join "agent prompt surface reaches this Lambda" with "this Lambda's role reaches PHI" without forcing the collector to denormalise the agent → Lambda → S3 reachability into a single per-Lambda boolean.

**Remediation:** None. This marker exists as a chain-detection ingredient. Render it under a "facts" panel rather than the violation list.

---

### CTL.LAMBDA.MICROVM.AUTHTOKEN.EXPIRY.001

**MicroVM Auth-Token Expiration Must Be Constrained to 30 Minutes or Less**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-12; soc2: CC6.1;

lambda:CreateMicrovmAuthToken mints a bearer token for a MicroVM and takes an expiration parameter. AWS best practice is a 15–30 minute lifetime; a long-lived token is a stolen-credential window (an 8-hour token gives an attacker an 8-hour foothold). If a role that can create auth tokens has no IAM policy condition constraining the expiration — or constrains it above 30 minutes — any caller can mint long-lived tokens.
This control reads collector-resolved signals, not raw policy JSON. The collector resolves the role's effective permissions (inline + attached managed + boundary, expanding lambda:* which includes CreateMicrovmAuthToken) into role.microvm_authtoken_create, and inspects the Allow statement's Condition for a numeric upper bound on the expiration condition key, emitting role.microvm_authtoken_expiry_constrained and (when present) role.microvm_authtoken_expiry_max_minutes.
Note on condition keys: the exact IAM condition key for MicroVM token expiration may not yet be published by AWS. The collector matches whatever key AWS uses (e.g. lambda:AuthTokenExpirationInMinutes); if it cannot resolve a constraint it MUST emit expiry_constrained=false — fail-loud, treated as unconstrained (FAIL), never a silent PASS.

**Remediation:** Add an IAM policy Condition with a numeric upper bound (<= 30) on the MicroVM auth-token expiration condition key to every Allow of lambda:CreateMicrovmAuthToken (and narrow any lambda:* grant). Check attached managed policies, not just inline.

---

### CTL.LAMBDA.MICROVM.AUTHTOKEN.PORTSCOPE.001

**MicroVM Auth Tokens Must Be Scoped to Specific Ports, Never the Lifecycle Port**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

lambda:CreateMicrovmAuthToken takes an allowedPorts parameter. A token minted without port scoping grants access to EVERY listening port on the MicroVM — the application port, debug ports, metrics, internal services, and critically the lifecycle hook port (the internal Lambda↔MicroVM API exposing /suspend, /terminate). An unscoped token lets its holder disrupt production or extract state. The lifecycle hook port (configured separately from the app port, per AWS) must never be reachable by an external auth token.
Reads collector-resolved signals. The collector resolves role.microvm_authtoken_create (effective, incl. the lambda:* wildcard), whether the Allow statement constrains allowed ports (role.microvm_authtoken_port_scoped), and whether the allowed set includes the MicroVM's configured lifecycle hook port (role.microvm_authtoken_allows_lifecycle_port — cross-referenced against the MicroVM lifecycle-port config).
Safe default / fail-loud: if no port constraint is resolvable (including when AWS has not yet published an allowed-ports condition key), the collector emits port_scoped=false → FAIL. An unscoped token is unsafe regardless of whether the constraint mechanism exists yet.

**Remediation:** Add an IAM policy Condition scoping allowed ports to only the application port(s) on every Allow of lambda:CreateMicrovmAuthToken (and narrow any lambda:* grant). Never include the lifecycle hook port in the allowed set for externally-issued tokens.

---

### CTL.LAMBDA.MICROVM.BASEIMAGE.001

**MicroVM Image Uses Unapproved Base Image**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Image Uses Unapproved Base Image. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Build only from approved, current AWS base images (e.g. aws:microvm-image:al2023-*).

---

### CTL.LAMBDA.MICROVM.BUILDROLE.001

**MicroVM Build Role Is Over-Privileged**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Build Role Is Over-Privileged. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Scope the build role to S3 read of the artifact bucket, ECR push, and CloudWatch logs only.

---

### CTL.LAMBDA.MICROVM.CONNORIGIN.001

**MicroVM Uses Developer-Created Network Connector in Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Uses Developer-Created Network Connector in Production. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Use a network-team-provisioned connector in production; do not let developers create prod connectors.

---

### CTL.LAMBDA.MICROVM.CONNROLE.001

**MicroVM Network Connector Role Is Over-Privileged**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Network Connector Role Is Over-Privileged. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Scope the connector role to ENI management only (ec2:Create/Delete/DescribeNetworkInterfaces).

---

### CTL.LAMBDA.MICROVM.DATAEVENTS.001

**Sensitive Lambda MicroVM Must Have Data-Event Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

A Lambda MicroVM classified as sensitive must be covered by CloudTrail data-event logging for its control-plane API surface (RunMicrovm, CreateMicrovmAuthToken, SuspendMicrovm, ResumeMicrovm). MicroVMs are long-lived, addressable compute — unlike ephemeral function invocations, a MicroVM is a durable execution environment an attacker can reach and reuse. Without data-event coverage, creation, token issuance, and lifecycle transitions on that compute are invisible to forensics.
Extends the existing CloudTrail data-event family (CTL.CLOUDTRAIL.DATA.LAMBDA.001, CTL.CLOUDTRAIL.DATA.DYNAMODB.001, CTL.SECRETS.AUDIT.DATAEVENTS.001) to the MicroVM compute layer. The collector emits microvm.kind, microvm.sensitive (the MicroVM runs a sensitive workload), and microvm.audit.data_events_enabled (a trail covers its API calls). This control fires on a sensitive MicroVM with no data-event coverage.

**Remediation:** Add a CloudTrail data-event selector covering the MicroVM API surface (RunMicrovm, CreateMicrovmAuthToken, SuspendMicrovm, ResumeMicrovm) for the sensitive MicroVMs, on a multi-region trail with log-file validation.

---

### CTL.LAMBDA.MICROVM.ENTROPY.001

**MicroVM Does Not Reinitialize Entropy on Resume**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Does Not Reinitialize Entropy on Resume. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Configure lifecycle hooks that reinitialize entropy on run and resume.

---

### CTL.LAMBDA.MICROVM.EXECROLE.001

**MicroVM Execution Role Is Over-Privileged**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Execution Role Is Over-Privileged. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Scope the execution role to least privilege; remove wildcard actions and broad secretsmanager/s3 access.

---

### CTL.LAMBDA.MICROVM.IDENTITY.001

**MicroVM Workload Identity Has No Identity Claims**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Workload Identity Has No Identity Claims. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Ensure the MicroVM workload identity carries non-empty identity claims so the workload is governable.

---

### CTL.LAMBDA.MICROVM.IDLE.001

**MicroVM Idle Duration Exceeds Organization Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Idle Duration Exceeds Organization Limit. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Lower maxIdleDurationSeconds to within the org limit (<=1800s) for agent workloads.

---

### CTL.LAMBDA.MICROVM.INGRESSAUTH.001

**MicroVM Ingress Authentication Not Securely Enabled**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Ingress Authentication Not Securely Enabled. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Enable ingress authentication and constrain the auth token expiry; never disable ingress auth.

---

### CTL.LAMBDA.MICROVM.OBSERVABILITY.ROLES.001

**Production MicroVM Must Have Both Build Role and Execution Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-12; soc2: CC7.1;

AWS makes both MicroVM roles optional: no build role means no build logs to CloudWatch (no record of how the image was made); no execution role means no runtime logs and no AWS-service access (zero observability into what the MicroVM does at runtime). In production both are unacceptable — a MicroVM with no execution role is an audit blind spot.
The control evaluates the running MicroVM. The collector emits microvm.is_production, microvm.execution_role_present, and — surfaced from the MicroVM's source image — microvm.build_role_present. A production MicroVM missing EITHER role fires, so the image-level build-role gap (no record of what was installed at build time) is caught at the MicroVM that runs from it.

**Remediation:** Attach an execution role to the MicroVM (runtime logs + scoped AWS access) and a build role to its source image (build logs). Both are required in production; only development sandboxes may omit them.

---

### CTL.LAMBDA.MICROVM.RUNTIME.001

**MicroVM Maximum Runtime Exceeds Organization Limit**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Maximum Runtime Exceeds Organization Limit. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Lower the MicroVM maximum duration to within the org limit (<=1800s); 8h is the AWS ceiling, not a target.

---

### CTL.LAMBDA.MICROVM.S3PUBLIC.001

**MicroVM Artifact Bucket Allows Public Access**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Artifact Bucket Allows Public Access. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Enable S3 Block Public Access on the artifact bucket and remove public bucket-policy grants.

---

### CTL.LAMBDA.MICROVM.S3VERSION.001

**MicroVM Artifact Bucket Versioning Not Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Artifact Bucket Versioning Not Enabled. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Enable (not merely un-suspend) versioning on the artifact bucket for a deployment audit trail.

---

### CTL.LAMBDA.MICROVM.SG.001

**MicroVM Network Connector Security Group Allows Unrestricted Ingress**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Network Connector Security Group Allows Unrestricted Ingress. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Restrict the connector security group ingress to specific ports and CIDRs; remove 0.0.0.0/0 rules.

---

### CTL.LAMBDA.MICROVM.SHELLAUTH.001

**MicroVM Shell-Auth Permission Must Be Restricted to Break-Glass Roles**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Lambda MicroVMs have first-class interactive shell access via lambda:CreateMicrovmShellAuthToken, which returns a bearer token granting an interactive shell inside a running MicroVM. Any non-break-glass IAM role holding this permission turns a single compromised credential into an interactive shell inside production compute, bypassing every application-layer control. Only explicitly designated break-glass roles may hold it.
This control evaluates a derived signal, not raw policy JSON. The collector resolves the role's EFFECTIVE permissions (inline + attached managed policies + permission boundaries, expanding lambda:* — which includes the shell token action) and emits role.microvm_shell_auth. It also resolves role.is_break_glass (tag break-glass:true, or name matching *break-glass* / *emergency*) and role.workload_type (agent | cicd | human | service). This HIGH control fires for ordinary roles (human/service); agent and CI/CD roles are escalated to CRITICAL by CTL.LAMBDA.MICROVM.SHELLAUTH.ELEVATED.001, so the two never double-fire.
Fail-loud: the collector MUST emit role.microvm_shell_auth explicitly (false when no grant); if effective-permission resolution fails it must surface that (e.g. present:false or an explicit marker), never omit the field — a missing signal must not read as a silent PASS.

**Remediation:** Remove lambda:CreateMicrovmShellAuthToken (and any lambda:* grant that includes it) from the role — check attached managed policies and permission boundaries, not just inline policies. If interactive shell access is genuinely needed for emergencies, move it to a dedicated break-glass role (tag break-glass=true) with monitoring.

---

### CTL.LAMBDA.MICROVM.SHELLAUTH.ELEVATED.001

**Agent or CI/CD Role Must Never Hold MicroVM Shell-Auth Permission**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

An agent execution role or a CI/CD role holding lambda:CreateMicrovmShellAuthToken is CRITICAL, not merely high: a prompt-injected AI agent or a compromised pipeline credential would gain an interactive shell inside production MicroVMs. These workload classes should never have interactive shell access under any circumstance — there is no legitimate break-glass case for a non-human automation identity.
This is the CRITICAL-severity counterpart to CTL.LAMBDA.MICROVM.SHELLAUTH.001 (HIGH, ordinary roles). ctrl.v1 controls carry a single static severity, so the HIGH/CRITICAL escalation is expressed as two disjoint controls: this one fires only when role.workload_type is agent or cicd, the HIGH one only when it is neither — they never both fire on the same role. The collector resolves role.microvm_shell_auth (effective, incl. attached managed policies and the lambda:* wildcard), role.is_break_glass, and role.workload_type (from the agent taxonomy and CI/CD trust-policy heuristics).
Fail-loud: role.microvm_shell_auth must be emitted explicitly; a resolution failure must surface, never read as a silent PASS.

**Remediation:** Remove lambda:CreateMicrovmShellAuthToken and any lambda:* grant from the agent/CI-CD role (inspect attached managed policies and boundaries, not just inline). Automation identities must never hold interactive shell access; there is no break-glass exception for them.

---

### CTL.LAMBDA.MICROVM.SHELLINGRESS.001

**Production MicroVM Must Not Be Launched With the SHELL_INGRESS Connector**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

Interactive shell access to a MicroVM (lambda:CreateMicrovmShellAuthToken) fails with ValidationException unless the MicroVM was launched with the SHELL_INGRESS network connector (arn:aws:lambda:<region>:aws:network-connector:aws-network-connector:SHELL_INGRESS). Without that connector, shell access is STRUCTURALLY IMPOSSIBLE regardless of IAM. A production MicroVM launched with SHELL_INGRESS has shell access enabled at the infrastructure level.
This is the stronger of the two shell controls: MICROVM-021 (infrastructure) > CTL.LAMBDA.MICROVM.SHELLAUTH.001 (IAM) in assurance — IAM restricts who MAY create a shell token; the connector decides whether a shell is possible AT ALL. Defense in depth: remove the connector in production and no IAM mistake can grant a shell.
The collector emits microvm.shell_ingress_connector (any launched connector ARN matches the SHELL_INGRESS pattern) and microvm.is_production (tag environment=production/prod, or a production account/OU). Dev/staging MicroVMs with SHELL_INGRESS are intentionally out of scope for this control (acceptable for development); only production fires.

**Remediation:** Relaunch the production MicroVM without the SHELL_INGRESS connector. Shell access then becomes impossible by construction — CreateMicrovmShellAuthToken returns ValidationException — independent of any IAM grant.

---

### CTL.LAMBDA.MICROVM.SNAPSHOTSECRET.001

**MicroVM Image Loads Secrets Into the Snapshot at Init**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Image Loads Secrets Into the Snapshot at Init. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Defer secret loading to a runtime lifecycle hook; never read secrets at module scope before the snapshot.

---

### CTL.LAMBDA.MICROVM.SUBNET.001

**MicroVM Network Connector Uses Unapproved Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-6;

MicroVM Network Connector Uses Unapproved Subnets. Lab control for the Lambda MicroVM validation suite (ctf/labs/microvm). Evaluates a captured MicroVM configuration snapshot (obs.v0.1) for this invariant.

**Remediation:** Attach the network connector only to approved private subnets; remove public or unlisted subnets.

---

### CTL.LAMBDA.MICROVM.TAGSESSION.MISSING.001

**MicroVM Execution Role Trust Policy Missing sts:TagSession**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

The MicroVM execution role's trust policy does not grant sts:TagSession (and has no sts:* wildcard that would cover it), so the role can never carry session tags. Without session tagging, attribute-based access control and tag-scoped guardrails cannot be applied to the role's sessions — a future-proofing gap that silently disables ABAC for every MicroVM that assumes this role. Distinct from the over-broad case (CTL.LAMBDA.MICROVM.TAGSESSION.WILDCARD.001): this is absence of the action, not an unscoped grant.

**Remediation:** Add sts:TagSession alongside sts:AssumeRole in the role's trust policy. Grant it as the explicit action, not via an sts:* wildcard.

---

### CTL.LAMBDA.MICROVM.TAGSESSION.WILDCARD.001

**MicroVM Execution Role Trust Policy Grants sts:TagSession via Over-Broad sts:* Wildcard**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6;

The MicroVM execution role's trust policy grants sts:TagSession through an sts:* wildcard rather than the explicit, scoped action. The wildcard also confers every other STS action (AssumeRoleWithWebIdentity, AssumeRoleWithSAML, GetFederationToken, …), expanding the trust relationship far beyond what session tagging requires. Distinct from the missing case (CTL.LAMBDA.MICROVM.TAGSESSION.MISSING.001): here the action is present, but granted over-broadly.

**Remediation:** Replace sts:* with the explicit actions the role needs — sts:AssumeRole and sts:TagSession — so session tagging is allowed without the unscoped wildcard.

---

### CTL.LAMBDA.MICROVM.WILDCARD.001

**Role With lambda:* Silently Gained All MicroVM Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

AWS placed the MicroVM actions inside the existing lambda: namespace, so any role granted lambda:* now ALSO holds lambda:RunMicrovm, lambda:CreateMicrovmAuthToken, lambda:CreateMicrovmShellAuthToken (interactive shell), lambda:TerminateMicrovm/SuspendMicrovm (lifecycle control), and lambda:CreateMicrovmImage. Most organizations granted lambda:* for ordinary Lambda-function management long before MicroVMs existed — those policies were never reviewed for MicroVM blast radius because MicroVMs did not exist when they were written. The blast radius expanded silently.
This HIGH control flags a non-MicroVM-admin role holding lambda:* (human or service workloads); agent and CI/CD roles are escalated to CRITICAL by CTL.LAMBDA.MICROVM.WILDCARD.ELEVATED.001, so the two never double-fire. The collector resolves role.has_lambda_wildcard from EFFECTIVE permissions — inline AND attached managed policies (e.g. AWS-published AWSLambda_FullAccess, which grants lambda:*) AND boundaries — plus role.is_microvm_admin (tag microvm-admin:true or name *microvm-admin*) and role.workload_type. Expect findings in most Lambda-heavy accounts; that is the point.

**Remediation:** Replace lambda:* with the explicit Lambda actions the role actually needs (e.g. lambda:InvokeFunction, lambda:UpdateFunctionCode). If the role is genuinely a MicroVM administrator, tag it microvm-admin=true to make the grant deliberate and reviewed. Check attached managed policies (AWSLambda_FullAccess grants lambda:*), not just inline.

---

### CTL.LAMBDA.MICROVM.WILDCARD.ELEVATED.001

**Agent or CI/CD Role With lambda:* Holds All MicroVM Permissions (Critical)**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

An agent execution role or a CI/CD role holding lambda:* is CRITICAL: the wildcard — granted for ordinary Lambda management before MicroVMs existed — now includes lambda:CreateMicrovmShellAuthToken (interactive shell), lambda:RunMicrovm, and lambda:Terminate/SuspendMicrovm. A prompt-injected agent or a compromised pipeline credential gains full MicroVM control, including a production shell, through a permission nobody reviewed for MicroVM blast radius.
CRITICAL counterpart to CTL.LAMBDA.MICROVM.WILDCARD.001 (HIGH). ctrl.v1 severity is static per control, so the escalation is two disjoint controls: this fires only when role.workload_type is agent or cicd; the HIGH one only when it is neither. role.has_lambda_wildcard is resolved from effective permissions (inline AND attached managed policies such as AWSLambda_FullAccess AND boundaries) — so a scoped-looking inline policy does not hide a wildcard granted by an attached managed policy.

**Remediation:** Replace lambda:* with the explicit, minimal Lambda actions the automation needs. Automation identities must never hold the MicroVM shell/run/lifecycle actions; there is no microvm-admin exception for an agent or pipeline role. Inspect attached managed policies (AWSLambda_FullAccess), not just inline.

---

### CTL.LAMBDA.OVERPERM.S3PHI.001

**Lambda Execution Role Must Not Reach PHI-Tagged S3 Buckets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

Lambda execution role's effective S3 access set includes at least one bucket carrying the data-classification=phi tag. Same predicate shape as CTL.LAMBDA.OVERPERM (general overpermission) but specialized for the cross-service AI compound: when a Lambda is also registered as a Bedrock agent action group (CTL.LAMBDA.MARKER.BEDROCK.TOOL.001), the agent's prompt surface gains a path to PHI through the tool-call boundary. The collector pre-computes the boolean by joining the role's effective s3:GetObject targets against the bucket-tag inventory; this control reads the flag and stamps target_phi_bucket_arn for chain composition with the S3 PHI marker.

**Remediation:** Scope the Lambda role's S3 actions to the specific non-PHI bucket(s) the function legitimately requires. If PHI access is necessary, wrap the function with explicit output redaction and require the agent (or any other caller) to authenticate per-request rather than relying on the Lambda's broad role permissions.

---

### CTL.LAMBDA.PASSROLE.001

**Lambda Execution Role Must Not Have Unconstrained iam:PassRole**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; iso_27001_2022: A.8.3; nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda execution roles must not have iam:PassRole with Resource: *. Unconstrained PassRole allows the function to attach any IAM role to new resources — effectively enabling privilege escalation to any role in the account including admin roles.

**Remediation:** Scope iam:PassRole in the execution role policy to specific role ARNs that the function legitimately needs to pass.

---

### CTL.LAMBDA.POLICY.ACCUMULATED.001

**Lambda Resource Policies Should Not Accumulate Excessive Permission Statements**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** nist_800_53_r5: AC-3;

Lambda function resource policies should carry no more than the configured threshold of permission statements (default 10). Each `lambda:AddPermission` call appends a statement; statements are rarely removed. Over time, the policy accumulates invocation grants from sources that may no longer be relevant — the S3 trigger from a bucket decommissioned last year, the EventBridge rule from a one-time migration, the SNS subscription from a decommissioned notification pipeline, the cross-account grant from a partner integration that has long since ended. Past the threshold, the policy is no longer a thing a human reviewer can hold in working memory — the effective invocation surface of the function spans many more sources than the team intends, and the auditing cost rises with every accretion. The threshold of 10 is a heuristic; some functions legitimately handle many triggers (S3 notifications from several buckets, multiple EventBridge rules), and the threshold is configurable for those.

**Remediation:** Audit the statements; remove ones whose principals or source resources no longer exist; consolidate equivalent grants.

---

### CTL.LAMBDA.POLICY.CROSSACCOUNT.001

**Lambda Resource Policies Must Constrain Cross-Account Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** nist_800_53_r5: AC-3; pci_dss_v4: 7.2;

Lambda resource policies that grant invocation rights to principals outside the function's own account must include an aws:PrincipalOrgID condition (or an equivalently scoping condition) that restricts the grant to specific AWS organizations or accounts. Without such a condition, any principal in the named external account can invoke the function — which means a compromise of any IAM identity in that account becomes a path to invoking the function and exercising the function's execution-role permissions. The pattern most often seen in the field is a one-shot AddPermission call that named an external account during a partner integration and never tightened the principal scope or added a condition; the policy remains in force long after the integration is decommissioned, the partner team has rotated, or the external account itself has changed ownership. Adding an aws:PrincipalOrgID, aws:SourceAccount, or aws:SourceArn condition limits the grant to the organization or specific source the integration actually required.

**Remediation:** Add aws:PrincipalOrgID, aws:SourceAccount, or aws:SourceArn condition to each cross-account statement.

---

### CTL.LAMBDA.ROLE.LEASTPRIV.001

**Lambda Execution Role Must Follow Least Privilege**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-6; hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda function execution roles must not have overly broad permissions. An over-privileged execution role grants the function — and any attacker who compromises or invokes it — access to AWS resources beyond what the function requires. Common violations include admin policies, wildcard resource ARNs on sensitive actions, or managed policies like AmazonS3FullAccess attached to functions that only need read access to a single bucket. When combined with a public function URL or a compromised dependency, an over-privileged role converts a single function compromise into account-wide lateral movement.

**Remediation:** Scope the execution role policy to only the specific actions and resource ARNs the function needs. Replace managed policies like AmazonS3FullAccess with inline policies scoped to specific buckets and actions. Use IAM Access Analyzer to identify unused permissions and generate a least-privilege policy from actual function activity.

---

### CTL.LAMBDA.ROLE.SHARED.001

**Lambda Execution Roles Must Not Be Shared Across Functions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

Each Lambda function must use a unique execution role not shared with other functions. Shared roles mean a compromise of one function grants the attacker the same permissions as every other function using that role. Blast radius isolation requires per-function roles.

**Remediation:** Create a unique IAM execution role per Lambda function scoped to the minimum permissions that function requires.

---

### CTL.LAMBDA.RUNTIME.001

**Lambda Functions Must Not Use Deprecated Runtimes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-6; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: CM-6; pci_dss_v4.0: 2.2.1; soc2: CC7.1;

Lambda functions must not run on runtimes that AWS has deprecated. Deprecated runtimes no longer receive security patches from AWS. Unlike EC2 where the operator controls patching, Lambda runtimes are AWS-managed — the only remediation is upgrading the runtime version. AWS publishes deprecation dates months in advance. A function on a deprecated runtime is running on an unpatched execution environment for every invocation. The operator has no mechanism to patch the underlying runtime independently — the runtime version is the patch level. AWS does not forcibly block invocations on deprecated runtimes immediately; functions continue working in a vulnerable state until AWS removes the runtime entirely, at which point the function breaks rather than degrading gracefully. This control detects the compliance gap during the window between deprecation and forced removal.

**Remediation:** Upgrade the Lambda function runtime to a supported version. Check the AWS Lambda runtimes documentation for the current supported runtime list and deprecation schedule. Test the function with the new runtime in a non-production environment before updating production. For Python, Node.js, and Java runtimes, review breaking changes in the language version upgrade guide.

---

### CTL.LAMBDA.RUNTIME.EOL.001

**Lambda Functions Must Not Use End-of-Life Runtimes**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** aws_security_hub: Lambda.2; mitre_attack: T1203; nist_800_53_r5: SI-2;

Lambda functions using end-of-life runtimes do not receive security patches from AWS. Known vulnerabilities in the runtime environment can be exploited to achieve code execution, escape the function sandbox, or access credentials. AWS deprecates runtimes on a published schedule — functions on deprecated runtimes cannot be updated but continue to run, creating a growing attack surface.

**Remediation:** Migrate the function to a supported runtime version. Check the AWS Lambda runtimes page for current supported versions. Test the function with the new runtime in a non-production environment before updating production.

---

### CTL.LAMBDA.SCIM.TAKEOVER.001

**SCIM Handler Enables Provisioning Takeover (Public Endpoint + Overprivileged + Reachable Token)**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3, AC-6, SC-7; owasp_nhi: NHI5; pci_dss_v4.0: 7.2.1; soc2: CC6.1, CC6.6;

A SCIM integration handler sits at the centre of a critical compound exposure: the SCIM endpoint it serves is publicly reachable with no effective gateway authentication, its execution role is overprivileged, and the SCIM bearer token is reachable. An attacker who obtains the token (from a Lambda env var, or a secret readable by a compromised role) hits the public endpoint and operates with the overprivileged handler's permissions — creating admin users, setting passwords, modifying attributes. Full provisioning takeover.
This is the chain no individual control sees. It composes existing detections (it does NOT duplicate them): the unauthenticated endpoint is also caught by CTL.APIGATEWAY.AUTH.001, the env-var token by CTL.LAMBDA.ENV.SECRETS.001, the overprivileged role by CTL.LAMBDA.ROLE.LEASTPRIV.001. The FN trap is an AWS_IAM-authorized endpoint whose API Gateway resource policy allows Principal:"*" — IAM auth with a permissive resource policy is effectively no auth (reuses CTL.APIGATEWAY.AUTH.IAM.UNRESTRICTED.001). Computed by examples/scim-provisioning-takeover/ (Soufflé + Z3, which agree).
Stave covers the infrastructure misconfiguration surface; the SCIM handler's code behaviour (parser differentials, verification bypass, re-provisioning fallback) requires application-level testing — see docs/contract/scim.md.
Infrastructure control inspired by Doyensec "SCIM Hunting — Beyond SSO".

**Remediation:** Break any one link: enforce gateway authentication on the SCIM route (and fix a Principal:"*" API Gateway resource policy), scope the handler role to provisioning-only on the managed pool, and move the token to Secrets Manager with a restricted resource policy and rotation. Each fix also clears its standalone finding (AUTH.001 / ROLE.LEASTPRIV.001 / ENV.SECRETS.001).

---

### CTL.LAMBDA.SECRETS.BROKEN.REF.001

**Lambda Secret References Must Match Execution Role Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** secrets
- **Compliance:** nist_800_53_r5: AC-3; owasp_nhi: NHI2; pci_dss_v4: 7.2;

Lambda functions whose environment variables reference Secrets Manager ARNs or SSM Parameter Store names must have execution roles whose IAM policy grants the appropriate fetch action (`secretsmanager:GetSecretValue` for SM, `ssm:GetParameter` / `ssm:GetParameters` for SSM) on the referenced resource. The deployment is set up with the right reference but the wrong (or missing) permission: the env var carries the ARN, the application code calls GetSecretValue with that ARN, and the call fails with AccessDeniedException. The function then either crashes (when it does not handle the error path) or operates in a degraded mode (when it falls back to a default or skips the credential-using operation), and the failure is consistent across every cold start. The pattern is almost always a deployment misconfiguration: the secret was created and the env var was wired, but the IAM policy update that grants the fetch was either never authored (the IaC is split across teams) or was scoped to the wrong ARN (a previous version of the secret, a sibling secret, or a wildcard that intentionally excluded this one). Cross-resource reasoning: env var references are joined against role policy grants to detect the mismatch.

**Remediation:** Add the GetSecretValue / GetParameter grant to the role's policy, scoped to the referenced ARN.

---

### CTL.LAMBDA.SECRETS.NOTMANAGED.001

**Lambda Functions Must Manage Credentials via Secrets Manager or SSM SecureString**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** secrets
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: IA-5; owasp_nhi: NHI2, NHI9; pci_dss_v4: 8.2;

Lambda functions that hold credential-shaped environment variables (DB_PASSWORD, API_KEY, SECRET_TOKEN, OAUTH_*, AUTH_TOKEN, and similar) must reference those values through Secrets Manager ARNs or SSM Parameter Store SecureString parameters at runtime, not store them as raw values in the function's environment block. Raw credentials in env vars are visible to any principal with `lambda:GetFunctionConfiguration` (a much broader set than the secrets-fetch IAM permission would be), persist immutably in every published function version (rotating the live credential leaves the old value in every historical version snapshot — see CTL.LAMBDA.ENV.VISIBLE.VERSIONS.001), are not CloudTrail-audited at the read level (only function- configuration reads are logged, not env var reads), and do not rotate without a function configuration update (which means rotation in practice happens rarely or never). Secrets Manager (and SSM SecureString) centralizes the credential, supports automatic rotation, logs every retrieval via CloudTrail with the IAM identity that fetched it, and keeps the credential value out of the function configuration entirely. Distinct from CTL.LAMBDA.ENV.SECRETS.001, which detects the pattern; this control checks for the management alternative.

**Remediation:** Move the credentials to Secrets Manager or SSM SecureString; reference the ARN from the env var; remove the raw values.

---

### CTL.LAMBDA.SECRETS.SSM.INSECURE.001

**Lambda SSM Parameter References Must Use SecureString**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** secrets
- **Compliance:** nist_800_53_r5: SC-28; owasp_nhi: NHI2, NHI9; pci_dss_v4: 3.4;

Lambda functions whose environment variables reference SSM Parameter Store parameters that hold credentials must reference SecureString-typed parameters, not String-typed ones. SSM Parameter Store String type stores values in plaintext: the parameter is readable by any principal holding `ssm:GetParameter` (a much broader IAM action than the kms:Decrypt that SecureString reads require), is visible in the SSM console without an additional decrypt step, is unencrypted at rest, and provides no CloudTrail signal for its read operations distinct from generic parameter reads. SecureString-typed parameters encrypt the value with KMS, gate reads on `kms:Decrypt` against the key policy, log every decrypt in CloudTrail under the calling identity, and store ciphertext at rest. The pattern that produces this finding is a one-shot parameter creation that took the SSM default (String) for what was clearly a credential, or a refactor where the parameter was migrated to a new name without re-typing as SecureString. Same architectural pattern as the S3 / RDS / Secrets-Manager equivalence: managed storage is necessary but not sufficient — the storage type matters.

**Remediation:** Recreate the parameter as SecureString (or migrate the credential to Secrets Manager) and update the env var reference.

---

### CTL.LAMBDA.TIMEOUT.001

**Lambda Function Timeout Must Not Exceed Safe Threshold**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(7); nist_800_53_r5: SC-5; soc2: A1.1;

Lambda functions must not have a timeout exceeding the safe threshold (default 60 seconds) without a documented justification. Excessively long timeouts amplify Denial of Wallet attacks (pricing is per-millisecond), mask hung or compromised functions, and contribute to account-wide concurrency exhaustion. The threshold is configurable per function via a stave/lambda-timeout-justified tag.

**Remediation:** Reduce the timeout to 60 seconds or less for synchronous API-serving functions. If a longer timeout is operationally required, add a stave/lambda-timeout-justified tag documenting the reason.

---

### CTL.LAMBDA.TRACE.001

**Lambda Functions Must Have Active X-Ray Tracing Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2.1; soc2: CC7.1;

Lambda functions must have X-Ray tracing set to Active, not PassThrough. Active tracing captures downstream service calls independently of function log output — providing an audit trail of what the function actually did at the infrastructure layer. PassThrough tracing only traces requests with upstream sampling decisions, creating a detection gap exploitable by compromised functions that suppress their own log output.

**Remediation:** Set the function tracing mode to Active via aws lambda update-function-configuration --tracing-config Mode=Active.

---

### CTL.LAMBDA.TRIGGER.APIGATEWAY.NOAUTH.001

**Lambda Behind API Gateway Without Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 6.4.2; soc2: CC6.1;

Lambda functions invoked via API Gateway must not be exposed through routes that have no authentication configured. A route with no IAM auth, no Cognito authorizer, no Lambda authorizer, and no API key requirement is a public endpoint — anyone who discovers the URL can invoke the function with any payload. The API Gateway provides throttling (unlike Function URLs) but no identity verification, so every unauthenticated invocation exercises the function's full execution-role permissions and accumulates Lambda invocation cost. Distinct from CTL.LAMBDA.URL.AUTH.001 which guards Function URL AuthType NONE; this control guards the API Gateway integration layer, where the public-invocability gate is the route's authorizer rather than the function URL config.

**Remediation:** Attach an authorizer to the route — IAM auth (AuthType AWS_IAM), Cognito user pool authorizer, Lambda authorizer, or API key requirement. For public APIs that must remain unauthenticated, document the exposure and reduce blast radius by tightening the function's execution-role permissions.

---

### CTL.LAMBDA.TRIGGER.CONFUSEDDEPUTY.001

**Lambda Trigger Allows Invocation Without Source Restriction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** access
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 1.2.1; soc2: CC6.1;

Lambda resource policy must not allow a service principal (s3.amazonaws.com, sns.amazonaws.com, events.amazonaws.com, apigateway.amazonaws.com, etc.) to invoke the function without an aws:SourceArn or aws:SourceAccount condition. Without one of these conditions, ANY resource of that service type in ANY account can trigger the function — the Lambda confused-deputy problem. An attacker creates an S3 bucket in their own account, configures a notification to the function ARN, uploads a crafted object, and the function is invoked with the attacker payload — executing with the function's full execution-role permissions. This is distinct from CTL.LAMBDA.POLICY.CROSSACCOUNT.001 which guards account-principal grants; this control guards the service-principal invocation surface, where the attacker doesn't need an account principal at all — the service itself is the principal and the missing source condition removes the account boundary.

**Remediation:** Add an aws:SourceArn (preferred — restricts to a specific source resource) or aws:SourceAccount (restricts to a specific account) condition to each service-principal invoke statement via aws lambda add-permission --source-arn or --source-account.

---

### CTL.LAMBDA.TRIGGER.GHOST.001

**Lambda Event Source Mappings Must Not Reference Deleted Sources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: SI-4; soc2: CC7.1;

Lambda event source mappings must not reference deleted SQS queues, DynamoDB streams, or Kinesis streams. The mapping enters an error state but the failure is surfaced only in the Lambda console. If the function processes security events, that processing stops silently.

**Remediation:** Update or remove the event source mapping.

---

### CTL.LAMBDA.UPDATECODE.SCOPE.001

**lambda:UpdateFunctionCode Must Not Be Broadly Granted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-6; nist_800_53_r5: AC-6; soc2: CC6.1;

IAM policies must not grant lambda:UpdateFunctionCode with Resource: * to non-administrative principals. Broad UpdateFunctionCode allows any developer to replace the code of any Lambda function in the account — injecting malicious code that executes with that function's execution role permissions.

**Remediation:** Scope lambda:UpdateFunctionCode to specific function ARNs in IAM policies. Restrict code deployment to CI/CD pipeline roles only.

---

### CTL.LAMBDA.URL.AUTH.001

**Lambda Function URLs Must Require Authentication**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; hipaa: 164.312(a)(1); nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

Lambda function URLs must not be configured with AuthType NONE. A function URL with no authentication creates a publicly invocable HTTPS endpoint — no API Gateway, no Cognito, no IAM signature, no network boundary. Any person on the internet can invoke the function with no credentials. The function executes with its full IAM execution role permissions and generates costs for every invocation including attacker-driven invocations. Function URLs bypass every network perimeter control — VPC, security groups, NACLs — that would otherwise restrict access to Lambda invocation. This is distinct from public invocation via the Lambda resource-based policy: a function with a restrictive resource policy can still be publicly invocable if it has a function URL with AuthType NONE. The Denial of Wallet risk is significant — Lambda pricing is per invocation and an unauthenticated endpoint allows unlimited invocations with no cost ceiling.

**Remediation:** Set the function URL AuthType to AWS_IAM to require IAM signature authentication for all invocations. If the function URL is not needed, remove it entirely via aws lambda delete-function-url-config. Note that Lambda resource-based policy restrictions do not apply to function URL invocations — AuthType is the only authentication gate for function URLs.

---

### CTL.LAMBDA.URL.CORS.001

**Function URLs Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

Lambda function URLs can attach a Cors block whose AllowOrigins and AllowCredentials values control cross-origin access. A function URL that sets AllowOrigins to "*" together with AllowCredentials=true encodes intent that any web origin should be able to make credentialed requests against the function. Browsers refuse the combination, but the configuration reveals misaligned intent about which origins should be permitted. This compounds badly with AuthType=NONE (covered separately by CTL.LAMBDA.URL.AUTH.001): a function URL that is both unauthenticated AND has permissive CORS signals a function URL whose access control has not been thought through at all. The observation shape mirrors the Cors block returned by "aws lambda get-function-url-config".

**Remediation:** Update the function URL config via "aws lambda update-function-url-config --function-name <name> --cors '...'" with either AllowCredentials set to false or an AllowOrigins list that enumerates specific origins. If the function handles sensitive operations, also confirm AuthType is AWS_IAM (see CTL.LAMBDA.URL.AUTH.001).

---

### CTL.LAMBDA.VPC.ENDPOINTS.001

**VPC-Attached Lambda Functions Must Use VPC Endpoints for AWS Services**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** network
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

Lambda functions attached to a VPC must use VPC endpoints for AWS service access (S3, DynamoDB, STS, Secrets Manager) instead of routing through NAT gateways or internet gateways. Traffic through NAT leaves the VPC, traverses the public internet, and creates an exfiltration channel.

**Remediation:** Create VPC endpoints (gateway or interface) for the AWS services the function accesses: S3 (gateway), DynamoDB (gateway), Secrets Manager (interface), STS (interface). Associate the endpoints with the function's subnets.

---

### CTL.LAMBDA.VPC.SENSITIVE.001

**Lambda Functions Accessing Sensitive Data Must Be in VPC**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Lambda functions tagged with data-classification phi or pii, or functions whose execution role grants access to RDS, DocumentDB, or DynamoDB, must be configured to run inside a VPC. Without VPC, the function executes in AWS-managed infrastructure with direct internet egress — data accessed by the function can be exfiltrated without traversing any network controls.

**Remediation:** Configure the function to run in a VPC with private subnets. Use a NAT gateway for outbound internet access if needed.

---

### CTL.LAMBDA.VPC.SUBNET.001

**Lambda Functions in VPC Must Use Private Subnets**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.1; soc2: CC6.6;

Lambda functions configured to run in a VPC must use private subnets with no direct route to an internet gateway. A function in a public subnet retains direct internet egress despite VPC enrollment — negating the network isolation that VPC membership is intended to provide. This is the complement to CTL.LAMBDA.VPC.SENSITIVE.001: VPC enrollment plus private subnet enforcement together close the network isolation requirement.

**Remediation:** Move the function to private subnets. Use a NAT gateway in a public subnet for outbound access.

---

