# Control Reference — APIGATEWAY

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APIGATEWAY.ACCESSLOG.CMK.001

**API Gateway Access Log Group Not Encrypted With Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-9, SC-12, SC-28; hipaa: 164.312(a)(2)(iv), 164.312(e)(2)(ii); iso_27001_2022: A.8.24; nist_800_53_r5: AU-9, SC-12, SC-13, SC-28; pci_dss_v4.0: 3.5, 10.5; soc2: CC6.1, CC6.7;

Access log destination CloudWatch log group is encrypted with the AWS-managed key (the default) instead of a customer-managed KMS key. The log group is technically "encrypted at rest" under either key, but the AWS-managed key cannot be revoked by the customer, has no customer-side audit trail of who decrypted what, and cannot be scoped by IAM policy distinct from the broader CloudWatch service role. Customer-managed keys allow per-key access policies, separate CloudTrail records of decrypt calls, key rotation cadence the customer controls, and emergency revocation by disabling the key. Compliance frameworks that require customer-controlled encryption (HIPAA, FedRAMP High, several PCI interpretations) typically don't accept the AWS-managed key.

**Remediation:** Associate a customer-managed KMS key with the log group: aws logs associate-kms-key --log-group-name <name> --kms-key-id arn:aws:kms:REGION:ACCOUNT:key/<id>. The key policy must allow the CloudWatch Logs service principal in the appropriate region to encrypt and decrypt; AWS publishes the required policy snippet. New log streams are encrypted under the new key; existing log streams remain encrypted under whatever key was active when they were written.

---

### CTL.APIGATEWAY.ACCESSLOG.FORMAT.INCOMPLETE.001

**API Gateway Access Log Format Missing Critical Fields**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-2, AU-3, AU-6; iso_27001_2022: A.8.15, A.8.16; nist_800_53_r5: AU-2, AU-3, AU-6; pci_dss_v4.0: 10.2, 10.3; soc2: CC7.2, CC7.3;

Access logging is enabled but the configured access log format omits at least one of the fields needed for incident response and audit: $context.requestId, $context.identity.caller or $context.identity.user, $context.identity.sourceIp, $context.responseLatency, $context.status. With these fields missing, an investigator looking at the logs cannot answer the questions an incident demands: who called this method, from where, how long did it take, what status did API Gateway return, what was the request correlation ID for cross-system tracing. The log line still exists and counts as "logging enabled" in compliance reporting, but its forensic value is near zero.

**Remediation:** Update the stage's access log format to include the full investigation-ready set: $context.requestId, $context.identity.sourceIp, $context.identity.caller (or $context.identity.user / $context.authorizer.principalId depending on auth type), $context.requestTime, $context.httpMethod, $context.resourcePath, $context.status, $context.responseLatency, $context.responseLength. aws apigateway update-stage with --patch-operations op=replace,path=/accessLogSettings/format,value=<json-template>. The AWS-recommended JSON format covers the full set; verify nothing has been pruned.

---

### CTL.APIGATEWAY.ACCESSLOG.RETENTION.001

**API Gateway Access Log Group Has No Retention Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-4, AU-11; iso_27001_2022: A.5.33, A.8.10; nist_800_53_r5: AU-4, AU-11, SI-12; pci_dss_v4.0: 10.5, 10.7; soc2: CC7.2, A1.1;

Access logging is enabled with a CloudWatch log group destination, but the log group has no retention policy configured (defaults to "Never expire"). Logs accumulate indefinitely. The cost grows month over month for data that most operators only need for the audit window the compliance framework prescribes (typically 90 days to 7 years depending on industry). The data also accumulates as a regulatory liability — logs that exist must be produced under subpoena, including whatever sensitive data leaks into the access log format.

**Remediation:** Set the log group retention to the period the compliance framework requires (or the operator-chosen window, whichever is longer): aws logs put-retention-policy --log-group-name /aws/apigateway/<api> --retention-in-days 365. Common values: 90 (general security), 365 (SOC 2), 2557 (HIPAA 7 years). For longer-than-CloudWatch retention windows, configure subscription filters to ship into S3 with object lifecycle policies and Glacier transitions.

---

### CTL.APIGATEWAY.ACCESSLOG.S3.NODELETE.001

**Access Log S3 Destination Bucket Allows DeleteObject**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 3.6; fedramp_moderate: AU-9, AU-11; iso_27001_2022: A.5.33, A.8.10, A.8.15; nist_800_53_r5: AU-9, AU-11; pci_dss_v4.0: 10.5, 10.7; soc2: CC6.1, CC7.2, CC8.1;

REST or HTTP API stage delivers access logs to an S3 destination, but the bucket policy or default IAM allows s3:DeleteObject for principals beyond the operator's intended retention boundary. An attacker who reaches the destination bucket can delete log objects to erase the audit trail of their activity. Access log buckets should enforce object-level immutability via a deny-DeleteObject bucket policy (or S3 Object Lock with appropriate retention), so logs persist for the audit window regardless of who has bucket access.

**Remediation:** Add a bucket policy that denies s3:DeleteObject (and s3:DeleteObjectVersion if versioning is enabled) for all principals except a tightly-scoped lifecycle role: aws s3api put-bucket-policy with a Deny statement on DeleteObject. Or enable S3 Object Lock with Compliance mode and a retention period matching the audit window — Object Lock prevents deletion even from the bucket owner during the retention period.

---

### CTL.APIGATEWAY.ACCOUNT.THROTTLE.DEFAULT.001

**API Gateway Account-Level Throttle At AWS Default Without Operator Review**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5, CM-2; iso_27001_2022: A.5.30, A.8.6; nist_800_53_r5: SC-5, CM-2; pci_dss_v4.0: 6.4.1; soc2: A1.1, CC6.6, CC8.1;

Account-level API Gateway throttle is at the AWS default (10000 RPS, 5000 burst) and no operator-recorded review exists in the account's configuration history. The account- level throttle is the ceiling against which every stage and every usage plan competes — one runaway stage can absorb the entire account's capacity, denying service to every other API in the account. The default value isn't inherently wrong; it's the absence of operator review that matters. Accounts hosting only a few low-traffic APIs should be far below 10000; accounts hosting high-traffic production workloads may legitimately request quota increases from AWS and should record the rationale.

**Remediation:** Either record an operator review confirming the default is appropriate (annotate via account tags or an SSM parameter documenting the review date and reviewer), or adjust the account-level throttle to match the portfolio. aws apigateway update-account with --patch-operations op=replace,path=/throttleSettings/rateLimit,value=<rps>. For accounts hosting public APIs, lower bounds force per- stage throttling decisions to be deliberate; for backend- integration accounts, much lower limits often suit the actual traffic profile.

---

### CTL.APIGATEWAY.ALARM.4XX.001

**No CloudWatch Alarm on API Gateway 4xx Error Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.4, 10.7, 11.5; soc2: CC7.2, CC7.3;

API Gateway stage emits the 4XXError metric to CloudWatch but no alarm watches it. 4xx errors are usually client mistakes — bad input, missing auth — but a sustained spike is a strong signal of attack probing: credential stuffing produces 401/403 spikes, parameter fuzzing produces 400/422 spikes, authorizer-bypass attempts produce 401 spikes. Alarming on a 4xx baseline plus deviation gives early warning of reconnaissance and active attack — well before the 5xx alarm fires from a successful exploitation.

**Remediation:** Create an alarm on AWS/ApiGateway namespace, 4XXError metric, dimensioned by ApiName/Stage. Threshold should reflect baseline plus reconnaissance headroom — a 5x increase over rolling baseline is a common attack-probing signal. aws cloudwatch put-metric-alarm with --metric-name 4XXError. Pair with a separate alarm on 401/403 specifically if the access log format breaks out status — credential-stuffing detection benefits from the narrower signal.

---

### CTL.APIGATEWAY.ALARM.5XX.001

**No CloudWatch Alarm on API Gateway 5xx Error Rate**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.4, 10.7; soc2: CC7.2, CC7.3;

API Gateway stage emits the 5XXError metric to CloudWatch but no alarm watches it. 5xx errors indicate backend failures, integration timeouts, Lambda concurrency exhaustion, authorizer outages — the operations conditions that need on-call attention. Without an alarm, problems surface only through user complaints or downstream dashboards that someone happens to be watching. The metric is published whether anyone is alarming on it; the cost of an alarm is near-zero, the cost of unnoticed backend failure compounds with time.

**Remediation:** Create an alarm on AWS/ApiGateway namespace, 5XXError metric, dimensioned by ApiName/Stage. Threshold should reflect baseline error rate plus operational headroom — a 1% sustained rate over 5 minutes is a common starting point. aws cloudwatch put-metric-alarm with --metric-name 5XXError --namespace AWS/ApiGateway. Alarm targets should include the service- owning team's pager / Slack channel.

---

### CTL.APIGATEWAY.ALARM.CONFIGCHANGE.001

**No Alarm on API Gateway Configuration Change Events**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: AU-6, AU-12, SI-4; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, AU-12, SI-4; pci_dss_v4.0: 10.4, 12.10; soc2: CC7.2, CC8.1;

No CloudWatch alarm fires when API Gateway configuration changes (CreateStage, DeleteStage, CreateAuthorizer, DeleteAuthorizer, UpdateRestApi, CreateDeployment, CreateApiKey, etc.). API Gateway management API calls land in CloudTrail, but without a metric filter on the relevant events and an alarm on the metric, configuration drift surfaces only when someone audits the trail manually. Configuration drift on production APIs warrants real-time visibility — the wrong stage gets enabled, an authorizer gets removed, a deployment lands without review.

**Remediation:** Create a CloudWatch metric filter on the CloudTrail log group matching API Gateway management events: eventSource=apigateway.amazonaws.com AND eventName=(CreateStage|DeleteStage|CreateAuthorizer| DeleteAuthorizer|UpdateRestApi|UpdateStage|...). aws logs put-metric-filter with the pattern, then aws cloudwatch put-metric-alarm on the metric. Alarm targets should reach the API-owning team; deletion events may warrant a higher-priority pager target.

---

### CTL.APIGATEWAY.ALARM.COUNT.DDOS.001

**No CloudWatch Alarm on API Gateway Request Count Spike**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SC-5; iso_27001_2022: A.5.25, A.8.6, A.8.16; nist_800_53_r5: AU-6, IR-4, SC-5, SI-4; pci_dss_v4.0: 10.4, 11.5; soc2: CC7.2, A1.1;

API Gateway stage publishes the Count metric to CloudWatch but no alarm watches it for traffic spikes. Volume spikes signal: legitimate viral traffic that needs capacity scaling, application-layer DDoS that needs WAF rate-rule tightening, or runaway clients caught in a retry loop. All three demand on-call attention; without an alarm, none of them surfaces until customer impact or cost reports arrive. Pair with the existing 4XX / 5XX / latency / throttle alarms; Count catches volume excursions those don't (a flood of 200s isn't an error spike but is still operationally meaningful).

**Remediation:** Create an alarm on the AWS/ApiGateway namespace Count metric, dimensioned by ApiName/Stage, with a deviation- from-baseline threshold (e.g., 5x rolling average over 5 minutes). aws cloudwatch put-metric-alarm with --metric-name Count --threshold <baseline*5>. For accounts with very dynamic traffic, anomaly detection alarms are a better fit than fixed thresholds.

---

### CTL.APIGATEWAY.ALARM.LATENCY.001

**No CloudWatch Alarm on API Gateway Latency**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SI-4; iso_27001_2022: A.5.25, A.8.6, A.8.16; nist_800_53_r5: AU-6, IR-4, SI-4; pci_dss_v4.0: 10.4; soc2: CC7.2, A1.1, A1.2;

API Gateway stage emits the Latency and IntegrationLatency metrics to CloudWatch but no alarm watches either. Latency alarms are how operators learn the backend is slowing down before customers notice. Latency excursions often precede outages: backend connection-pool exhaustion, downstream dependency degradation, Lambda cold-start storms. The two metrics are complementary — Latency is end-to-end (including API Gateway overhead and authorizer time); IntegrationLatency isolates the backend hop. Alarming on both gives both customer-visible signal and root-cause attribution.

**Remediation:** Create alarms on AWS/ApiGateway namespace for both Latency and IntegrationLatency, dimensioned by ApiName/Stage. P99 threshold tied to the SLO is the standard pattern; a P50 threshold flags broader degradation. aws cloudwatch put-metric-alarm with --metric-name Latency --extended-statistic p99 --threshold <ms>. Document the SLO in the runbook so on-call has the right action when the alarm fires.

---

### CTL.APIGATEWAY.ALARM.RESOURCEPOLICY.CHANGE.001

**No Alarm on API Gateway Resource Policy Modifications**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** cis_aws_v3.0: 4.7; fedramp_moderate: AU-6, AU-12, SI-4, AC-3; iso_27001_2022: A.5.25, A.8.16; nist_800_53_r5: AU-6, AU-12, SI-4, AC-3; pci_dss_v4.0: 10.4, 7.1; soc2: CC6.1, CC7.2, CC8.1;

No CloudWatch alarm fires when an API Gateway resource policy is modified (UpdateRestApi with a policy patch). Resource policies are the network-and-principal authorization layer on REST APIs — they decide whether a request is allowed based on source VPC, source IP, principal ARN, or organization ID. Modifications open or close the API to classes of callers; an attacker with apigateway:UpdateRestApi permission can flip a private API to allow Principal=*, and the change should be the highest-priority alarm category in the API Gateway monitoring set.

**Remediation:** Create a CloudWatch metric filter on the CloudTrail log group matching policy patches: eventSource=apigateway.amazonaws.com AND eventName=UpdateRestApi AND requestParameters.patchOperations.path contains "/policy". aws logs put-metric-filter, then aws cloudwatch put-metric-alarm with --threshold 1 (any occurrence is meaningful). Alarm should page on-call immediately and route to a security pager during off- hours.

---

### CTL.APIGATEWAY.ALARM.THROTTLE.001

**No CloudWatch Alarm on API Gateway Throttled (429) Responses**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** fedramp_moderate: AU-6, IR-4, SC-5; iso_27001_2022: A.5.25, A.8.6, A.8.16; nist_800_53_r5: AU-6, IR-4, SC-5, SI-4; pci_dss_v4.0: 10.4; soc2: CC7.2, A1.1;

API Gateway stage emits the ThrottleCount or 429 status metric to CloudWatch but no alarm watches it. 429 responses are the customer-visible signal that traffic exceeded the configured rate, burst, or quota. A spike has two distinct causes that demand different responses: legitimate traffic growth (bump the limit) or rate-based attack (lower the limit further or shift to WAF). Without an alarm, customer impact persists until the affected user reports it. A baseline of zero throttled requests is the typical safe state; any sustained non-zero rate is operationally meaningful.

**Remediation:** Create an alarm on AWS/ApiGateway namespace, ThrottleCount metric (or a metric filter on access logs filtering status=429 if the stage has access logs and metric filters), dimensioned by ApiName/Stage. Threshold should be very low — a sustained non-zero rate is meaningful — paired with a longer evaluation period to avoid alerting on incidental bursts. aws cloudwatch put-metric-alarm with --metric-name ThrottleCount --threshold 1.

---

### CTL.APIGATEWAY.API.NOCUSTOMDOMAIN.001

**REST API Has No Custom Domain Mapped to Any Stage**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: CM-2, SC-7; soc2: CC6.1, CC6.6, CC8.1;

REST API serves traffic only on the default execute-api domain (e.g., abcdef.execute-api.us-east-1.amazonaws.com) with no custom domain mapped to any of its stages. The default execute-api domain is a public AWS-managed name — it appears in URLs clients see, it changes if the API is recreated, and it doesn't carry the operator's TLS policy / WAF / mutual-TLS configuration that custom domains enable. APIs serving production-shaped traffic should publish at a custom domain the operator owns; the default endpoint is suitable for development and quick prototypes but not for long-lived public-facing services.

**Remediation:** Provision a custom domain with an ACM certificate matching the operator's preferred hostname: aws apigateway create-domain-name --domain-name api.example.com --regional-certificate-arn <arn> --endpoint-configuration types=REGIONAL. Map it to the API stage: aws apigateway create-base-path-mapping --domain-name api.example.com --rest-api-id <id> --stage <stage>. Pair with the existing CTL.APIGATEWAY.ENDPOINT.DEFAULT.001 control which flags whether the default endpoint is also disabled.

---

### CTL.APIGATEWAY.APIKEY.SOURCE.HEADER.LOGGED.001

**API Key Source HEADER While Access Log Captures the Key Header**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-9, IA-5, SC-28; hipaa: 164.312(a)(2)(iv); iso_27001_2022: A.5.16, A.8.15; nist_800_53_r5: AU-9, IA-5, SC-28; pci_dss_v4.0: 3.5, 8.3, 10.5; soc2: CC6.1, CC6.7;

REST API key source is set to HEADER (clients send the key as the x-api-key request header), and the access log format includes $context.identity.apiKey or $context.requestOverride.header.x-api-key — or a verbose $context.requestOverride.header.* expansion. The access log persists every API key that any client sends. Logs end up in CloudWatch or S3, both common access targets for internal audit, ops dashboards, and downstream analytics pipelines. API keys that should be opaque session tokens become searchable strings sitting at rest in log storage. Anyone with log read access reads every key in use.

**Remediation:** Remove $context.identity.apiKey and any header expansion that captures x-api-key from the access log format: aws apigateway update-stage with --patch-operations op=replace,path=/accessLogSettings/format,value=<sanitized-format>. If audit needs to know which key authenticated the request, log $context.identity.apiKeyId (the AWS-managed identifier) rather than the secret value. Consider migrating from API keys to a stronger primitive (Cognito, IAM, JWT) for any API where the key authenticates a human or production system.

---

### CTL.APIGATEWAY.AUTH.001

**API Routes Must Have Authorization Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

API Gateway routes and methods must have an authorizer configured (Cognito, Lambda, IAM, or JWT). Routes with authorization set to NONE are publicly accessible without any identity verification. The Trello breach (2024) exposed 15 million accounts through an unauthenticated API endpoint. The Spoutible breach (2024) leaked user data through an API without proper auth checks.

**Remediation:** Configure an authorizer on all non-health-check routes. Use Cognito user pools, Lambda authorizers, IAM authorization, or JWT authorizers depending on the client type.

---

### CTL.APIGATEWAY.AUTH.APIKEY.SOLE.001

**API Gateway Uses API Key as Sole Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2; nist_800_53_r5: IA-2; pci_dss_v4.0: 8.2; soc2: CC6.1;

API Gateway method or route requires an API key but has no other authorizer (no IAM, no Cognito, no Lambda authorizer, no JWT). API keys are identifiers, not credentials — AWS documentation explicitly states they are not meant for authentication or authorization. They are plain strings sent in the x-api-key header, shared across users (no per-user identity), often hardcoded in mobile and SPA clients (extractable via decompilation or DevTools), logged in proxy and CDN access logs, and not rotatable without breaking all clients simultaneously. API key as sole auth means anyone with the key string has full API access with no identity attribution.

**Remediation:** Attach an authorizer (IAM, Cognito, Lambda authorizer, or JWT) to the route. The API key, if still needed, then serves its intended purpose — usage tracking, throttling, and quota enforcement — alongside the authorizer's identity check. If the route is intentionally public, remove the api_key_required flag so the lack of auth is explicit rather than disguised by a key that grants no real protection.

---

### CTL.APIGATEWAY.AUTH.COGNITO.MULTICLIENT.001

**Cognito Authorizer Accepts Tokens From Any App Client in Pool**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, AC-3, AC-6; iso_27001_2022: A.5.15, A.5.16; nist_800_53_r5: AC-2, AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2, 8.3; soc2: CC6.1, CC6.3;

Cognito user pool authorizer is attached to a user pool but the authorizer's allowed app-client list is empty or wildcarded. Any access token issued by any app client in the pool is accepted. User pools commonly host multiple applications: the consumer mobile app, the partner portal, the internal admin console — each typically has its own app client. With no client-ID restriction, a token issued for the consumer app is also accepted by the admin API. A leaked or compromised consumer token grants admin access if the admin API also trusts the same pool.

**Remediation:** Configure the Cognito authorizer's identity validation to pin the specific app client IDs that should be accepted. In a Lambda authorizer fronting Cognito, validate the token's client_id (id token) or aud (access token) claim against an allowlist. For HTTP API JWT authorizers, set the audience field to the specific client IDs. Document which app clients legitimately reach this API and reject tokens from others.

---

### CTL.APIGATEWAY.AUTH.COGNITO.SCOPE.MISSING.001

**Cognito User Pool Authorizer Without Scope Validation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, AC-3, AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-2, AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

REST API method protected by a Cognito user pool authorizer is configured without authorization scopes. With no scopes, any valid access token from the user pool is accepted regardless of the OAuth scopes the token was issued for. A token issued for read-only access to the catalog endpoint is also accepted by the admin endpoint, the billing endpoint, and every other method attached to the same authorizer. Scopes are the per-method ACL — without them, the authorizer collapses to authentication only, and authorization is delegated entirely to the application code (which often performs no further check).

**Remediation:** Set authorizationScopes on the method integration with the OAuth scopes that should be required: aws apigateway update-method with --patch-operations op=add,path=/authorizationScopes,value=resource-server/read. Define and enforce per-method scopes that match the operation's sensitivity (read vs. write, public-read vs. admin). Cognito user pool app clients must be configured to issue the corresponding scopes.

---

### CTL.APIGATEWAY.AUTH.IAM.UNRESTRICTED.001

**IAM-Authorized Method Without Resource-Level Restriction**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, AC-3, AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-2, AC-3, AC-6; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3;

REST API method uses AWS_IAM authorization, but no resource policy restricts which IAM principals can invoke. With AWS_IAM alone, every IAM principal in the AWS account that holds execute-api:Invoke on this API's ARN can call the method. In large accounts that's hundreds or thousands of principals — far beyond the intended caller set. AWS_IAM is the authentication layer; the authorization layer is the resource policy. Without a resource policy that names specific principals or scopes invocation by VPC, source IP, or organization, the method is effectively open to every IAM identity that can hit it.

**Remediation:** Attach a resource policy that names the specific principals permitted to invoke (Principal: AWS: arn:aws:iam::ACCOUNT:role/X) or scopes by source VPC / source IP / aws:PrincipalOrgID. aws apigateway update-rest-api with --patch-operations op=replace,path=/policy,value=<json>. For private APIs, scope by aws:SourceVpce. For public-internet APIs, scope by aws:PrincipalOrgID to the organization that should reach the API.

---

### CTL.APIGATEWAY.AUTH.JWT.AUDIENCE.001

**HTTP API JWT Authorizer Without Audience Validation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-2; nist_800_53_r5: IA-2; pci_dss_v4.0: 8.2; soc2: CC6.2;

HTTP API JWT authorizer does not validate the audience (aud) claim. Without audience validation, any valid JWT signed by the configured issuer is accepted — regardless of which application it was issued for. If the issuer (Auth0, Cognito, Okta, or any IdP serving multiple applications) issues tokens for Application A, those tokens can be used to access this API even if it is Application B. The token is legitimately signed and not expired but was never intended for this audience. Audience validation ties the token to this API's specific client ID.

**Remediation:** Configure the audience claim on the JWT authorizer with the specific client ID(s) that should be accepted. In the API Gateway console: Authorizer → Edit → Audience. Multiple audiences are allowed; an empty audience list is the unsafe state. Verify that the issuer URL is also pinned and uses HTTPS.

---

### CTL.APIGATEWAY.AUTH.WEBSOCKET.001

**WebSocket API $connect Route Has No Authorizer**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 8.2; soc2: CC6.1;

WebSocket API's $connect route has no authorizer. WebSocket APIs authenticate only at connection time — once a connection is established, the client can send messages to any route ($default, custom routes) without further authentication. If $connect has no authorizer, any client can establish a WebSocket connection, send messages to all routes, receive responses, and maintain the connection indefinitely. For WebSocket APIs that provide real-time data, execute commands, or access internal services, unauthenticated $connect means unauthenticated access to all WebSocket functionality.

**Remediation:** Attach an authorizer (Lambda authorizer or IAM auth) to the $connect route. The $connect route is the only place where WebSocket APIs can enforce authorization — message-level checks are not a substitute. If the API is intentionally public (e.g., a public chat broadcast), document the intent in an exemption rather than relying on the absence of auth.

---

### CTL.APIGATEWAY.AUTHORIZER.LAMBDA.CACHE.LONG.001

**Lambda Authorizer Cache TTL Exceeds Recommended Ceiling**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, AC-3, IA-2; iso_27001_2022: A.5.16, A.8.2; nist_800_53_r5: AC-2, AC-3, IA-2; pci_dss_v4.0: 8.2, 8.3; soc2: CC6.1, CC6.2;

Lambda authorizer is configured with an authorization cache TTL greater than 300 seconds. API Gateway caches the authorizer's IAM policy decision for the configured TTL — once cached, the cached policy is reused for matching tokens without re-invoking the authorizer Lambda. A long TTL means revoked tokens, deleted users, scope changes, and policy revocations don't take effect until the cache entry expires. The default and AWS-recommended ceiling is 300 seconds; values up to 3600 are allowed but only appropriate when the upstream identity store guarantees the permissions named in the cached policy can't change within that window.

**Remediation:** Lower the authorizer's authorizer_result_ttl_in_seconds to 300 or less (default is 300). For high-revocation-rate workloads consider 60 seconds or disable the cache entirely (TTL = 0) and accept the per-request authorizer invocation cost. aws apigateway update-authorizer with --patch-operations op=replace,path=/authorizerResultTtlInSeconds,value=300.

---

### CTL.APIGATEWAY.CACHE.ENCRYPT.001

**REST API Cache Must Be Encrypted**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** nist_800_53_r5: SC-28; soc2: CC6.7;

API Gateway REST API stages with caching enabled must encrypt cached responses at rest. Unencrypted cache can expose response payloads, tokens, and PII.

**Remediation:** Enable cache encryption on the stage.

---

### CTL.APIGATEWAY.CACHE.KEY.MISSING.001

**API Gateway Caching Enabled Without Cache Key Parameters**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, SI-10; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SC-5, SI-10; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC7.1;

REST API stage has caching enabled but no cache key parameters are configured. With no key parameters, every request to a given resource+method receives the same cached response regardless of query string, path parameter, or header variation. A user query for /products?id=5 returns the cached response for /products?id=42. The cache turns from a performance accelerator into a correctness hazard — users see other users' data, search results unrelated to the query, responses for resource IDs that aren't theirs. Cache key parameters tell API Gateway which request attributes partition the cache; for any non-trivial endpoint, at least the query string and path parameters that vary the response must be in the key.

**Remediation:** Configure cache key parameters on the method that match the request attributes which legitimately vary the response. aws apigateway put-method with cacheKeyParameters listing method.request.querystring.<name>, method.request.path.<name>, method.request.header.<name>. For per-user caches, key on the auth-derived caller (method.request.header.Authorization or a custom header). For endpoints whose response should not be cached at all, disable caching on the method instead of caching with no keys.

---

### CTL.APIGATEWAY.CACHE.TTL.001

**REST API Cache TTL At Default Maximum**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; soc2: CC6.3;

REST API stage has caching enabled and the cache TTL is left at the AWS default (3600 seconds for REST APIs) or otherwise exceeds a policy-acceptable upper bound. Long TTLs serve stale responses for up to an hour after the underlying state changes. For security-sensitive responses — authorization decisions, account state, permission lookups — stale cached responses mean the system serves obsolete authority: a user whose access was revoked five minutes ago still receives a "permitted" response from cache. Configuration safety is not just about who can read the response; it is about how long stale responses persist after authority changes. APIs that cache authorization-sensitive state must use short TTLs (typically <= 300 seconds) so revocation propagates within a bounded window.

**Remediation:** Reduce cache TTL on the stage or per-method to a value appropriate for the responses being cached. For authorization-sensitive responses, set TTL to 300 seconds or less. For responses that change rarely (static metadata, catalog endpoints), the default 3600 may be acceptable — document that decision in the triage override and acknowledge this control. Disable caching entirely for endpoints that return authorization decisions.

---

### CTL.APIGATEWAY.CORS.001

**HTTP APIs Must Not Combine Wildcard Origin With Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 6.4.1; soc2: CC6.1;

API Gateway v2 HTTP APIs expose CORS configuration at the API level. Setting AllowOrigins to "*" together with AllowCredentials=true is the canonical CORS misconfiguration: browsers reject the combination at request time, so the configuration never succeeds for real clients, but the intent encoded in the resource is credentialed cross-origin access from any origin. This typically indicates the API owner intended to allow a broad set of web clients to make credentialed calls and did not understand that wildcard-plus-credentials is rejected. Real attackers do not need this misconfiguration to be functional — its presence signals that the origin allowlist and credentials policy have not been reasoned about together. The observation shape mirrors the CorsConfiguration object returned by "aws apigatewayv2 get-api".

**Remediation:** Either set AllowCredentials to false and keep the wildcard (if the API is genuinely open and cookies/auth headers are not required), or replace the wildcard in AllowOrigins with the explicit set of origins that need credentialed access. Update via "aws apigatewayv2 update-api --api-id <id> --cors-configuration ...".

---

### CTL.APIGATEWAY.CORS.NOTCONFIGURED.001

**Browser-Facing API Has No CORS Configuration At All**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: CM-2, SC-7; soc2: CC6.1, CC6.6;

REST or HTTP API serves traffic that includes browser-origin requests (the API has documented browser clients, the hosting setup implies SPA / single-page-app traffic, or CloudFront fronts the API for browsers), but no CORS configuration is declared on the API. Without CORS, every cross-origin request from a browser fails the preflight check — legitimate browser-side clients can't reach the API. Operators sometimes add ad-hoc per-method CORS headers in mapping templates as a workaround, but the proper layer is the API-level CORS configuration. The control's complement (CORS configured but with wildcard origins) is already covered by CTL.APIGATEWAY.CORS.001; this control catches the absent-altogether case.

**Remediation:** Configure CORS at the API level: aws apigatewayv2 update-api --cors-configuration with the appropriate AllowOrigins, AllowMethods, AllowHeaders, MaxAge. For REST APIs, configure CORS via per-resource OPTIONS method definitions or via the console's "Enable CORS" helper. Pair with the CORS wildcard control — neither "no CORS at all" nor "CORS allows everything" is the safe state; explicit allow-listed origins are.

---

### CTL.APIGATEWAY.DOMAIN.CERT.EXPIRY.WARN.001

**API Gateway Custom Domain Certificate Expires Within 30 Days**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-12, SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-8, SC-12, SC-17; owasp_nhi: NHI7; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7, CC8.1;

Custom domain certificate is approaching expiry. ACM-issued certificates auto-renew when they're attached to a supported AWS service and DNS validation records remain valid; imported certificates do not — the operator is responsible for re-importing before expiry. The 30-day window catches both auto-renewal failures (DNS records changed, validation broke) and imported-cert renewal oversights. Expired certificates produce hard TLS failures the moment the expiration timestamp passes — clients see certificate-not-valid errors, every API call fails, and the operator finds out from customer reports.

**Remediation:** For ACM-managed certificates, verify auto-renewal is healthy: aws acm describe-certificate to inspect RenewalSummary; failed renewal usually indicates a DNS validation record was deleted. For imported certificates, request and import a renewal: aws acm import-certificate with --certificate, --private-key, --certificate-chain, and the existing certificate ARN to replace in place. Verify the new ARN is associated with the custom domain after import.

---

### CTL.APIGATEWAY.DOMAIN.CERT.NOTACM.001

**API Gateway Custom Domain Certificate Imported Manually Instead of ACM-Issued**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-12, SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: SC-12, SC-17, CM-2; pci_dss_v4.0: 4.2; soc2: CC6.7, CC8.1;

Custom domain certificate is imported into ACM rather than issued by ACM. Imported certificates are valid TLS certificates and ACM holds them, but ACM cannot auto-renew them — the operator must request a new certificate from the issuing CA, import the renewed cert, and re-associate with the custom domain before the existing cert expires. ACM-issued certificates renew automatically (provided DNS validation records remain valid) and the operator is notified before expiry. Manually-imported certs are a recurring operational burden; the manual step is precisely where renewals get missed.

**Remediation:** Migrate to an ACM-issued certificate when feasible: aws acm request-certificate with the same SAN list, complete DNS validation, then update the custom domain to use the new ACM-issued ARN. ACM-issued certificates handle renewal silently. Migration is a one-time effort that eliminates the recurring manual renewal step. For cases where imported certs are required (third-party CA requirements, EV certificates, internal CA chains), document the rationale and implement an external monitor that alerts well before expiry.

---

### CTL.APIGATEWAY.DOMAIN.TLS.001

**API Gateway Custom Domains Must Enforce TLS 1.2+**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-8;

API Gateway custom domain names must enforce a minimum TLS version of 1.2. TLS 1.0 and 1.1 have known protocol-level vulnerabilities including BEAST, POODLE, and weak cipher suites that enable man-in-the-middle attacks. When a custom domain allows TLS below 1.2, an attacker on the network path can downgrade the connection and intercept API credentials, session tokens, or request payloads in transit. AWS API Gateway supports TLS 1.2 as the minimum security policy. Custom domains configured with older TLS versions expose every API behind that domain to protocol downgrade attacks regardless of the application-layer security controls in place.

**Remediation:** Update the custom domain security policy to TLS_1_2. In the API Gateway console or via the AWS CLI, set the security policy on the domain name to TLS_1_2. Verify that all API clients support TLS 1.2 before applying the change. Monitor CloudWatch access logs for connection failures after the update to identify clients that need upgrading.

---

### CTL.APIGATEWAY.DOMAIN.TLS.POLICY.STALE.001

**API Gateway Custom Domain Uses Stale TLS Security Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-13; iso_27001_2022: A.8.24; nist_800_53_r5: SC-8, SC-13; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

API Gateway custom domain is configured with a TLS security policy older than the current AWS-recommended policy (e.g., TLS_1_2_2018 instead of TLS_1_2_2021). Newer policies remove weaker cipher suites and add modern AEAD ciphers. The TLS minimum version itself may be 1.2 — passing the basic minimum-version check — but the cipher list is the older recommendation. Clients negotiating with an older policy pick up cipher suites AWS has since deprecated; the cumulative cipher mix has weakened relative to current guidance.

**Remediation:** Update the custom domain security policy to the current AWS recommendation (TLS_1_2_2021 at the time of writing): aws apigateway update-domain-name --domain-name <name> --patch-operations op=replace,path=/securityPolicy,value=TLS_1_2_2021. Track AWS announcements for newer policy releases and update in step. Verify that all clients negotiate successfully after the change; older clients may need TLS-stack upgrades to negotiate with the modern cipher list.

---

### CTL.APIGATEWAY.EDGE.NOCLOUDFRONT.001

**REST API With EDGE Endpoint Type Lacks CloudFront Origin Configuration**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-7, CM-2; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: SC-7, CM-2; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6;

REST API is configured with EDGE endpoint type but is not fronted by an operator-managed CloudFront distribution. EDGE endpoint type uses a CloudFront distribution that AWS manages on the customer's behalf — it provides geographic edge termination but is not customer-configurable for WAF, custom error pages, geo-restriction, signed URLs, or origin shield. Most production APIs warrant a customer-managed CloudFront in front of REGIONAL endpoints rather than the EDGE convenience type, because customer-managed CloudFront exposes the full configuration surface. EDGE without a customer CloudFront in front loses the ability to apply WAF, custom origin headers, and per-PoP routing decisions.

**Remediation:** Switch to REGIONAL endpoint type and front the API with a customer-managed CloudFront distribution: aws apigateway update-rest-api with --patch-operations op=replace,path=/endpointConfiguration/types,value=REGIONAL, then create a CloudFront distribution with the API Gateway domain as origin and configure WAF, custom error responses, and any other CloudFront-managed surfaces. EDGE endpoint type is appropriate for low-traffic APIs that legitimately don't need any of the customer- CloudFront features, but those should be the exception.

---

### CTL.APIGATEWAY.ENDPOINT.DEFAULT.001

**Default execute-api Endpoint Not Disabled Alongside Custom Domain**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-4; nist_800_53_r5: AC-4; pci_dss_v4.0: 1.3; soc2: CC6.6;

The default execute-api endpoint (https://{api-id}.execute-api.{region}.amazonaws.com) is enabled on an API that also has a custom domain configured. The default endpoint is a direct path to the API that bypasses every control applied at the custom domain layer: WAF rules attached to CloudFront or an ALB in front of the custom domain do not apply to the default endpoint, mTLS configured on the custom domain does not apply, custom TLS policy (TLS 1.2 minimum) does not apply, and CloudFront geographic restrictions do not apply. Disabling the default endpoint forces all traffic through the custom domain where security controls are applied. The control does not fire when no custom domain exists — in that case the default endpoint is the intended access path.

**Remediation:** Set DisableExecuteApiEndpoint=true on the API. For REST APIs this is the disableExecuteApiEndpoint property; for HTTP APIs it is the disableExecuteApiEndpoint setting on the API. After disabling, verify the custom domain still serves traffic and that no internal callers were using the default endpoint URL.

---

### CTL.APIGATEWAY.EXECLOG.DATALOG.001

**API Gateway Execution Logging Captures Full Request and Response Bodies**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-9, SC-28; hipaa: 164.312(a)(2)(iv), 164.312(c)(1); iso_27001_2022: A.5.33, A.8.10, A.8.15; nist_800_53_r5: AU-9, SC-28, SI-12; pci_dss_v4.0: 3.5, 8.3, 10.5; soc2: CC6.1, CC6.7;

Execution logging is enabled with data trace on — every request and response body that flows through the stage is written to CloudWatch as part of the API Gateway execution log. Data tracing exists for debugging integration mappings and is appropriate in development; in production it persists every payload the API processes. Request bodies carrying credentials, PII, PHI, payment data, or otherwise sensitive content end up at rest in CloudWatch. The same caveats as access-log API key capture apply, but the exposure surface is much broader: any data sent in any request body is logged.

**Remediation:** Disable data tracing on production stages: aws apigateway update-stage with --patch-operations op=replace,path=/*/dataTraceEnabled,value=false. Keep execution logging enabled at level INFO or ERROR for integration troubleshooting without payload capture. If payload-level diagnostics are needed during an incident, enable data trace on a per-stage basis briefly, capture, then disable — leaving it on permanently is the unsafe state.

---

### CTL.APIGATEWAY.EXECLOG.DATAMASK.MISSING.001

**Execution Logging With Data Trace But No Parameter Masking**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AU-9, SC-28, SI-12; hipaa: 164.312(a)(2)(iv), 164.312(c)(1); iso_27001_2022: A.5.33, A.8.10, A.8.15; nist_800_53_r5: AU-9, SC-28, SI-12; pci_dss_v4.0: 3.5, 8.3, 10.5; soc2: CC6.1, CC6.7;

REST API stage has data trace enabled in execution logs (full request and response bodies captured) without any parameter masking declared. When data trace is on and a legitimate diagnostic window justifies the exposure, masking rules can redact known-sensitive parameter names (password, token, ssn, credit_card, authorization) before logs are written. Without masking, every body field — including credentials in form-style POSTs, PII in user-update payloads, payment data — persists at rest in CloudWatch. The existing DATALOG control flags data trace being on at all; this control catches the case where data trace is legitimately needed but masking isn't applied alongside.

**Remediation:** Configure parameter masking via stage variables or method- level mapping templates that redact known-sensitive field names before the body reaches the execution log. For deeper data-leak prevention, integrate CloudWatch Logs with a data-classification pipeline (Amazon Macie, custom Lambda subscriber) that scrubs detected credentials and PII from the log stream after-the-fact. The cleanest fix is still to disable data trace on production stages — the existing CTL.APIGATEWAY.EXECLOG.DATALOG.001 covers the on-by-default case; this control catches the data-trace-needed-and- no-masking case.

---

### CTL.APIGATEWAY.EXECLOG.LEVEL.INFO.001

**REST API Execution Logging Set to INFO in Production**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-9, SC-28; iso_27001_2022: A.5.33, A.8.10, A.8.15; nist_800_53_r5: AU-9, SC-28, SI-12; pci_dss_v4.0: 10.5; soc2: CC6.7, CC8.1;

REST API stage has execution logging enabled at level INFO on what appears to be a production stage (stage_name not matching dev/test/staging conventions). INFO-level execution logs include detailed per-request internal processing — authorizer outputs, integration request/response headers and metadata, mapping template execution. Production volume at INFO level inflates CloudWatch costs significantly and surfaces operational metadata that can leak sensitive detail. ERROR level captures the same diagnostic value for failures without persisting per-request internals on the happy path. INFO is appropriate for development and short- lived diagnostic windows; the long-lived production setting should be ERROR.

**Remediation:** Lower the production stage's execution log level to ERROR: aws apigateway update-stage with --patch-operations op=replace,path=/*/loggingLevel,value=ERROR. For short- lived diagnostic windows, raise to INFO temporarily, then revert when the diagnosis is complete. Pair with the existing CTL.APIGATEWAY.EXECLOG.DATALOG.001 control — keep data trace off in production regardless of log level.

---

### CTL.APIGATEWAY.GATEWAYRESPONSE.SERVERHEADER.001

**Gateway Responses Include Server Header That Discloses API Gateway Version**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: SC-7, SI-10; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

REST API gateway responses (the templated error responses that API Gateway returns directly without invoking a backend — 401, 403, 404, 429, 5xx, etc.) include a Server response header that identifies the API Gateway service and version. Server headers are a small but standard fingerprinting source: scanners catalog them, attack tools bucket targets by stack, vulnerability databases match on version. The header doesn't enable a specific exploit on its own — API Gateway is a managed service AWS patches centrally — but the disclosure is unnecessary; removing the Server header narrows what reconnaissance learns passively from the API.

**Remediation:** Customize the gateway responses to override or remove the Server header: aws apigateway update-gateway-response with --patch-operations op=remove,path=/responseParameters/gatewayresponse.header.Server for each response type that should be overridden, or op=replace setting Server to an opaque value. The default set of gateway responses (DEFAULT_4XX, DEFAULT_5XX, UNAUTHORIZED, ACCESS_DENIED, etc.) all share the same header behavior; customize the parents to apply universally.

---

### CTL.APIGATEWAY.GHOST.AUTHORIZER.001

**API Gateway Authorizer References Deleted Provider**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 8.2; soc2: CC6.1;

API Gateway authorizer references a Lambda function (Lambda authorizer) or Cognito User Pool (Cognito authorizer) that has been deleted. The authorizer object remains in place and is attached to routes. When a request hits the route, the authorizer attempts to invoke the deleted function or validate against the deleted user pool and authorization fails — routes return 403 (denied) or 500 (internal error), depending on the gateway's error handling. The authorizer appears configured in the console; the failure only surfaces when authenticated traffic arrives.

**Remediation:** Either recreate the authorizer's backend (function or user pool) with the same ARN, or update the authorizer to reference a current provider. Add a deletion guard at the provider tier so that deleting a Lambda function or Cognito User Pool referenced by an authorizer fails until the authorizer is migrated.

---

### CTL.APIGATEWAY.GHOST.CERT.001

**API Gateway Custom Domain Certificate Deleted or Expired**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-17; hipaa: 164.312(e)(1); nist_800_53_r5: SC-17; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

API Gateway custom domain references an ACM certificate that has been deleted or has expired. Clients connecting to the custom domain receive TLS errors — the handshake fails, browsers display certificate warnings, and automated integrations reject the connection. The custom domain configuration appears intact in the console; the failure is external and immediate. The control surfaces both the deleted-certificate case (immediate failure) and the imminent-expiry case (failure within a known window) so remediation happens during a change window rather than during an outage.

**Remediation:** Replace the certificate on the custom domain. If the original ACM certificate was deleted, request a new one with the same subject alternative names and associate it. If the certificate expired, investigate the ACM renewal path (DNS validation records, IAM permissions for renewal) and enable automated renewal. Add a 30-day-before-expiry alarm.

---

### CTL.APIGATEWAY.GHOST.LAMBDA.001

**API Gateway Integration References Deleted Lambda Function**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; nist_800_53_r5: CM-2; soc2: CC8.1;

API Gateway method or route integration references a Lambda function that has been deleted from the function inventory. The route is configured, accepts requests, and attempts to invoke the function — every invocation fails because the function no longer exists. The console shows the integration ARN as if it were valid; the failure surfaces only when a request reaches the route, at which point API Gateway returns 500. If the route handles authentication, payment, or other critical paths, the functionality is fully broken with no configuration-time signal.

**Remediation:** Recreate the Lambda function with the same ARN, or update the integration to point at a current function. Add a deletion guard on Lambda functions that cross-references API Gateway integrations so the function deletion either fails or cascades the integration cleanup.

---

### CTL.APIGATEWAY.GHOST.LOGDEST.001

**API Gateway Access Log Destination Deleted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AU-12; hipaa: 164.312(b); nist_800_53_r5: AU-12; pci_dss_v4.0: 10.2; soc2: CC7.2;

API Gateway stage's access log destination — a CloudWatch log group or Firehose delivery stream — has been deleted. The stage shows a destination ARN configured, so the API appears to have access logging enabled. The destination does not exist, so logs are silently discarded. The "logging is on" signal is preserved while the audit trail produces nothing. This is the silent-failure flavor of a logging gap: the operator who looks at the stage configuration reports compliance; the operator who looks for logs finds none.

**Remediation:** Recreate the log destination (CloudWatch log group or Firehose delivery stream) at the same ARN, or update the stage's access log settings to point at a current destination. Add a deletion guard on log destinations referenced by API Gateway stages.

---

### CTL.APIGATEWAY.GHOST.USAGEPLAN.001

**API Gateway Usage Plan References Deleted API Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

API Gateway usage plan references one or more API keys that have been deleted. The usage plan retains its throttling and quota settings, but the keys it governs no longer exist. Clients using a deleted key receive 403 Forbidden; the throttle and quota policy attached to the deleted key never applies; if the deleted key was the only key in the plan, the plan is effectively empty. The failure is medium severity rather than critical because the impact is per-client (the holder of the deleted key) rather than per-API.

**Remediation:** Remove deleted key IDs from the usage plan's key list. If clients still need the throttle policy that was attached to a deleted key, issue a new key and re-attach. Add a deletion guard on API keys that cross-references usage plans before allowing the key to be deleted.

---

### CTL.APIGATEWAY.GHOST.VPCLINK.001

**API Gateway VPC Link References Deleted Load Balancer**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-2; nist_800_53_r5: CM-2; soc2: CC8.1;

API Gateway VPC Link references an NLB or ALB that has been deleted from the load balancer inventory. The VPC Link is the network bridge between API Gateway and a private backend in a VPC. When the target load balancer is deleted, the VPC Link has no destination — but its status remains AVAILABLE in the console because the link object itself still exists. API Gateway routes requests through the VPC Link, the VPC Link tries to forward to the deleted load balancer, and every request fails with 500 Internal Server Error. The API configuration looks correct, the integration looks correct, every request fails.

**Remediation:** Either delete the VPC Link and remove integrations that reference it, or recreate the target load balancer with the same ARN and re-attach. Add a check at load-balancer deletion time to enumerate VPC Links referencing the LB ARN and fail-fast or delete-cascade rather than orphan the link.

---

### CTL.APIGATEWAY.HTTPAPI.DEFAULT.ROUTE.001

**HTTP API Has $default Catch-All Route**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, CM-2, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6;

HTTP API has a $default route configured. The $default route matches any path and method that no specific route handles — including paths the API author never intended to expose. When the $default route forwards to a Lambda or HTTP backend, the backend receives traffic for /admin, /internal, /.git, /actuator, /debug, and every other path the backend itself implements, even if no specific API Gateway route was created for them. Discovery becomes path enumeration on the backend rather than on the API. The safer pattern is explicit route definitions for every supported method+path; unknown paths receive 404 from API Gateway rather than reaching the backend.

**Remediation:** Replace the $default route with explicit routes for each supported method+path: aws apigatewayv2 delete-route --route-id <default> followed by create-route for each intended route. If the application genuinely needs a catch- all (single-page app routing, custom 404 handling), keep $default but front it with a Lambda that explicitly allowlists expected paths and returns 404 for everything else.

---

### CTL.APIGATEWAY.HTTPAPI.JWT.ISSUER.HTTP.001

**HTTP API JWT Authorizer Issuer URL Uses HTTP**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: IA-2; hipaa: 164.312(d); nist_800_53_r5: IA-2; pci_dss_v4.0: 8.3.1; soc2: CC6.1;

HTTP API JWT authorizer is configured with an issuer URL whose scheme is HTTP rather than HTTPS. The JWT authorizer derives the JWKS endpoint from the issuer URL — typically by appending /.well-known/jwks.json — and retrieves the issuer's public keys from that endpoint to validate token signatures. When the issuer URL is HTTP, the JWKS retrieval traverses the network in plaintext. An attacker on the network path between API Gateway and the issuer (an upstream router, a malicious DNS server, a compromised intermediate proxy) can intercept the JWKS request and substitute their own public keys. The authorizer caches the substituted keys and accepts any JWT signed by the attacker's matching private key as valid — a complete authentication bypass on every route protected by this authorizer. HTTPS prevents key substitution by encrypting and authenticating the JWKS retrieval.

**Remediation:** Update the authorizer's issuer URL to HTTPS. Verify that the issuer's JWKS endpoint serves over HTTPS with a certificate whose subject matches the issuer hostname. If the issuer can only serve HTTP, treat that as the underlying problem — fix the issuer's TLS configuration before pointing the authorizer at it. Rotate any JWTs issued under the previous configuration; treat them as potentially exposed.

---

### CTL.APIGATEWAY.HTTPAPI.JWT.SCOPE.MISSING.001

**HTTP API JWT Authorizer Without Per-Route Scope Validation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-2, AC-3, AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-2, AC-3, AC-6, IA-2; pci_dss_v4.0: 7.1, 7.2, 8.3; soc2: CC6.1, CC6.3;

HTTP API route is protected by a JWT authorizer, but no authorization scopes are configured on the route. Any valid token from the issuer with valid audience is accepted regardless of the OAuth scopes the token bears. A token issued for read-only access is also accepted by the admin write route. Scopes are the per-route ACL — without them the JWT authorizer enforces only authentication and audience, and authorization collapses to whatever the application code does (which often isn't a scope check). HTTP APIs let scopes be configured per route via authorizationScopes; routes that omit it inherit scope-less authorization.

**Remediation:** Set authorizationScopes on each protected route with the OAuth scopes that should be required: aws apigatewayv2 update-route --route-id ... --authorization-scopes resource-server/read resource-server/write. Define scopes that match the operation sensitivity and configure the IdP (Cognito, Auth0, Okta) to issue them based on role/group membership.

---

### CTL.APIGATEWAY.INCOMPLETE.001

**Complete Data Required for API Gateway Assessment**

- **Severity:** info
- **Type:** unsafe_state
- **Domain:** exposure

The observation snapshot is missing required API Gateway properties.

**Remediation:** Ensure the extractor calls aws apigateway get-rest-apis and aws apigateway get-domain-names and maps security policy to the api observation properties.

---

### CTL.APIGATEWAY.INTEGRATION.HTTP.BACKEND.PUBLIC.001

**HTTP Integration Backend Is Public Internet URL Instead of Private Endpoint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7, AC-4; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SC-7, AC-4; pci_dss_v4.0: 1.2, 1.3, 4.2; soc2: CC6.1, CC6.6;

REST API method has an HTTP_PROXY or HTTP integration whose backend URL resolves to a public internet endpoint rather than a private resource (VPC endpoint, private DNS, internal IP). API Gateway routes traffic over the public internet to reach the backend — adding a public-internet hop between API Gateway (an AWS service in the same region, often the same account as the backend) and the backend itself. That hop is unnecessary egress, increases attack surface (the backend has a public listener that must accept traffic from arbitrary AWS API Gateway IP ranges), and removes the private-network blast-radius containment that VPC isolation provides.

**Remediation:** Replace the public URL with a VPC Link integration to a private NLB or with a private DNS name resolved within the VPC: aws apigateway update-integration with --patch-operations op=replace,path=/connectionType,value=VPC_LINK and the appropriate connectionId. For backends that are inherently third-party (an external SaaS API), document the rationale in the triage override — third-party reach legitimately transits the public internet and is not the case this control flags.

---

### CTL.APIGATEWAY.INTEGRATION.HTTP.PLAINTEXT.001

**API Gateway Integration Forwards to HTTP Backend**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.7;

API Gateway integration forwards requests to a backend over plain HTTP, not HTTPS. The client connects to API Gateway over TLS and sees a padlock; API Gateway terminates TLS and re-emits the request to the backend in plaintext. Headers (including any forwarded Authorization or session cookies), query parameters, request bodies, and response bodies traverse the network between API Gateway and the backend without encryption. This is the same false-HTTPS pattern documented across CDN→origin (CTL.S3.CDN.TRANSPORT.001), Cloudflare Flexible SSL (CTL.CLOUDFLARE.ZONE.SSL.001), and RDS Proxy without backend TLS (CTL.RDS.PROXY.TLS.001) — encryption at the edge, plaintext inside. The control fires on HTTP and HTTP_PROXY integration types whose URI begins with http://.

**Remediation:** Update the integration URI from http:// to https://. If the backend doesn't yet support TLS, terminate TLS at a load balancer or service mesh in front of it before exposing it through API Gateway. For backends in a VPC, use a VPC Link with an HTTPS listener on the NLB or ALB. Verify by re-issuing a request and confirming the backend log shows TLS-terminated traffic.

---

### CTL.APIGATEWAY.INTEGRATION.HTTP.SENSITIVE.HEADERS.001

**HTTP Integration Forwards Authorization or Cookie Headers Unconditionally**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-5, SC-7; iso_27001_2022: A.5.10, A.5.16, A.8.16; nist_800_53_r5: AC-3, IA-5, SC-7; pci_dss_v4.0: 8.3, 6.4.2; soc2: CC6.1, CC6.6;

HTTP / HTTP_PROXY integration is configured without explicit request parameter mappings to strip sensitive headers (Authorization, Cookie, Set-Cookie, X-Api-Key) before forwarding to the backend. The default behavior of HTTP proxy integration is to pass every request header through. When the backend is internal or third-party and doesn't itself need the API Gateway-layer credentials (a Cognito bearer token meant only for API Gateway, an API key meant only for usage-plan throttling), forwarding the header to the backend unnecessarily exposes the credential. The backend may log it, may proxy it onward, may have weaker IAM than expected — none of which the operator considered when designing API Gateway-layer auth.

**Remediation:** Map integration.request.header.* to drop or rename sensitive headers before forwarding. aws apigateway update-integration with --patch-operations op=remove,path=/requestParameters/integration.request.header.Authorization, or replace with a backend-specific token. The mapping explicitly enumerates which headers reach the backend; the default (forward everything) is the unsafe state.

---

### CTL.APIGATEWAY.INTEGRATION.HTTP.TLS.UNVALIDATED.001

**HTTP Integration Doesn't Validate Backend TLS Certificate**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8, SC-12, SC-23; iso_27001_2022: A.5.10, A.8.20, A.8.24; nist_800_53_r5: SC-8, SC-12, SC-23; pci_dss_v4.0: 4.2; soc2: CC6.1, CC6.7;

HTTP / HTTP_PROXY integration is configured with TLS certificate validation disabled (insecureSkipVerification flag, or an explicit configuration that accepts any certificate). Integration traffic is technically encrypted but the certificate chain is not checked — API Gateway accepts connections to a backend whose certificate is self-signed, expired, or impersonated. An attacker who can redirect traffic in the network path between API Gateway and the backend (DNS hijack, BGP misroute, compromised intermediate) can present any certificate; API Gateway accepts it and forwards traffic. The encryption is cosmetic — confidentiality of credentials and request data is no stronger than plaintext HTTP.

**Remediation:** Re-enable TLS validation on the integration: aws apigateway update-integration with --patch-operations op=replace,path=/tlsConfig/insecureSkipVerification,value=false. For backends with self-signed or internal-CA certificates, install the issuing CA into ACM and import the chain so validation succeeds; don't disable validation as a shortcut.

---

### CTL.APIGATEWAY.INTEGRATION.LAMBDA.SCOPE.001

**Lambda Permission Not Scoped to Specific API**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3; nist_800_53_r5: AC-3; pci_dss_v4.0: 7.2.1; soc2: CC6.1;

API Gateway integrates with a Lambda function whose resource-based policy allows invocation from execute-api with an unscoped or wildcarded source ARN. Lambda's resource-based policy is what authorizes API Gateway to invoke it; the policy's source ARN condition is what restricts which API Gateway can do so. When the source ARN condition is missing, set to arn:aws:execute-api:REGION:ACCOUNT:* (or omits the API ID), the Lambda is invocable from any API Gateway in the account — not just the one the operator built. An attacker (or a different team) who can create an API in the same account can point a route at this Lambda and bypass the original API's authorizer entirely. This control is a cross-resource check: API Gateway provides the Lambda ARN; Lambda's policy determines whether invocation is scoped.

**Remediation:** Update the Lambda's resource-based policy to add an explicit SourceArn condition pinning the API ID, stage, method, and path — for example, arn:aws:execute-api:REGION:ACCOUNT:API_ID/STAGE/METHOD/PATH. Use the smallest pattern that covers the intended call sites; avoid trailing wildcards beyond what's necessary. Re-add the permission via aws lambda add-permission with the scoped source-arn rather than editing the policy in place.

---

### CTL.APIGATEWAY.INTEGRATION.TIMEOUT.001

**API Gateway Integration Timeout At Maximum**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; soc2: A1.1;

API Gateway integration timeout is set to the maximum allowed by the API type — 29 seconds for REST APIs, 30 seconds for HTTP APIs. The maximum-timeout configuration is sometimes intentional for genuinely long-running backends (file processing, report generation, ML inference), but it has measurable side effects on the API's resilience: each slow or hanging request holds an API Gateway connection for the full timeout window before failing, back-pressure is delayed, and the per-account concurrency budget is consumed by stuck requests. Under abuse — request flooding, attacker-controlled slow backends — the maximum timeout amplifies the impact of every request that doesn't complete. Operators who run backends that never need 29 seconds should set the timeout to a value that matches actual SLOs. Operators with genuinely long backends should acknowledge this control in the triage override with the rationale.

**Remediation:** Reduce the integration timeout to match the backend's actual p99 latency plus headroom. For a backend whose p99 is 2 seconds, a timeout of 5 seconds is more than enough; the maximum is appropriate only for backends that genuinely need it. If the long timeout is intentional, document the reason in a triage override on this control rather than leaving it at default.

---

### CTL.APIGATEWAY.INTEGRATION.VPCLINK.MISSING.001

**API Gateway Routes to Private Backend Without VPC Link**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; nist_800_53_r5: SC-7; pci_dss_v4.0: 1.3.4; soc2: CC6.6;

API Gateway integration routes to a backend whose URI matches private-resource patterns — internal hostname suffixes (.internal, .local, .vpc), RFC 1918 IP ranges, or NLB/ALB ARNs inside the same account — but the integration does not use a VPC Link. Without a VPC Link, the integration must reach the backend over the public internet. For the URI to resolve, the backend has to expose a public endpoint, which defeats the reason it was placed in a private network. Either the backend is unreachable (asymmetric: the API tells clients it works, the backend can't be reached), or the backend has a public exposure the operator did not intend. The control's heuristic for "private backend" is documented in the URI pattern field; if the heuristic produces false positives in a particular environment, the triage override should pin the rationale.

**Remediation:** Create a VPC Link pointing at the appropriate NLB (REST API) or ALB/NLB/CloudMap service (HTTP API), then update the integration to reference that VPC Link. Once the link is in place, remove any public exposure from the backend's load balancer or service. If the backend is genuinely meant to be public, change the URI to its public DNS name so the heuristic stops matching the private pattern.

---

### CTL.APIGATEWAY.LOG.001

**REST API Stages Must Have Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

API Gateway REST API stages must have execution or access logging enabled to CloudWatch. Without logging, API activity lacks visibility for detecting abuse and supporting incident response.

**Remediation:** Enable execution logging or access logging on the stage.

---

### CTL.APIGATEWAY.METHOD.ANY.001

**REST API Method Configured As ANY (Matches All HTTP Verbs)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-3, CM-2, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, CM-2, SC-7; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC8.1;

REST API method is configured with httpMethod ANY, which matches any HTTP verb (GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS) at that resource path. ANY is convenient for proxying everything to a single backend handler, but it exposes operations the API author may not have considered: DELETE on a read-only resource, PUT on a list endpoint, TRACE / CONNECT on any resource. The backend receives the full set of verbs and is expected to handle each one appropriately — frequently it doesn't, returning 200 for unintended operations or producing unexpected behavior. Explicit method declarations (GET, POST individually) are the safer pattern; ANY should be reserved for cases where the backend is genuinely a verb-agnostic dispatcher.

**Remediation:** Replace the ANY method with explicit declarations for the verbs the API actually supports: aws apigateway delete-method --http-method ANY, then put-method for each intended verb. For backends that genuinely dispatch on verb (Lambda proxy integration handling all verbs in one handler), keep ANY but document the rationale; the control's triage-override layer accepts that case explicitly.

---

### CTL.APIGATEWAY.METHOD.RESPONSE.MISSING.001

**REST API Method Has No Method Response Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-11, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-11, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

REST API method has no method response (no methodResponses for any status code, or only the 200 response is declared). Without method responses, API Gateway passes the integration's raw response straight through to clients — including backend error responses with stack traces, internal paths, ORM error details, and any other exception detail the backend emits. Method responses let the operator declare which status codes are expected and what response models / parameter mappings apply, transforming integration responses into a stable API contract instead of a passthrough.

**Remediation:** Declare method responses for each expected status code: aws apigateway put-method-response --status-code 200, --status-code 400, --status-code 5XX, etc. Pair with response models that constrain the body shape and integration-response mappings that transform raw backend output into the declared contract. The default integration response (when present) catches anything the explicit mappings don't.

---

### CTL.APIGATEWAY.METHOD.THROTTLE.MISSING.001

**REST API Method Lacks Per-Method Throttle Override**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, AC-7; iso_27001_2022: A.5.30, A.8.6, A.8.16; nist_800_53_r5: SC-5, AC-7; pci_dss_v4.0: 6.4.1, 8.3.4; soc2: A1.1, CC6.6;

Sensitive REST API method (login, signup, password reset, payment, search, file upload) has no method-level throttle override. The method inherits the stage-level rate, which is typically tuned for normal-flow methods. Sensitive methods warrant tighter limits — login at 5 RPS rather than 1000 RPS drops credential-stuffing throughput by 200x without affecting legitimate users (who login once per session). Method-level overrides are the surgical layer; stage-level is the broad layer; usage plans are the per-consumer layer. All three combine to bound an attacker's effective throughput.

**Remediation:** Add method-level throttle on sensitive methods via the stage methodSettings: aws apigateway update-stage with --patch-operations op=replace,path=/~1users~1login/POST/throttling/rateLimit, value=5. The path encoding uses ~1 for / in the method selector. Identify sensitive methods by reviewing the API's operation list — any operation that gates auth, mutates sensitive resources, or has a meaningful per-user upper bound on legitimate frequency is a candidate.

---

### CTL.APIGATEWAY.MOCK.PRODUCTION.001

**Mock Integration on Production Stage**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-3; iso_27001_2022: A.8.9, A.8.32; nist_800_53_r5: CM-2, CM-3, SI-7; pci_dss_v4.0: 6.4.1, 6.4.2; soc2: CC6.1, CC8.1;

REST API method on a production stage uses a MOCK integration type. Mock integrations return hardcoded responses that bypass the backend entirely — they exist for testing wiring before the backend is ready, for stub endpoints, or for forced-response paths during rollouts. In production, mock integrations either return canned data that may be stale or inappropriate for live traffic, or return generic success status codes that mask backend issues from monitoring. A mock on production is almost always either leftover testing artifact or an unintended deployment. The fix is to replace with a real integration before the stage is considered production.

**Remediation:** Replace the MOCK integration with the appropriate AWS, AWS_PROXY, HTTP, or HTTP_PROXY integration: aws apigateway update-integration with --patch-operations op=replace,path=/type,value=AWS_PROXY (or appropriate type) plus the integration URI / role / parameters. Audit the method's response mappings and stage variables for any references that assumed mock behavior.

---

### CTL.APIGATEWAY.MODEL.ADDITIONAL.PROPERTIES.001

**Request Model Permits additionalProperties (Schema Not Closed)**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-10, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

REST API request model is associated with a method, but the JSON Schema either declares "additionalProperties": true or omits the keyword entirely (which JSON Schema interprets as true by default). Callers can include arbitrary extra fields on the request body and the model accepts them. The backend may not handle the unexpected fields, may inadvertently persist them, or may fail to spot mass- assignment vulnerabilities where a caller smuggles a field the API didn't intend to accept (admin=true on a profile update). Closed schemas — additionalProperties: false — reject extra fields at the API Gateway layer before the backend ever sees them.

**Remediation:** Update the model's JSON Schema to set additionalProperties: false: aws apigateway update-model --rest-api-id <id> --model-name <name> --patch-operations op=replace,path=/schema,value=<closed-schema-json>. The closed schema rejects any field not declared in the properties list. Migrate carefully — clients sending legitimate-but-undocumented fields will start receiving 400 responses; communicate the schema tightening before enforcing.

---

### CTL.APIGATEWAY.MODEL.UNASSOCIATED.001

**Request Model Defined But Not Associated With Any Method**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: SI-10, CM-2; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-10, CM-2; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6, CC8.1;

REST API has request model resources defined (the JSON Schema contracts API Gateway uses to validate request bodies), but the model is not attached to any method's requestModels[contentType]. The model exists in the API inventory but never enforces anything — every method accepts whatever the caller sends. Operators provisioning the model often assume it's enforced because it appears in the API definition; the actual enforcement requires an explicit per-method association alongside a request validator that includes body validation.

**Remediation:** Either associate the model with the method that should enforce it: aws apigateway update-method with --patch-operations op=add,path=/requestModels/application~1json,value=<modelName>. Or delete the orphan model if it's leftover from a partial refactor: aws apigateway delete-model --model-name <name>. Pair with a request validator that has --validate-request-body set so the model actually gates traffic.

---

### CTL.APIGATEWAY.MTLS.001

**REST API Stages Must Use Client Certificates**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

API Gateway REST API stages should configure a client certificate for mutual TLS with backend integrations. Without client authentication, backends cannot verify requests originate from API Gateway.

**Remediation:** Generate and attach a client certificate to the stage.

---

### CTL.APIGATEWAY.NETWORK.CLIENTCERT.EXPIRY.001

**API Gateway Stage Client Certificate Expired**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: IA-5; hipaa: 164.312(d); nist_800_53_r5: IA-5; owasp_nhi: NHI7; soc2: CC6.1;

REST API stage has a client certificate configured for backend authentication, but the certificate has expired. Backends that validate the API Gateway client certificate to distinguish legitimate API Gateway traffic from direct connections will reject every request once the certificate expires. The stage configuration reports mTLS-to-backend as enabled, but the certificate it presents is no longer trustworthy. Distinct from CTL.APIGATEWAY.MTLS.001, which checks whether a client certificate is configured at all — this control fires when one IS configured but has expired (or is within the imminent-expiry window).

**Remediation:** Generate a new client certificate via the API Gateway console or the GenerateClientCertificate API and re-attach it to the stage. Distribute the new certificate's public key to every backend that pins it. Add a 30-day-before-expiry alarm on the certificate's expiration date so the next renewal happens during a change window rather than during an outage.

---

### CTL.APIGATEWAY.NETWORK.CLIENTCERT.STALE.001

**REST API Stage Client Certificate Older Than Rotation Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: IA-5, SC-12, SC-17; iso_27001_2022: A.5.16, A.8.24; nist_800_53_r5: IA-5, SC-12, SC-17; pci_dss_v4.0: 3.7, 8.3; soc2: CC6.1, CC6.7;

REST API stage uses a client certificate (the certificate API Gateway presents to backends to authenticate itself during integration calls), and the certificate is older than the rotation policy threshold (default: 365 days). Client certificates that aren't rotated accumulate the same drift problems as long-lived credentials elsewhere — if the private key is compromised, every backend that trusts the cert is reachable; rotation cadence limits the blast radius. The expiry control (CTL.APIGATEWAY.NETWORK.CLIENTCERT.EXPIRY.001) catches imminent expiry; this control catches stale-but- not-yet-expired certs that are overdue for rotation.

**Remediation:** Generate a new client certificate, distribute it to the backends that trust it, and update the stage to use the new certificate: aws apigateway generate-client-certificate followed by aws apigateway update-stage with --patch-operations op=replace,path=/clientCertificateId,value=<new-cert-id>. Plan rotation in advance — backends typically need a deployment to trust the new certificate before the stage flips. Once rotation is complete, delete the old certificate.

---

### CTL.APIGATEWAY.NETWORK.PRIVATE.POLICY.001

**Private API Resource Policy Does Not Restrict VPC Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-7; hipaa: 164.312(e)(1); nist_800_53_r5: SC-7; pci_dss_v4.0: 1.4.2; soc2: CC6.6;

REST API uses the PRIVATE endpoint type but has a resource policy that does not restrict access to specific VPC endpoints or source VPCs. A Private API is reachable only through VPC endpoints — not from the public internet — but the "only through VPC endpoints" guarantee says nothing about whose VPC. Any AWS account in any region that creates a VPC endpoint for the execute-api service can invoke this API. Without an aws:sourceVpce or aws:sourceVpc condition in the resource policy, the PRIVATE designation provides no meaningful access boundary. Operators frequently mistake PRIVATE for "internal to my organization" — it is not. Internal-only reachability requires the resource policy to enumerate the allowed VPC endpoint IDs or source VPC IDs.

**Remediation:** Add a condition block to the resource policy restricting access to specific aws:sourceVpce values (the VPC endpoint IDs your consumers use) or specific aws:sourceVpc values (the source VPCs your consumers run in). For multi-account architectures, list every consumer endpoint explicitly — wildcards defeat the purpose. Verify by attempting to invoke the API from an unrelated AWS account's VPC endpoint and confirming the request is denied.

---

### CTL.APIGATEWAY.ORPHAN.API.001

**API Gateway Has No Custom Domain and No Recent Deployments**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2; nist_800_53_r5: CM-2; soc2: CC8.1;

API Gateway has no custom domain associated and has not been deployed in the last 90 days. The combination of "no custom domain" and "no recent deployments" indicates the API is no longer actively maintained — it isn't fronted by a customer- facing hostname, and nobody has updated its definition in three months. Either indicator alone is consistent with active use (an internal API may not need a custom domain; a stable API may not need recent deployments), so the control requires both. An abandoned API still retains its full configuration: routes, integrations, authorizers, the default execute-api endpoint. If the default endpoint is enabled (see CTL.APIGATEWAY.ENDPOINT.DEFAULT.001), the API remains invocable from the internet despite being unmaintained. Stale APIs accumulate configuration drift — security settings not updated, integrations pointing at moved or deleted backends, authorizers whose JWKS keys have rotated.

**Remediation:** Confirm whether the API is still in use by any consumer (check CloudWatch invocation metrics for the stage). If unused, delete the API. If still used but stale, plan a deployment cycle that re-validates the routes, integrations, authorizers, and security settings against current standards and disables the default endpoint if a custom domain isn't needed.

---

### CTL.APIGATEWAY.ORPHAN.APIKEY.001

**API Key Not Associated With Any Usage Plan**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: AC-2, CM-8, IA-5; iso_27001_2022: A.5.16, A.8.9; nist_800_53_r5: AC-2, CM-8, IA-5; pci_dss_v4.0: 8.3; soc2: CC6.1, CC8.1;

REST API key exists but is not associated with any usage plan. API keys only enforce throttling and quota when attached to a usage plan; an unassociated key is a credential that authenticates but has no rate / burst / quota constraint. The key still works for any method that has apiKeyRequired=true on the underlying API — it just bypasses the per-consumer limits the operator likely intended. Orphan keys also clutter the audit view: rotation policies don't apply consistently, who-uses-which-key gets ambiguous.

**Remediation:** Either associate the key with the usage plan that should govern it: aws apigateway create-usage-plan-key --usage-plan-id <id> --key-id <key-id> --key-type API_KEY. Or delete the orphan key: aws apigateway delete-api-key --api-key <key-id>. Audit the consumer using the key first — deleting in production breaks legitimate clients.

---

### CTL.APIGATEWAY.ORPHAN.AUTHORIZER.001

**API Gateway Authorizer Not Referenced by Any Route**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

API Gateway has an authorizer configured but no route or method references it. The authorizer exists in the API's configuration but is enforcing authentication on nothing. Three causes produce this state. First, an authorizer that was attached to routes earlier was detached during a configuration change — the routes are now unauthenticated and the authorizer is a vestigial artifact. Second, an authorizer was created during initial setup and the routes that were supposed to use it were never updated to reference it — the authorizer's existence masks the fact that nothing is authenticated. Third, the routes that referenced the authorizer were deleted but the authorizer wasn't cleaned up. The control is low severity — the authorizer's existence is not itself a vulnerability — but the orphan signal indicates one of the three causes above warrants investigation.

**Remediation:** Determine which of the three causes applies. If routes were detached, re-attach the authorizer (or confirm the detachment was intentional and the routes are deliberately unauthenticated). If routes were never attached, attach the authorizer to the intended routes. If the authorizer is truly unused, delete it so the API's configuration accurately reflects what it enforces.

---

### CTL.APIGATEWAY.ORPHAN.CUSTOMDOMAIN.001

**Custom Domain Has No Active API Mapping**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

REST or HTTP API custom domain exists with a valid certificate and TLS configuration, but no base path mapping points the domain at any API and stage. The custom domain is effectively orphaned: the DNS record may resolve, the TLS handshake may succeed, but every request returns a default API Gateway response (typically Forbidden / Missing Authentication). The domain accumulates ACM and DNS coordination cost, and the cert auto-renewal stays active even though the domain serves no traffic. Common cause: stage migration where the new mapping was added but the old domain wasn't cleaned up; an experimental domain that never reached production.

**Remediation:** Either map the domain to the API and stage that should serve it: aws apigateway create-base-path-mapping --domain-name <name> --rest-api-id <id> --stage <stage>. Or delete the orphan domain: aws apigateway delete-domain-name --domain-name <name>. Inspect Route 53 alias records pointing at the domain — they should be cleaned up alongside.

---

### CTL.APIGATEWAY.ORPHAN.NODEPLOYMENT.001

**REST API Has No Deployment Records — Defined But Never Deployed**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

REST API resource exists with method definitions, integrations, and authorizers configured, but has no deployment records. No stage references this API; no traffic ever reaches the configuration. The API is a definition-only artifact — partial work an operator started and didn't complete, a template that was provisioned but not pushed to production, or a resource left over from a delete-by-stage cleanup. The risk is configuration drift: the API has IAM, network, and integration coupling that other resources may still honor (Lambda permission grants, VPC Link references, authorizer dependencies), but no operational traffic to surface bugs. When an operator later deploys it, the configuration is whatever it has drifted to — possibly outdated, possibly never reviewed in the current state.

**Remediation:** Either deploy the API to a stage if it's intended to be live (aws apigateway create-deployment --rest-api-id --stage-name <name>), or delete the API if it's leftover: aws apigateway delete-rest-api --rest-api-id <id>. Audit Lambda resource-based policies, VPC Links, and any cross-resource references to confirm the cleanup is complete.

---

### CTL.APIGATEWAY.ORPHAN.USAGEPLAN.001

**Usage Plan Not Associated With Any API Stage**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

Usage plan exists with rate, burst, and quota settings, but it is not associated with any API stage. The plan is inert — no API consumes its limits, no API key tied to the plan enforces anything against any traffic. Common cause: development experiment that never got cleaned up; a stage that was migrated and the old plan wasn't retired; a usage plan provisioned ahead of an API that never launched. Orphan usage plans clutter the operational view, complicate audits ("which plan governs which API?"), and accumulate configuration drift — when an operator later associates the plan with a stage, its limits are whatever they drifted to, often without recent review.

**Remediation:** Either associate the plan with the API stage that should use it (aws apigateway create-usage-plan-key followed by update-usage-plan adding apiStages) or delete the plan if it's leftover: aws apigateway delete-usage-plan --usage-plan-id <id>. Inspect any API keys associated with the plan first — they may need re-association with a different plan or independent cleanup.

---

### CTL.APIGATEWAY.ORPHAN.VPCLINK.001

**VPC Link Not Used By Any Integration**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-2, CM-8; iso_27001_2022: A.5.10, A.8.9; nist_800_53_r5: CM-2, CM-8; soc2: CC6.1, CC8.1;

REST or HTTP API VPC Link exists but no integration references it. The VPC Link is provisioned (charges accrue, ENIs occupy IP addresses in the configured subnets, NLB capacity remains allocated to the link) but doesn't serve any traffic. Common cause: API migration where the new integration uses a different VPC Link and the old one wasn't decommissioned; experimental integration that was rolled back without removing the link.

**Remediation:** Audit the VPC Link to confirm no current or pending integration uses it. Either repoint a current integration at the link or delete the link: aws apigateway delete-vpc-link --vpc-link-id <id>. Audit the target NLB and its security group during cleanup — they may need independent decommissioning.

---

### CTL.APIGATEWAY.PAYLOAD.SIZE.UNLIMITED.001

**API Gateway Method Has No Request Validator Body Size Constraint**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, SI-10; iso_27001_2022: A.5.30, A.8.6, A.8.16; nist_800_53_r5: SC-5, SI-10; pci_dss_v4.0: 6.4.1, 6.4.2; soc2: A1.1, CC6.6;

REST API method does not declare an explicit maximum body size constraint via the request validator and request model. API Gateway accepts request bodies up to the service maximum (10 MB for REST, 10 MB for HTTP). For most APIs the legitimate maximum is far smaller — kilobytes for typical JSON, hundreds of kilobytes for richly-attributed records. The 10 MB ceiling is a memory amplification vector: an attacker sends max-size bodies repeatedly to exhaust backend memory (Lambda allocation, container heap), drive up invocation cost, or trigger downstream timeouts. The fix is the request model declaring a maxLength / maxItems / maxBytes constraint matching the operation's legitimate maximum.

**Remediation:** Define a request model with maxLength / maxItems constraints in the JSON Schema, attach the model to the method, and ensure a request validator is configured to enforce body validation. aws apigateway create-model followed by update-method to attach. For methods that legitimately accept large bodies (file upload, batch import), document the rationale in the triage override rather than removing the constraint.

---

### CTL.APIGATEWAY.POLICY.CROSSACCOUNT.OPEN.001

**REST API Resource Policy Allows Any VPC In Any Account**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6, SC-7; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.3;

REST API resource policy grants invocation rights to a source-VPC condition without restricting to specific VPCs or specific accounts (e.g., aws:SourceVpc condition with no specific VPC IDs, or no aws:SourceAccount / aws:PrincipalOrgID restriction alongside the VPC clause). The policy effectively allows any VPC in any AWS account in the AWS partition to invoke the API. Cross-account access through VPC peering or VPC sharing reaches the policy condition; what was intended as "internal-only via VPC" becomes "any AWS-internal caller anywhere." Pair every cross-account / VPC-scoped resource policy with an account or organization restriction.

**Remediation:** Add an aws:SourceAccount or aws:PrincipalOrgID condition to the resource policy alongside the VPC clause: aws apigateway update-rest-api with --patch-operations op=replace,path=/policy,value=<json> where the policy document has both the source-VPC clause and an Account/Org restriction. For private APIs, prefer aws:SourceVpce listing specific VPC endpoint IDs — that's the most restrictive shape and avoids the cross-account VPC ambiguity entirely.

---

### CTL.APIGATEWAY.POLICY.METHODAUTH.CONFLICT.001

**Resource Policy Conflicts With Method-Level Authorization**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, CM-2; pci_dss_v4.0: 7.1, 7.2; soc2: CC6.1, CC6.3, CC8.1;

REST API resource policy and method-level authorization are inconsistent — one is permissive while the other is restrictive. Common shapes: resource policy allows Principal "*" while methods require AWS_IAM (the resource policy effectively grants public access regardless of the method's IAM requirement); or method is open (NONE) while the resource policy denies external principals (callers see Forbidden even though the method is intentionally public). The resource policy is evaluated together with method auth — discrepancies produce surprising auth outcomes that pass one review and fail another.

**Remediation:** Reconcile the two layers: decide whether authorization is enforced at the resource-policy layer (Principal allowlist), the method layer (AWS_IAM / Cognito / Lambda authorizer), or both layered consistently. The common safe pattern is method authorization as the per-route check, with the resource policy as a coarse-grained enforcement layer (org-scoped, VPC- scoped). If the method is intentionally NONE (e.g., a public health endpoint), the resource policy should explicitly allow that route from the expected source set rather than implicitly relying on the method being open.

---

### CTL.APIGATEWAY.PRIVATE.EXTERNAL.VPCE.001

**PRIVATE API Resource Policy Allows VPC Endpoints In External Accounts**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, AC-6, SC-7; iso_27001_2022: A.5.15, A.8.3; nist_800_53_r5: AC-3, AC-6, SC-7; pci_dss_v4.0: 1.2, 7.1; soc2: CC6.1, CC6.3;

PRIVATE-endpoint REST API has a resource policy whose aws:SourceVpce condition lists VPC endpoint IDs from accounts other than the API's home account. PRIVATE APIs are typically intended for in-account or in-organization reach; allowing VPC endpoints from external accounts widens the reachable principal set to whoever in the external account holds permissions to use that VPC endpoint. The cross-account-private pattern is occasionally legitimate (a partner whose workload is in their own AWS account reaches the API through a shared VPC endpoint), but it warrants explicit operator review because the discovery story for "who in the external account can actually invoke" is often unclear without an audit of the external account's IAM.

**Remediation:** Audit each VPCE ID in the resource policy to confirm it belongs to an account where the operator has visibility into who can use the endpoint. Remove external-account VPCEs that don't represent an explicit cross-account integration: aws apigateway update-rest-api with --patch-operations op=replace,path=/policy,value=<json>. For legitimate cross-account integrations, document the arrangement in the triage override and pair with audit visibility into the external account's IAM (organization- wide CloudTrail, central audit role).

---

### CTL.APIGATEWAY.PUBLIC.001

**REST APIs Should Use Private Endpoints When Possible**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

REST APIs using EDGE or REGIONAL endpoint types are internet-accessible. APIs that serve only internal consumers should use PRIVATE endpoint type (VPC-only via PrivateLink) to reduce attack surface.

**Remediation:** Convert to PRIVATE endpoint type if the API serves only VPC consumers. If public access is required, ensure WAF and authorizers are configured.

---

### CTL.APIGATEWAY.RESPONSE.EXPOSURE.001

**API Gateway Default Gateway Responses Expose Internal Details**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-11; nist_800_53_r5: SI-11; pci_dss_v4.0: 6.5.5; soc2: CC6.6;

API Gateway uses the default gateway-response templates rather than customized responses. Default 4xx and 5xx responses include details useful for reconnaissance: the specific failure type (AUTHORIZER_FAILURE, INTEGRATION_FAILURE, INTEGRATION_TIMEOUT, THROTTLED, MISSING_AUTHENTICATION_TOKEN), the request ID, and — for INTEGRATION_FAILURE responses — backend error messages passed through verbatim. An attacker probing the API distinguishes "no auth" from "wrong auth" from "timeout" from "backend crash" and tailors next steps accordingly. Custom gateway responses collapse all of these into generic messages — "400 Bad Request", "500 Internal Server Error" — without revealing which underlying condition produced the response. The control fires when no customizations are in place; it is medium severity because information disclosure aids reconnaissance but doesn't itself enable exploitation.

**Remediation:** Customize gateway responses for the high-information types — DEFAULT_4XX, DEFAULT_5XX, AUTHORIZER_FAILURE, INTEGRATION_FAILURE, MISSING_AUTHENTICATION_TOKEN, UNAUTHORIZED, ACCESS_DENIED — with response templates that return only generic error text. Suppress the Server header in the customized responses. Verify by triggering each failure type and confirming the response body contains no implementation specifics.

---

### CTL.APIGATEWAY.STAGE.AUTODEPLOY.001

**HTTP API Default Stage Has Auto-Deploy Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

HTTP API $default stage has auto-deploy enabled. With auto-deploy on, any change to the API definition — adding or removing routes, modifying integrations, attaching or detaching authorizers, changing CORS — is immediately deployed to the stage. There is no deployment review, no canary, no rollback gate, no separation between "I edited the API" and "the change is live." The $default stage is most often the production stage, so a route added with a misconfigured integration is immediately serving 500 errors to real users; a route whose authorizer was accidentally removed is immediately unauthenticated; a removed route is immediately a 404 for active clients. Auto-deploy is a reasonable convenience on explicitly-named non-production stages (dev, sandbox). On the default stage that backs production traffic, it eliminates every deployment safety control. REST APIs do not have auto-deploy; this control is HTTP-API-specific.

**Remediation:** Disable auto-deploy on the $default stage and move deployments to an explicit pipeline that runs validation, manual approval on production-impacting routes, and a canary or blue/green cutover. If auto-deploy is intentional for the team's workflow, move production traffic to an explicitly-named stage and leave auto-deploy on a non-prod stage instead.

---

### CTL.APIGATEWAY.STAGE.CROSSENV.001

**API Gateway Non-Production Stage Routes to Production Backend**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; pci_dss_v4.0: 6.5.6; soc2: CC8.1;

API Gateway stage whose name suggests non-production (dev, staging, test, qa, sandbox) routes to a backend that appears to be production (production-account ARN, production-stage Lambda alias, prod-tagged URL). The stage name promises isolation; the backend provides none. Two failure modes follow. First, traffic through the non-production stage — typically subject to looser authorizer settings, less restrictive throttling, weaker WAF coverage, and broader developer access — reaches production data. A request that an attacker (or developer) authenticates against the dev stage's relaxed controls hits the same production Lambda, the same production database. Second, developers who believe the dev stage is harmless run destructive operations against it (data resets, schema changes, load tests) and corrupt production state. The control's stage-name and backend-identity heuristics are documented and configurable; false positives are expected when naming conventions don't follow the assumed patterns and should be acknowledged via triage override.

**Remediation:** Point the non-production stage at a non-production backend (separate Lambda alias, separate database endpoint, separate account). If the backend genuinely must be shared, rename the stage so the cross-environment relationship is explicit, or document the exception in a triage override on this control with the reason the stage name and backend cannot be aligned.

---

### CTL.APIGATEWAY.STAGE.GHOST.VARS.001

**API Gateway Stage Variables Reference Deleted Resources**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CM-3; nist_800_53_r5: CM-3; soc2: CC8.1;

API Gateway stage has stage variables that reference resources (Lambda function ARNs, DynamoDB table names, S3 bucket names, backend URLs, parameter store paths) that no longer exist. Stage variables are typically interpolated into integration URIs via ${stageVariables.varName} so a single API definition can target different backends per stage. When the resource a variable points at is deleted, requests that resolve through the variable hit a non-existent target — 5xx responses with no clue at the API Gateway layer that the cause is configuration drift rather than a backend outage. This is the ghost-reference pattern applied to stage variables, alongside CTL.APIGATEWAY.GHOST.LAMBDA.001 (integration ARN), CTL.APIGATEWAY.GHOST.AUTHORIZER.001 (authorizer provider), and others in the apigateway/ghost/ family. Detection requires the extractor to resolve each variable's value against the relevant resource catalog — same mechanism the other ghost controls already use.

**Remediation:** Identify each variable whose value resolves to a deleted resource and either re-create the resource (if the deletion was accidental), update the variable to a current resource, or remove the variable if no integration references it. Add a deletion guard on the affected resource types that cross-references stage variables before allowing the resource to be deleted.

---

### CTL.APIGATEWAY.STAGE.LIFECYCLE.001

**API Gateway Stages Must Not Have Orphaned or Deprecated Versions Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: CM-7; hipaa: 164.312(a)(1); nist_800_53_r5: CM-7; pci_dss_v4.0: 6.3.2; soc2: CC7.1;

API Gateway REST APIs must not have orphaned stages accessible with weaker security controls than the production stage. Orphaned stages from previous deployments, testing, and migrations accumulate without security controls applied to the current stage — no WAF association, no throttling, potentially no authorization. OWASP API9:2023 (Improper Inventory Management) identifies this as a primary API security gap. Older stages may retain endpoints that were fixed or removed in current versions. The security delta between orphaned and production stages defines the attack surface an attacker gains by discovering the old endpoint. A stage with no invocations in 30 days and missing controls present on the production stage is considered orphaned.

**Remediation:** Decommission orphaned stages by deleting the deployment from the API Gateway console or DeleteStage API. If the stage must remain for legacy integration, apply equivalent security controls — WAF association, throttling, and authorization — matching the production stage. Document intentional multi-stage deployments with a stave/api-stage-lookback-days tag.

---

### CTL.APIGATEWAY.STAGE.VARS.CREDENTIALS.001

**API Gateway Stage Variables Contain Credentials**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: SC-28; hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; pci_dss_v4.0: 3.5.1; soc2: CC6.1;

API Gateway stage variables hold values that match credential patterns — AWS access-key prefixes (AKIA, ASIA), database connection strings with embedded passwords, generic password= or token= assignments, or JWT-shaped strings. Stage variables are plaintext configuration: they are visible to anyone with apigateway:GetStage permission, returned in API exports (OpenAPI/Swagger), included in CloudTrail audit events for UpdateStage calls, and may be reflected into responses if used in mapping templates without escaping. They have no encryption at rest beyond the API Gateway service itself and no rotation. This is the same detection mechanism used by CTL.LAMBDA.ENV.SECRETS.001 against Lambda environment variables — same pattern, different configuration surface. Secrets belong in Secrets Manager or SSM Parameter Store SecureString.

**Remediation:** Move the credential to AWS Secrets Manager or SSM Parameter Store SecureString. Update the integration mapping templates or Lambda integrations to fetch the secret at request time via a Lambda authorizer or backend code. Remove the credential from the stage variables and rotate it (assume the previous plaintext is compromised).

---

### CTL.APIGATEWAY.THROTTLE.001

**API Gateway Stages Must Have Throttling Limits Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; hipaa: 164.308(a)(1)(ii)(B); nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: A1.1;

API Gateway stages must have default throttling limits configured with non-zero burst and rate values. Without throttling, a single client can send unlimited requests — exhausting backend resources, generating unbounded AWS costs (Denial of Wallet on Lambda), enabling credential brute force, and abusing sensitive business flows at machine speed. OWASP API4:2023 (Unrestricted Resource Consumption) and API6:2023 (Unrestricted Access to Sensitive Business Flows) both share this infrastructure gap. WAF rate-based rules limit requests per IP at the WAF layer; API Gateway throttling limits requests per stage or per API key at the application layer. Both are needed — WAF addresses anonymous volume attacks, API Gateway throttling addresses authenticated API abuse and distributed attacks that evade per-IP limits.

**Remediation:** Configure stage-level throttling via the API Gateway console or UpdateStage API. Set a burst limit and rate limit appropriate for the API's expected traffic. For REST APIs handling sensitive operations, create a usage plan with per-consumer throttle limits and associate API keys with it.

---

### CTL.APIGATEWAY.THROTTLE.NOPLAN.001

**REST API Has No Usage Plan Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: A1.1;

REST API has no usage plan attached. Usage plans provide per-API-key throttling and quotas — the only way to enforce consumer-specific rate limits in API Gateway. Without a usage plan, every consumer shares the account-level default throttle (10,000 RPS for REST APIs in most regions). One badly behaved or compromised client can exhaust the entire account's API Gateway capacity, denying service to every other API in the account. Stage-level throttling (CTL.APIGATEWAY.THROTTLE.001) caps the API as a whole; usage plans cap individual consumers. Both are needed for APIs with multiple consumers, especially when authentication is API-key-based.

**Remediation:** Create a usage plan with rate, burst, and quota limits appropriate for the API's consumer profile. Associate API keys with the plan and configure clients to send those keys. For APIs with IAM authentication where per-consumer throttling isn't required (the IAM principal already constrains the caller), this control can be acknowledged as not applicable in the triage overrides.

---

### CTL.APIGATEWAY.TLS.001

**API Gateway Must Enforce TLS 1.2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; gdpr: Art.32; hipaa: 164.312(e)(2)(ii); nist_800_53_r5: SC-8; pci_dss_v4.0: 4.2.1; soc2: CC6.6;

API Gateway stages must enforce TLS 1.2 or higher. Allowing older TLS versions exposes API traffic to known cryptographic attacks (BEAST, POODLE, etc).

**Remediation:** Set the minimum TLS version on the custom domain or API stage. For REST APIs, configure a security policy of TLS_1_2 on the custom domain name.

---

### CTL.APIGATEWAY.TLS.MTLS.TRUSTSTORE.001

**API Gateway mTLS Truststore Object Deleted or Empty**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-8; hipaa: 164.312(e)(1); nist_800_53_r5: SC-8; pci_dss_v4.0: 8.3.2; soc2: CC6.1;

API Gateway custom domain has mutual TLS enabled and references a truststore S3 object that has been deleted or is zero bytes. The truststore contains the CA certificates used to validate client certificates. With the truststore object missing or empty, mTLS validation cannot match any client certificate against a trusted CA. REST APIs typically reject all client connections in this state (no valid CA to validate against); HTTP APIs may silently fall back to no-mTLS, validating no client certificates while the console still reports mTLS as enabled. The custom domain configuration appears intact in the console — the truststore URI is set, mTLS is flagged on, but the underlying object is gone or empty. This is the same ghost-reference pattern as the deleted certificate case (CTL.APIGATEWAY.GHOST.CERT.001) applied to the truststore content rather than to the certificate.

**Remediation:** Re-upload the CA bundle to the configured truststore S3 location, or reconfigure the custom domain to point at a truststore object that exists and contains valid PEM-encoded CA certificates. Validate by issuing a client certificate signed by one of the CAs in the bundle and confirming a successful handshake. Add an S3 object-existence alarm against the truststore key so the next accidental delete pages someone before clients are affected.

---

### CTL.APIGATEWAY.TRACING.001

**REST API Stages Should Enable X-Ray Tracing**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-12;

API Gateway REST API stages should enable X-Ray active tracing for distributed request tracing across connected services.

**Remediation:** Enable active tracing on the stage.

---

### CTL.APIGATEWAY.UNAUTH.THROTTLE.MISSING.001

**Unauthenticated Routes Lack Per-Method Throttling**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, AC-7; iso_27001_2022: A.5.30, A.8.6, A.8.16; nist_800_53_r5: SC-5, AC-7; pci_dss_v4.0: 6.4.1; soc2: A1.1, CC6.6;

REST API has methods with NONE authorization (intentionally public — health check, signup, contact form) and no method- level throttle is configured for them. Authenticated routes benefit from per-API-key throttling via usage plans; unauthenticated routes do not — every request is anonymous, every request shares the stage-level limit. Public-facing unauthenticated routes are the highest-throughput attack surface on most APIs: bots, scrapers, abuse traffic, DDoS vectors. They warrant the tightest method-level throttle the use case tolerates, paired with WAF rate-based rules at the edge.

**Remediation:** Add method-level throttle on every NONE-authorized method: aws apigateway update-stage with --patch-operations op=replace,path=/<method-selector>/throttling/rateLimit, value=<rps>. Pair with WAF rate-based rules to drop abusive sources at the edge before they reach API Gateway. For signup or other identity-creation routes, also consider CAPTCHA or proof-of-work to raise the abuse cost.

---

### CTL.APIGATEWAY.USAGEPLAN.QUOTA.MISSING.001

**Usage Plan Has Rate Limit But No Daily/Monthly Quota**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, SC-6; iso_27001_2022: A.5.30, A.8.6; nist_800_53_r5: SC-5, SC-6; pci_dss_v4.0: 6.4.1; soc2: A1.1, A1.2, CC6.6;

REST API usage plan is configured with rate and burst limits but no quota (daily/weekly/monthly request count cap). Rate and burst constrain instantaneous traffic, not aggregate consumption. A consumer that stays under the rate limit but hammers the API steadily for 24 hours generates orders of magnitude more requests than the operator likely intended, driving Lambda invocation costs, downstream backend load, and database read/write spend. Quotas are the time-bounded consumption cap; rate is the instantaneous flow limit. APIs that handle business operations (signup, password reset, payment, search) should set quotas that match expected consumer behavior.

**Remediation:** Set a quota on the usage plan that matches expected consumer aggregate behavior: aws apigateway update-usage-plan with --patch-operations op=add,path=/quota,value='{"limit":10000,"period":"DAY"}'. Periods are DAY, WEEK, MONTH. The number should reflect a consumer's expected upper bound plus operational headroom — bursting consumers can exceed in-period budget; the operator decides whether to refuse or to allow.

---

### CTL.APIGATEWAY.USAGEPLAN.RATE.EXCESSIVE.001

**Usage Plan Rate Limit Far Exceeds Plausible Consumer Need**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, SC-6, CM-2; iso_27001_2022: A.5.30, A.8.6; nist_800_53_r5: SC-5, SC-6, CM-2; pci_dss_v4.0: 6.4.1; soc2: A1.1, A1.2, CC6.6;

REST API usage plan is configured with a rate limit greater than 10000 requests per second per consumer. That ceiling is the AWS account-level default; setting a usage plan rate at or above the account-level limit means the usage plan exerts no effective constraint — every consumer can burst to the account ceiling. Most APIs serve consumers that legitimately need 10s-100s of RPS, not 10000. The number is often left at the AWS console-form maximum during initial setup and never tuned downward; or copied from a high-traffic template without review.

**Remediation:** Lower the per-consumer rate to the value the consumer actually needs: aws apigateway update-usage-plan with --patch-operations op=replace,path=/throttle/rateLimit, value=100. Pair with a burst limit roughly 2-3x the rate. Values appropriate for typical consumers are 10-100 RPS; high-traffic consumers may legitimately need 1000+ but that should be a deliberate decision, not a default.

---

### CTL.APIGATEWAY.VALIDATION.001

**API Gateway Must Have Request Validation Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; hipaa: 164.312(c)(1); nist_800_53_r5: SI-10; pci_dss_v4.0: 6.2.4; soc2: CC6.6;

API Gateway REST APIs must have request validation configured. API Gateway can validate incoming requests against a defined schema — checking required parameters, parameter types and formats, and request body conformance to a JSON schema — before the request reaches the backend. Without validation, malformed and malicious inputs are forwarded to the backend uninspected. This is complementary to WAF protection: WAF managed rules detect known-malicious patterns (SQLi, XSS, known exploits), while request validation detects structural violations (missing fields, wrong types, malformed bodies). A backend that receives only structurally valid requests is harder to attack through injection because type confusion, null pointer paths, and unexpected field exploitation are blocked at the API boundary. Request validation is particularly valuable for APIs handling PHI or financial data where the backend may make trust assumptions about well-formed input.

**Remediation:** Configure a request validator on the REST API via the API Gateway console or PutRestApi/UpdateMethod API. Define request models (JSON schemas) for endpoints that accept request bodies. Enable parameter validation for all methods. For REST APIs handling PHI or sensitive data, enable both parameter and body validation against defined model schemas.

---

### CTL.APIGATEWAY.VALIDATION.BODYONLY.001

**API Gateway Validator Checks Body But Not Parameters**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; nist_800_53_r5: SI-10; soc2: CC6.6;

REST API method has a request validator, but the validator type is BODY only — query string parameters and headers are not validated. Body validation catches malformed JSON and schema violations in the request body, but injection-shaped payloads delivered through query parameters or HTTP headers reach the backend without checks. The finding is "validation is partial" rather than "validation is broken." Severity is low — partial validation is materially better than none. The remediation is upgrading the validator from BODY to BODY_AND_PARAMS.

**Remediation:** Change the method's request validator type from BODY to BODY_AND_PARAMS. Define a parameter schema (queryStringParameters, headers) alongside the body model so the validator has something to check parameters against. The runtime cost of parameter validation is negligible relative to the input surface it covers.

---

### CTL.APIGATEWAY.VALIDATION.MISSING.001

**API Gateway Method Has No Request Validator**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; hipaa: 164.312(c)(1); nist_800_53_r5: SI-10; pci_dss_v4.0: 6.2.4; soc2: CC6.6;

REST API method has no request validator configured at the method level. Distinct from CTL.APIGATEWAY.VALIDATION.001, which checks that the API has *any* validation enabled — this control checks per-method and fires for individual methods whose validator type is NONE even when other methods on the same API have validators. Without a method-level validator, every request reaching that method — body, query string, headers — is forwarded to the backend uninspected. Validation at the gateway is the cheapest layer of input filtering, applied before WAF rule evaluation and before the backend has to spend cycles parsing malformed input. When validation is absent on a method, malformed JSON, oversized values, missing required parameters, and injection-shaped payloads all reach the backend as if they were valid.

**Remediation:** Define a request model (JSON schema) for the method's body and a parameter schema for query strings and headers, then attach a validator of type BODY_AND_PARAMS to the method. Reject obviously malformed requests at the gateway. For HTTP APIs, the equivalent is OpenAPI request validation — not yet covered by this control's predicate; HTTP API methods will not fire this control.

---

### CTL.APIGATEWAY.VALIDATION.PATH.MISSING.001

**REST API Method Validator Doesn't Validate Path Parameters**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-10, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

REST API method has a request validator attached but the validator skips path parameter validation. Path parameters ({userId} in /users/{userId}/orders) flow through to the integration unchecked. Without validation, common issues reach the backend: path-traversal sequences (../../../), type-mismatched values (GUIDs where integers expected, vice versa), oversized values that exceed downstream query column lengths, injection payloads. Path parameters are the most direct integration input on REST APIs — unchecked, they amplify whatever input-handling weaknesses the backend has.

**Remediation:** Use a request validator that includes parameter validation and declare path parameters explicitly: aws apigateway update-method-request-parameter with the path parameter name and required=true. Validate with the OpenAPI / Swagger schema if the API is exported from one — the model can declare type, format, and pattern constraints API Gateway enforces before invoking the integration.

---

### CTL.APIGATEWAY.VALIDATION.QUERY.MISSING.001

**REST API Method Validator Doesn't Validate Query Parameters**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10, SC-7; iso_27001_2022: A.5.10, A.8.16; nist_800_53_r5: SI-10, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

REST API method has a request validator attached but the validator is configured to skip query-string parameter validation. Method query parameters declared on the method (with required=true) flow through to the integration unchecked: missing parameters reach the backend (which often 500s on null), wrong-type parameters bypass schema expectations, parameter-injection payloads transit unfiltered to the backend. Body validation alone is incomplete — many REST endpoints carry their primary input in query strings, and those need the same schema-driven gating as bodies.

**Remediation:** Configure a request validator that includes query/header validation and attach it to the method: aws apigateway create-request-validator with --validate-request-parameters true, then update-method --request-validator-id <id>. Declare each method query parameter with required=true / false explicitly so the validator has a contract to enforce.

---

### CTL.APIGATEWAY.VPCLINK.SG.BROAD.001

**VPC Link Target NLB Security Group Allows Sources Beyond API Gateway**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7; iso_27001_2022: A.5.15, A.8.20; nist_800_53_r5: AC-3, SC-7; pci_dss_v4.0: 1.2, 1.3, 6.4.2; soc2: CC6.1, CC6.6;

REST API VPC Link points at a Network Load Balancer whose security group allows inbound traffic from sources beyond the API Gateway service. Common shapes: SG opens the application port from 0.0.0.0/0, from broad VPC CIDRs, or from any SG in the account. The VPC Link is the API Gateway path to the backend; the NLB SG should restrict inbound to the API Gateway prefix list (com.amazonaws.<region>.apigateway-execute-api) so other sources can't reach the backend by addressing the NLB directly. With a broad SG, anything that can resolve the NLB hostname or IP reaches the backend without traversing API Gateway — bypassing authorizers, WAF, and every other API-Gateway-layer protection.

**Remediation:** Tighten the NLB security group to allow inbound on the application port from only the AWS API Gateway prefix list: aws ec2 authorize-security-group-ingress with SourcePrefixListIds set to the com.amazonaws.<region>.apigateway-execute-api prefix list. Remove broader rules (0.0.0.0/0, broad CIDRs, unrelated SGs). For NLBs that legitimately serve traffic from sources beyond API Gateway (shared NLB used by other callers), document the additional sources explicitly and ensure each is justified.

---

### CTL.APIGATEWAY.VPCLINK.SINGLEAZ.001

**VPC Link Target NLB Provisioned in a Single Availability Zone**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** fedramp_moderate: CP-2, CP-7, SC-7; iso_27001_2022: A.5.30, A.8.14, A.8.16; nist_800_53_r5: CP-2, CP-7, SC-7; pci_dss_v4.0: 1.2; soc2: A1.1, A1.2, CC6.6;

REST API VPC Link points at a Network Load Balancer configured with subnets in a single availability zone. NLB cross-zone load balancing aside, the NLB itself only routes to targets in the AZs where the NLB has subnets — a single-AZ NLB has a single point of failure tied to the health of that AZ. AZ-failure events (rare but real) take the entire VPC Link integration offline. Multi-AZ NLB configuration with subnets in at least two AZs (ideally three) is the standard production posture for HA-relevant backends; the cost is minimal — a few subnets and the same NLB.

**Remediation:** Add subnets in at least one additional availability zone to the NLB: aws elbv2 set-subnets --load-balancer-arn <nlb-arn> --subnets subnet-A subnet-B subnet-C. Provision backend targets in the additional AZs so the NLB has healthy targets to route to. Update the VPC Link configuration if it pins specific subnet IDs. For development or non-production VPC Links where AZ redundancy isn't required, document the rationale in the triage override.

---

### CTL.APIGATEWAY.WAF.001

**REST API Stages Must Have WAF ACL Attached**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

API Gateway REST API stages must have an AWS WAF web ACL associated for application-layer filtering. Without WAF, APIs are exposed to injection attacks, parameter tampering, L7 floods, and bot abuse.

**Remediation:** Associate a WAFv2 web ACL with the API stage.

---

### CTL.APIGATEWAY.WAF.BYPASS.CF.001

**WAF Applied Only at CloudFront — Direct API Gateway Access Bypasses It**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: AC-3, SC-7, SI-4; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, SC-7, SI-4; pci_dss_v4.0: 1.2, 6.4.2; soc2: CC6.1, CC6.6, CC8.1;

REST API stage is fronted by CloudFront with a WAF web ACL attached at the CloudFront layer, but no WAF web ACL is attached at the API Gateway stage layer. The API Gateway execute-api domain (and any custom domain pointed directly at API Gateway rather than at CloudFront) is reachable on the public internet — clients that resolve those endpoints bypass CloudFront entirely, never see the CloudFront-layer WAF, and reach API Gateway directly. Discovery is straight- forward: dig +short, search Censys for the AWS API Gateway certificate, follow CNAMEs through DNS history. The CloudFront-only WAF posture is the false-protection pattern in WAF deployments — appears to provide protection, bypassable at one DNS lookup remove.

**Remediation:** Either disable the default execute-api endpoint and require all clients to traverse CloudFront (the CTL.APIGATEWAY.ENDPOINT.DEFAULT.001 control flags this case), or attach a WAF web ACL at the API Gateway stage level so direct access still flows through WAF: aws wafv2 associate-web-acl with --resource-arn pointing at the API Gateway stage. WAF rules can be attached at multiple layers; the same web ACL ARN can be associated with both CloudFront and API Gateway stages so the rule set stays consistent.

---

### CTL.APIGATEWAY.WAF.RATELIMIT.MISSING.001

**API Gateway WAF Web ACL Has No Rate-Based Rule**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5, SC-7, SI-4; iso_27001_2022: A.5.30, A.8.6, A.8.16; nist_800_53_r5: SC-5, SC-7, SI-4; pci_dss_v4.0: 6.4.1, 6.4.2; soc2: A1.1, CC6.6, CC7.2;

REST API stage is associated with a WAF web ACL, but the web ACL contains no rate-based rule. Rate-based rules drop abusive sources at the WAF layer before requests ever reach API Gateway — the lowest-cost, highest-leverage layer for application-DDoS mitigation. API Gateway's own throttling layer is per-stage / per-API-key; it can't drop traffic by IP. Without WAF rate rules the attack-volume traffic still reaches API Gateway, where it consumes the stage rate limit and crowds out legitimate users with 429 responses.

**Remediation:** Add a rate-based rule to the WAF web ACL: aws wafv2 update-web-acl with a Rule of type RateBasedStatement, Limit (request count over 5-minute window), and Action BLOCK. A typical starting point is 2000 requests per IP per 5 minutes; tune downward for sensitive operations (login: 100, signup: 50). Combine with the count-only detect-mode rule first, observe baseline, then promote to block.

---

### CTL.APIGATEWAY.WEBSOCKET.DEFAULT.UNVALIDATED.001

**WebSocket API $default Route Accepts Any Message Without Validation**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SI-10; nist_800_53_r5: SI-10; soc2: CC6.6;

WebSocket API has a $default route configured but the route's request validator is not enabled. The $default route is the catch-all: every message that does not match a named route selector flows through it. Without validation, any payload — oversized binary frames, malformed JSON, application-protocol messages from a different version, deliberate fuzzing input — reaches the route's backend (Lambda function or HTTP integration) unchecked. Some WebSocket APIs are designed to route everything through $default and validate at the application layer; the triage override should record that decision when it applies. For WebSocket APIs that route by named selector and use $default only as a safety net, the safety net should reject anything it catches.

**Remediation:** Attach a route response selection expression and a model to the $default route, or remove the $default route entirely and let unmatched messages return a Bad Request to the client. For APIs that intentionally route everything through $default with application-layer validation, document that decision in a triage override on this control rather than leaving it as an unacknowledged finding.

---

### CTL.APIGATEWAY.WEBSOCKET.IDLETIMEOUT.MISSING.001

**WebSocket API Has No Connection Idle Timeout Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** resilience
- **Compliance:** fedramp_moderate: SC-5, AC-12; iso_27001_2022: A.5.30, A.8.6; nist_800_53_r5: SC-5, AC-12; pci_dss_v4.0: 6.4.1, 8.2; soc2: A1.1, CC6.6;

WebSocket API stage has no idle timeout configured below the AWS service maximum (10 minutes). Idle WebSocket connections persist until the timeout fires; with the service maximum every idle connection holds backend state (DynamoDB connection records, in-memory routing state, any per-connection resources) for the full 10 minutes after the client falls silent. Attackers exploit this by opening many connections and going silent — exhausting connection state without sending any actual traffic. A shorter idle timeout (60-300 seconds depending on application) reaps silent connections faster, freeing state and bounding the resource cost per connection.

**Remediation:** Configure a per-route idle timeout on the WebSocket API appropriate for the application: aws apigatewayv2 update-stage with default route settings or per-route settings. Most chat-style WebSocket workloads tolerate a 30-60 second idle timeout (clients send keepalives during legitimate activity); pure server-push notification workloads may need longer. Pair with the existing WebSocket throttle and $default-route validation controls.

---

### CTL.APIGATEWAY.WEBSOCKET.ORIGIN.UNVALIDATED.001

**WebSocket $connect Route Doesn't Validate the Origin Header**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** fedramp_moderate: AC-3, IA-2, SC-7; iso_27001_2022: A.5.15, A.8.16; nist_800_53_r5: AC-3, IA-2, SC-7; pci_dss_v4.0: 6.4.2; soc2: CC6.1, CC6.6;

WebSocket API $connect route has no Origin-header validation. Browsers attach an Origin header to WebSocket upgrade requests; the value identifies the page that initiated the connection. Without server-side validation, any web origin can establish a WebSocket connection — a malicious site that gets a victim to visit can open a WebSocket against the API on the victim's behalf, leveraging cookie-based auth to act as the victim. WebSocket connections aren't subject to the Same-Origin Policy unilaterally; the server has to enforce it. The $connect-route Lambda authorizer (or a Lambda integration on $connect) is the layer that should inspect the Origin header and reject connections from origins not in the allowlist.

**Remediation:** Implement Origin-header validation in the $connect Lambda authorizer (or in the $connect Lambda integration if no authorizer is configured). The handler reads the Origin header from the request context, compares against an operator-maintained allowlist, and rejects (returns deny / 403) for unrecognized origins. Document the allowlist explicitly in code or configuration; trusting the Origin header server-side requires the server-side check, since the client controls what it sends.

---

### CTL.APIGATEWAY.WEBSOCKET.THROTTLE.001

**WebSocket API Has No Connection or Message Rate Limiting**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** fedramp_moderate: SC-5; nist_800_53_r5: SC-5; pci_dss_v4.0: 6.4.1; soc2: A1.1;

WebSocket API has no throttling configured for connection establishment or message delivery. A single client can: open thousands of simultaneous connections (each one consuming a $connect Lambda invocation and a connection slot), send unlimited messages per second on each connection (each one consuming a route Lambda invocation and bandwidth), and hold connections indefinitely with no idle timeout enforcement. Without rate limits, a WebSocket API is vulnerable to connection flooding (exhausting the per-account connection budget) and message flooding (exhausting Lambda concurrency or HTTP integration capacity). REST API throttling controls do not apply to WebSocket APIs — WebSocket throttling is a separate configuration surface.

**Remediation:** Configure stage-level throttling on the WebSocket API to set a connection rate and a message rate appropriate for the expected client population. For APIs whose clients are authenticated and per-user limits matter more than per-API limits, also configure an idle connection timeout so that abandoned connections are reclaimed.

---

