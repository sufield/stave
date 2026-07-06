# Control Reference — BEDROCK

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.BEDROCK.ACCESS.ADMIN.001

**Bedrock API Keys Must Not Have Administrative Privileges**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM users with Bedrock API keys must not have policies granting bedrock:* or full administrative access. A compromised overprivileged key can invoke models at scale, modify guardrails and logging, and escalate IAM privileges.

**Remediation:** Scope the IAM user's policies to only the Bedrock actions required (e.g., bedrock:InvokeModel on specific models).

---

### CTL.BEDROCK.ACCESS.FULLACCESS.001

**IAM Roles Must Not Use AmazonBedrockFullAccess Policy**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

IAM roles (excluding service-linked roles) must not have the AWS-managed AmazonBedrockFullAccess policy attached. This policy grants unrestricted access to all Bedrock actions and resources. If the role is compromised, an attacker can invoke any model, modify guardrails and logging, and incur significant costs.

**Remediation:** Replace AmazonBedrockFullAccess with a scoped policy granting only required Bedrock actions on specific model ARNs.

---

### CTL.BEDROCK.ACCESS.LONGTERM.001

**Bedrock API Keys Must Not Be Long-Lived**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: IA-5; soc2: CC6.1;

Bedrock API keys must have appropriate expiration dates. Long-lived or non-expiring keys enable persistent access if compromised — unauthorized inference, exposure of prompts/outputs, uncontrolled cost, and inability to timely revoke credentials.

**Remediation:** Set an appropriate expiration on the API key. Rotate keys regularly and use short-lived credentials where possible.

---

### CTL.BEDROCK.ACCESS.MODELSCOPE.001

**Bedrock Model Access Allows All Foundation Models**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6, CM-7; soc2: CC6.1;

AWS account's Bedrock model access configuration enables all available foundation models rather than restricting to an approved subset. When all models are enabled, any IAM principal with bedrock:InvokeModel permission can call any model — including expensive models (increasing cost blast radius) and models with capabilities beyond what the workload requires (e.g. code generation, image generation). Restricting model access to the approved set limits both cost exposure and the capability surface available to compromised credentials. The model access list is an account-level setting managed through the Bedrock console or bedrock:PutFoundationModelEntitlement API.

**Remediation:** Review the enabled models in the Bedrock console under Model access. Disable models not required by any workload. Enable only the specific models each team needs and enforce per-model IAM conditions (bedrock:InvokeModel with Resource ARN scoped to specific model IDs) in IAM policies.

---

### CTL.BEDROCK.AGENT.ACTIONGROUPS.SPRAWL.001

**Bedrock Agent Action-Group Count Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-6, CM-2; owasp_nhi: NHI5; soc2: CC6.1, CC8.1;

Bedrock agent has more than 10 action groups attached. Each action group is a Lambda function or API schema the agent can invoke; sprawled action-group lists expand the agent's blast radius beyond its stated purpose, often because teams stack ad-hoc tool integrations onto a single agent rather than splitting capability into purpose-built agents. Same shape as CTL.SQS.POLICY.SPRAWL and CTL.SECRETS.POLICY.SPRAWL — accumulated permission attachments that hide effective reachability. An attacker who controls the prompt enumerates the larger surface; legitimate operators no longer reason about what the agent can do.

**Remediation:** Split the agent into purpose-built agents (one per customer workflow) so each agent's action-group list stays small and reviewable. Remove inactive or deprecated action groups via DeleteAgentActionGroup.

---

### CTL.BEDROCK.AGENT.CROSSACCOUNT.001

**Bedrock Agent Resource Policy Allows Cross-Account Invocation**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-3, AC-6; owasp_nhi: NHI4; soc2: CC6.1;

Bedrock agent's resource-based policy grants InvokeAgent permission to principals outside the owning account. A cross-account invocation grant means any principal in the allowed account can invoke the agent, including compromised roles and automated pipelines. The agent's blast radius is its full tool surface — knowledge bases, action-group Lambdas, and the foundation model's inference cost. Cross-account access should use a dedicated proxy role with SourceAccount / SourceArn conditions rather than a direct resource-policy grant, matching the confused deputy prevention pattern used for S3, Lambda, and SQS cross-account access.

**Remediation:** Remove the cross-account principal from the agent's resource policy. Instead, create a proxy role in the agent's account that the remote account assumes via sts:AssumeRole with ExternalId, and scope that role to bedrock:InvokeAgent on the specific agent ARN. Add aws:SourceAccount and aws:SourceArn conditions to the agent's resource policy if cross-account access is genuinely required.

---

### CTL.BEDROCK.AGENT.GHOST.LAMBDA.001

**Bedrock Agent Action Group Must Not Reference Deleted Lambda**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2, CM-8; owasp_nhi: NHI1; soc2: CC8.1;

Bedrock agent has at least one action group whose actionGroupExecutor.lambda field references a Lambda function ARN that no longer exists. Same shape as the Cognito ghost-trigger family (CTL.COGNITO.GHOST.PRESIGNUP.001 et al) applied to Bedrock action groups. The agent's tool list advertises a capability it cannot deliver; either the action group should be deleted (because the underlying Lambda is gone) or the Lambda should be restored. Ghost references are the canonical NHI1 (improper offboarding) failure mode: the surrounding configuration retains active references to decommissioned dependencies.

**Remediation:** Either delete the orphan action group via DeleteAgentActionGroup, or restore the missing Lambda function and reattach it. Re-prepare the agent with PrepareAgent after the change.

---

### CTL.BEDROCK.AGENT.GUARDRAIL.001

**Bedrock Agents Must Have an Associated Guardrail**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock agents must have a guardrail associated with their sessions. Without guardrails, agent exchanges may expose PII or internal data, accept prompt injections that manipulate tool calls, and produce unsafe or out-of-scope responses. Agents can invoke tools and APIs — an unguarded agent is an unguarded API caller.

**Remediation:** Associate a guardrail with the agent via the guardrailConfiguration setting in the agent definition.

---

### CTL.BEDROCK.AGENT.LOGGING.001

**Bedrock Agent Must Have Per-Agent Invocation Logging**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-2, AU-12; owasp_nhi: NHI8; soc2: CC7.2;

Bedrock agent invocations must be captured by per-agent logging. The account-level CTL.BEDROCK.LOG.INVOCATION.001 control checks the global ModelInvocationLoggingConfiguration; this control flags individual agents that opt out of, or are not covered by, invocation logging — so an operator can see "agent X has no audit trail" without scanning every agent's coverage manually. Without per-agent invocation records, prompt-injection attacks, unauthorized tool calls, and data-exfiltration attempts leave no forensic evidence.

**Remediation:** Enable model invocation logging at the account level (PutModelInvocationLoggingConfiguration) and verify the agent's invocations land in the configured CloudWatch log group or S3 destination. For agents that need logging segregated from the account default, configure a dedicated logging configuration tagged with the agent ID.

---

### CTL.BEDROCK.AGENT.OVERPERM.LAMBDA.001

**Bedrock Agent Execution Role Must Scope lambda:InvokeFunction**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

Bedrock agent execution role grants lambda:InvokeFunction on Resource: * — the agent can invoke any Lambda function in the account, not only the functions registered as action groups. An attacker who gains prompt control can direct the agent to invoke privileged Lambda functions beyond its intended tool set, turning the agent into a proxy for arbitrary Lambda execution. Scope lambda:InvokeFunction to the specific function ARNs registered in the agent's actionGroups.

**Remediation:** Replace Resource: "*" on lambda:InvokeFunction with the explicit list of Lambda function ARNs the agent's actionGroups reference. Example: Resource: ["arn:aws:lambda:us-east-1:111122223333:function:order-lookup", "arn:aws:lambda:us-east-1:111122223333:function:product-search"].

---

### CTL.BEDROCK.AGENT.OVERPERM.MODEL.001

**Bedrock Agent Execution Role Must Scope bedrock:InvokeModel**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

Bedrock agent execution role grants bedrock:InvokeModel on Resource: * — the agent can invoke any foundation model in the account, ignoring whatever model the agent's foundation_model field declares. An attacker who controls the agent's prompt or tool input can pivot the agent to invoke unintended models (cheaper, less restricted, or with different content policies) and bypass model-allowlist governance. Scope the bedrock:InvokeModel permission to the specific model ARN(s) the agent is configured to use.

**Remediation:** Scope the role's bedrock:InvokeModel permission to the specific foundation model ARN(s) the agent uses. Replace Resource: "*" with explicit model ARNs such as arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-sonnet-20240229-v1:0.

---

### CTL.BEDROCK.AGENT.OVERPERM.S3.001

**Bedrock Agent Execution Role Must Scope S3 Access**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

Bedrock agent execution role grants s3:GetObject (or s3:*) on Resource: * — the agent can read any object in any bucket in the account, not only the buckets that back its action-group API schemas or knowledge-base data sources. An attacker who controls the agent's prompt or tool input can extract data from buckets the agent should never touch (PHI buckets, customer-tenant buckets, audit logs).

**Remediation:** Scope the role's s3:GetObject (and any other S3 actions) to the specific bucket / prefix combinations the agent's action groups and knowledge bases reference. Use StringEquals on s3:prefix conditions to narrow further.

---

### CTL.BEDROCK.AGENT.PUBLIC.INVOCATION.001

**Bedrock Agent Invocation Endpoint Must Not Be Publicly Accessible**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3, SC-7; owasp_nhi: NHI6; soc2: CC6.6;

Bedrock agent's invocation surface is reachable without authenticated AWS principals — for example, an API Gateway fronting InvokeAgent with no authorizer, a public Lambda URL proxying agent invocation, or a CloudFront distribution that forwards directly to the agent without auth. The agent's blast radius is whatever the agent's execution role can reach (knowledge-base contents, Lambda action groups, invoked models). Letting unauthenticated callers reach InvokeAgent turns the agent's internal data and tool surface into an internet-accessible API. The collector pre-computes the boolean from the agent's downstream invocation paths (API Gateway authorizers, Lambda URL auth_type, public CloudFront distributions pointing at the agent endpoint).

**Remediation:** Front the agent invocation with an authenticated path: either an API Gateway authorizer (Cognito user pool, custom Lambda authorizer, or IAM auth), a Lambda URL with auth_type=AWS_IAM, or a private VPC integration. Remove any public Lambda URL or unrestricted API Gateway resource that proxies InvokeAgent.

---

### CTL.BEDROCK.AGENT.SESSION.TTL.001

**Bedrock Agent Idle Session TTL Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(2)(iii); nist_800_53_r5: AC-12; owasp_nhi: NHI7; soc2: CC6.1;

Bedrock agent's idle session TTL (idleSessionTTLInSeconds) is excessive — sessions persist longer than necessary, leaving partially-consumed agent contexts available to subsequent callers. A long-lived idle session keeps prompt history, tool-call results, and partially-populated working memory available to whoever next attaches to that session ID. The collector pre-computes whether the configured TTL exceeds the recommended threshold (1800 seconds / 30 minutes by default).

**Remediation:** Reduce idleSessionTTLInSeconds on the agent to 1800 (30 minutes) or less. For agents handling sensitive workflows, 600 (10 minutes) is the tighter recommendation. Update via UpdateAgent and re-prepare with PrepareAgent.

---

### CTL.BEDROCK.AGENT.SHADOW.001

**Bedrock Agent Must Be Managed by Infrastructure as Code**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2, CM-3, AC-3; owasp_nhi: NHI1, NHI6; soc2: CC8.1;

Bedrock agent has no infrastructure-as-code management tag (managed_by, terraform, cloudformation, or equivalent). Agents created outside the IaC pipeline are not subject to code review, approval workflows, or drift detection — their permissions may exceed what the security team has approved, and there is no audit trail tying the agent's existence to a reviewed commit. Shadow agents are the canonical AI-surface ungoverned-configuration failure mode: production agents appear through console clicks or scripted CLI calls without going through change-management. The collector pre-computes the managed_by_iac boolean by inspecting the agent's tags against the organisation's IaC tagging convention.

**Remediation:** Either (1) import the agent into your IaC pipeline via terraform import or aws cloudformation import, then tag it with managed_by=terraform / managed_by=cloudformation, or (2) delete the agent if it was created for ad-hoc testing and is no longer in active use. Reject any future untagged agents at the SCP / Service Control Policy level with a Deny statement on bedrock:CreateAgent missing the required tag.

---

### CTL.BEDROCK.AGENT.STALE.001

**Bedrock Agent Must Not Be Idle Beyond Threshold**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2(3); owasp_nhi: NHI1; soc2: CC6.1;

Bedrock agent has not been invoked within the observation window (default 30 days). A stale agent retains its execution role permissions, its action-group registrations (the Lambdas it can call), and its knowledge-base associations — a dormant attack surface with active credentials. Same shape as CTL.SAGEMAKER.NOTEBOOK.IDLE.001 (idle data-science notebook) and CTL.LIFECYCLE.STAGING.STALE.001 (general stale-resource pattern) applied to Bedrock agents. Distinct from CTL.BEDROCK.AGENT.SESSION.TTL.001 (idle-session TTL too long): SESSION.TTL is per-session timeout configuration; this control flags agents whose entire identity is idle.

**Remediation:** Either delete the agent + its execution role if the workload is truly abandoned, or document the agent's expected idle duration with a reviewed_at tag and a scheduled review date. Reduce blast radius by detaching high-privilege managed policies from the role even while the agent stays.

---

### CTL.BEDROCK.AGENT.TOOLACCESS.BROAD.001

**Bedrock Agent Must Not Have Excessive Action Groups**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; owasp_llm: LLM08; scs_c02: 13.1; soc2: CC6.1;

Bedrock agents should have a minimal set of action groups — each action group grants the agent access to an additional Lambda function or API schema. OWASP LLM08 (Excessive Agency) identifies this as a top LLM risk: agents with many tools have a larger attack surface for prompt injection. An attacker who gains prompt control can invoke any tool the agent has access to. Limit action groups to the minimum set required for the agent's purpose.

**Remediation:** Review each action group and remove any that are not required for the agent's primary purpose. Split agents with many tools into specialized agents with fewer, scoped action groups.

---

### CTL.BEDROCK.AGENTCORE.CRED.001

**AgentCore Runtime Must Use Credential Provider Not Embedded Secrets**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: IA-5(7); pci_dss_v4.0: 3.4.1; soc2: CC6.1;

AgentCore runtime tool configuration contains embedded credentials (API keys, tokens, passwords) instead of referencing a Credential Provider. Embedded secrets persist in the runtime configuration, appear in API responses (GetAgentRuntime), and cannot be rotated without redeploying the runtime. AgentCore's Credential Provider integrates with OAuth token vaulting and automatic rotation — embedded secrets bypass these protections. The collector pre-computes whether the tool configuration contains embedded secret patterns.

**Remediation:** Migrate embedded secrets to an AgentCore Credential Provider. Configure OAuth credentials through the Credential Provider API and reference them by ARN in the tool configuration. Delete the embedded secret values after migration.

---

### CTL.BEDROCK.AGENTCORE.GW.DEBUG.001

**AgentCore Gateway Must Not Expose Debug Exceptions**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-11; owasp_nhi: NHI9; soc2: CC7.2;

AgentCore gateway exceptionLevel is set to DEBUG — error responses include full stack traces, internal service names, and configuration details. An attacker probing the gateway can use these details to map internal architecture, identify software versions, and craft targeted exploits. DEBUG exception level should never be enabled in production.

**Remediation:** Remove the exceptionLevel setting or set it to a non-DEBUG value. DEBUG is appropriate only for development gateways in isolated environments.

---

### CTL.BEDROCK.AGENTCORE.GW.EGRESS.001

**AgentCore Gateway Targets Must Use Private Endpoints**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-7, SC-8; soc2: CC6.6;

AgentCore gateway target does not use a private endpoint — traffic between the gateway and the target (MCP server, Lambda, HTTP endpoint) traverses the public internet. AgentCore supports VPC egress private endpoints via VPC Lattice for gateway targets, routing traffic through the customer's VPC without internet exposure. Without private endpoints, credentials, tool payloads, and agent context are exposed to network-path interception.

**Remediation:** Configure a private endpoint for the gateway target via the privateEndpoint field on the GatewayTarget resource. This creates a VPC Lattice-managed endpoint within the customer VPC.

---

### CTL.BEDROCK.AGENTCORE.GW.ENCRYPT.001

**AgentCore Gateway Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12, SC-28; soc2: CC6.1;

AgentCore gateway does not have a customer-managed KMS key (kmsKeyArn is absent). Without CMK encryption, gateway data (OAuth tokens, credential provider secrets, session context) is encrypted with the AWS-managed default key, which the customer cannot rotate, audit, or revoke independently. CMK provides cryptographic isolation — revoking the key immediately renders all gateway data inaccessible, a critical incident-response capability for agent infrastructure handling third-party credentials.

**Remediation:** Create a KMS key for AgentCore gateway encryption and set kmsKeyArn on the gateway. Use a key policy that restricts access to the gateway service role and security operators.

---

### CTL.BEDROCK.AGENTCORE.GW.WAF.001

**AgentCore Gateway Must Have WAF Web ACL Attached**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7(5); soc2: CC6.6;

AgentCore gateway does not have a WAF web ACL (webAclArn is absent). Without WAF, the gateway has no request-level filtering — no rate limiting, no IP reputation blocking, no managed rule groups for known attack patterns. AgentCore gateways are internet-facing MCP endpoints; WAF provides the first line of defense against volumetric abuse, credential stuffing, and prompt-injection payloads delivered via malformed requests.

**Remediation:** Create a WAF web ACL with appropriate managed rule groups (AWSManagedRulesCommonRuleSet, AWSManagedRulesBotControlRuleSet) and associate it with the AgentCore gateway via webAclArn.

---

### CTL.BEDROCK.AGENTCORE.IMDS.001

**AgentCore Runtime Must Require IMDSv2**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-3, SC-23; owasp_nhi: NHI5; soc2: CC6.1;

AgentCore runtime metadataConfiguration.requireMMDSV2 is false — the runtime accepts IMDSv1 requests. IMDSv1 uses a simple GET without a session token, making it exploitable via SSRF attacks: any code running in the agent that can issue HTTP requests to 169.254.169.254 can steal the runtime's IAM credentials. IMDSv2 requires a PUT-based token exchange that SSRF payloads typically cannot perform. This mirrors CTL.EC2.IMDSV2.001 applied to the AgentCore execution environment.

**Remediation:** Set metadataConfiguration.requireMMDSV2 to true on the AgentCore runtime via UpdateAgentRuntime.

---

### CTL.BEDROCK.AGENTCORE.LOGGING.001

**AgentCore Runtime Must Have Logging Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** audit
- **Compliance:** hipaa: 164.312(b); nist_800_53_r5: AU-2, AU-12; owasp_nhi: NHI8; soc2: CC7.2;

AgentCore runtime does not have S3 logging configured — agent invocations, tool calls, and session events leave no audit trail. Without log uploads, prompt-injection attacks, unauthorized tool execution, and data exfiltration through the agent produce no forensic evidence. AgentCore supports S3LoggingConfiguration for durable log storage.

**Remediation:** Configure S3LoggingConfiguration on the runtime via CreateAgentRuntime or UpdateAgentRuntime. Point to an S3 bucket with appropriate lifecycle policies and encryption.

---

### CTL.BEDROCK.AGENTCORE.MEM.ENCRYPT.001

**AgentCore Memory Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-12, SC-28; soc2: CC6.1;

AgentCore memory does not have a customer-managed KMS key (encryptionKeyArn is absent). Agent memory stores conversation history, tool-call results, extracted facts, and strategy outputs — potentially including PII, credentials, and business logic. Without CMK encryption, this data is encrypted with the AWS-managed default key, which the customer cannot independently rotate or revoke. CMK provides cryptographic kill-switch capability: revoking the key immediately makes all stored memory inaccessible.

**Remediation:** Create a KMS key for AgentCore memory encryption and set encryptionKeyArn on the memory resource. The key policy should restrict access to the memory execution role and security operators.

---

### CTL.BEDROCK.AGENTCORE.NOAUTH.001

**AgentCore Gateway Must Require Authentication**

- **Severity:** critical
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(d); nist_800_53_r5: AC-3, IA-2; owasp_nhi: NHI4; soc2: CC6.1;

AgentCore gateway authorizer type is set to NONE — the gateway endpoint accepts unauthenticated requests. Any caller with network access to the gateway can invoke the agent, triggering model inference, tool execution, and memory access without identity attribution. AgentCore supports CUSTOM_JWT, AWS_IAM, and AUTHENTICATE_ONLY authorizer types; NONE should never be used outside development.

**Remediation:** Set the gateway authorizer type to AWS_IAM (recommended) or configure a JWT authorizer with a trusted identity provider. NONE authorizer is appropriate only for internal development endpoints isolated within a private VPC.

---

### CTL.BEDROCK.AGENTCORE.OVERPERM.001

**AgentCore Runtime Execution Role Must Scope Permissions**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

AgentCore runtime execution role grants overly broad permissions — the role can reach resources far beyond what the runtime's registered tools require. An attacker who controls the agent's prompt or tool input can leverage the broad role to read, write, or delete resources the agent should never touch. The collector pre-computes whether the role's effective permissions exceed the runtime's declared tool scope. Mirrors CTL.BEDROCK.AGENT.OVERPERM.S3.001 applied to AgentCore runtimes.

**Remediation:** Scope the role's permissions to the specific resources the runtime's tools require. Use resource-based conditions (aws:ResourceTag, StringEquals on prefix) to narrow access. Review the role with IAM Access Analyzer to identify unused permissions.

---

### CTL.BEDROCK.AGENTCORE.SESSION.001

**AgentCore Runtime Session Lifetime Must Be Bounded**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(2)(iii); nist_800_53_r5: AC-12; owasp_nhi: NHI7; soc2: CC6.1;

AgentCore runtime lifecycleConfiguration.maxLifetime exceeds the recommended threshold. Long-lived runtime sessions extend the window during which a compromised agent retains its execution role credentials, memory context, and tool access. The collector pre-computes whether maxLifetime exceeds the threshold (default 28800 seconds / 8 hours). Shorter lifetimes force credential rotation and limit the blast radius of prompt-injection or credential-theft attacks.

**Remediation:** Reduce lifecycleConfiguration.maxLifetime to 28800 seconds (8 hours) or less. For agents handling sensitive data, 3600 seconds (1 hour) is the tighter recommendation. Update via UpdateAgentRuntime.

---

### CTL.BEDROCK.AGENTCORE.STALE.001

**AgentCore Runtime Must Not Be Idle Beyond Threshold**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-2(3); owasp_nhi: NHI1; soc2: CC6.1;

AgentCore runtime has not been invoked within the observation window (default 30 days). A stale runtime retains its execution role credentials, network configuration, and tool registrations — a dormant attack surface with active permissions. The collector pre-computes whether the runtime's last invocation exceeds the staleness threshold. Mirrors CTL.BEDROCK.AGENT.STALE.001 applied to AgentCore runtimes.

**Remediation:** Either delete the runtime and its execution role if the workload is truly abandoned, or document the runtime's expected idle duration with a reviewed_at tag and a scheduled review date. Reduce blast radius by detaching high-privilege managed policies from the role even while the runtime stays.

---

### CTL.BEDROCK.AGENTCORE.VPC.001

**AgentCore Runtime Must Be VPC-Attached**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: SC-7, AC-4; soc2: CC6.6;

AgentCore runtime networkConfiguration.networkMode is PUBLIC — the runtime executes on the public network rather than within a customer VPC. A public-mode runtime sends all egress traffic (tool calls, API requests, model invocations) over the internet, exposing it to network-path threats. VPC mode routes traffic through customer-controlled subnets and security groups, enabling VPC endpoint routing, security group filtering, and flow log capture.

**Remediation:** Set networkConfiguration.networkMode to VPC and configure subnets and security groups via networkModeConfig. Use private subnets with VPC endpoints for AWS service access.

---

### CTL.BEDROCK.CUSTOMMODEL.ENCRYPT.001

**Bedrock Custom Model Must Use Customer-Managed KMS Key**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Bedrock custom model (fine-tuned or imported) does not use a customer-managed KMS key for encryption. Custom models contain organization-specific training data encoded in model weights. Without a customer-managed key, the model artifact uses AWS- managed encryption, which does not allow key rotation control, key policy restrictions, or CloudTrail logging of key usage. For models fine-tuned on proprietary or regulated data, customer- managed KMS keys provide the audit trail and access control required for compliance.

**Remediation:** Specify a customModelKmsKeyId when creating the custom model via CreateModelCustomizationJob. Use a customer-managed KMS key with a key policy scoped to the Bedrock service principal.

---

### CTL.BEDROCK.GHOST.KNOWLEDGEBASE.001

**Bedrock Agent Must Not Reference Deleted Knowledge Base**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: CM-2, CM-8; owasp_nhi: NHI1; soc2: CC8.1;

Bedrock agent's knowledgeBases list contains at least one knowledge-base ID that no longer exists in the current inventory. RAG queries through this agent will fail or return empty results — and the broken reference is invisible to runtime: the agent silently degrades. Sibling to CTL.BEDROCK.AGENT.GHOST.LAMBDA.001 (which catches the same pattern on actionGroups). Same shape as the Cognito ghost-trigger family (PRESIGNUP, PREAUTH, ...) applied to Bedrock agent KB references. The collector pre-computes the has_ghost_knowledge_base boolean by joining the agent's declared KB IDs against the live knowledge-base inventory.

**Remediation:** Either remove the dead knowledge base from the agent via DisassociateAgentKnowledgeBase, or recreate the knowledge base if it was deleted accidentally. Re-prepare the agent with PrepareAgent after the change.

---

### CTL.BEDROCK.GUARDRAIL.CONTENT.001

**Bedrock Guardrails Must Enable Content Filter**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock guardrails must configure content filters to block harmful content categories (hate, insults, sexual, violence, misconduct). Without content filtering, the model can generate or accept content in regulated categories. Content filters operate on both prompts and responses, providing defense-in-depth against prompt injection attacks that attempt to elicit harmful outputs.

**Remediation:** Configure content filters in the guardrail for all applicable categories (hate, insults, sexual, violence, misconduct) with appropriate strength levels.

---

### CTL.BEDROCK.GUARDRAIL.PII.001

**Bedrock Guardrails Must Enable Sensitive Information Filter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock guardrails must configure sensitive information filters to block or mask PII and custom patterns in prompts and responses. Without filtering, prompts or outputs can reveal PII, credentials, financial records, or other sensitive data. LLMs may echo sensitive data from prompts or training data in responses.

**Remediation:** Configure sensitive information filters in the guardrail to block or mask PII types (SSN, credit card, email, etc.) and custom regex patterns.

---

### CTL.BEDROCK.GUARDRAIL.PROMPTATTACK.001

**Bedrock Guardrails Must Enable High-Strength Prompt Attack Filter**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SI-10; soc2: CC6.1;

Bedrock guardrails must configure the prompt attack filter at HIGH strength. Without high-strength filtering, models are exposed to prompt injection and jailbreak attacks that can coerce disclosure of sensitive data, evade content policies, and trigger unintended tool execution.

**Remediation:** Update the guardrail to set the prompt attack filter strength to HIGH via aws bedrock update-guardrail.

---

### CTL.BEDROCK.GUARDRAIL.TOPIC.001

**Bedrock Guardrails Must Define Topic Policy**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

Bedrock guardrails must configure a topic policy to deny specific subjects the model should not engage with. Without a topic policy, the guardrail relies solely on content filters, which operate on toxicity categories but cannot enforce business-specific restrictions — for example, preventing a customer-facing model from discussing competitors, providing medical advice, or generating legal opinions.

**Remediation:** Add a topic policy to the guardrail with denied topics appropriate for the model's use case. Define clear topic definitions and sample phrases for each denied topic.

---

### CTL.BEDROCK.KB.DATASOURCE.CROSSACCOUNT.001

**Bedrock Knowledge Base Data Source Must Not Cross Account Boundary**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(e)(1); nist_800_53_r5: AC-4, AC-6; owasp_nhi: NHI3, NHI6; soc2: CC6.1, CC6.6;

Bedrock knowledge base reads from an S3 bucket in a different AWS account. Cross-account RAG ingestion expands the trust boundary of the agent's response surface: query results may include content from outside the workload's control plane, and a compromise of the source account propagates into the agent's outputs. Cross-account data sources are sometimes legitimate (a dedicated data-engineering account feeding a product account) but require explicit scoping — VPC endpoint policies, encryption-in-transit on the bucket policy, and pinned KMS key ARNs — none of which are visible to a casual reader of the knowledge-base config. This control flags the cross-account property so operators can confirm the scoping is in place.

**Remediation:** Either (1) replicate the data source into the local account via S3 replication + recreate the knowledge base, or (2) keep the cross-account source but pin the bucket policy to require aws:PrincipalArn matching the KB role and add a VPC endpoint policy restricting the call path. Document the cross-account dependency in the agent's runbook.

---

### CTL.BEDROCK.KB.DATASOURCE.UNENCRYPTED.001

**Bedrock Knowledge Base Data Source Must Use Encrypted Reads**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** governance
- **Compliance:** hipaa: 164.312(e)(1), 164.312(e)(2)(ii); nist_800_53_r5: SC-8, SC-13; owasp_nhi: NHI6; soc2: CC6.7;

Bedrock knowledge base reads its S3 data source without encryption in transit / encryption-context binding. RAG retrieval flows S3 object content through the knowledge base ingestion pipeline; without TLS-only bucket policy enforcement (aws:SecureTransport=true) and SSE-KMS with explicit encryption context, the data path is observable on shared network paths and AWS API logs do not bind retrieval to the intended decrypt key. The collector pre-computes the boolean data_source_encrypted assessment from the bucket policy, KMS key policy, and KB role's permission boundary.

**Remediation:** Add aws:SecureTransport=true deny-rule to the source bucket's policy. Configure the bucket with SSE-KMS and a customer-managed CMK. Add a key policy permitting the KB role to decrypt with an explicit encryption context matching the knowledge-base ID.

---

### CTL.BEDROCK.KB.MARKER.INDEXES.001

**Bedrock Knowledge Base Indexes S3 Bucket (Marker)**

- **Severity:** low
- **Type:** marker
- **Domain:** governance
- **Compliance:** hipaa: 164.312(c)(1);

Fact-recording marker for Bedrock knowledge bases that index a specific S3 bucket. Emits an informational finding (NOT a violation) on every knowledge base whose data source carries a bucket ARN — so cross-resource chains can compose this fact with data-classification markers on the target bucket. Same pattern as CTL.S3.MARKER.PHI.001 + CTL.COGNITO.IDPOOL.UNAUTH.S3 / cognito_unauth_phi_s3 chain: a knowledge base indexing a bucket is the desired state — never a finding to triage. The marker exists so the chain engine can join "knowledge base side: indexes bucket X" with "storage side: bucket X is classified PHI" via scope_field on the shared bucket ARN.

**Remediation:** None. This marker exists as a chain-detection ingredient. To suppress noise on dashboards, filter findings by control_id when rendering Findings — markers should appear in a separate "facts" panel rather than the violation list.

---

### CTL.BEDROCK.KB.OVERPERM.S3.001

**Bedrock Knowledge Base Role Must Scope S3 Access to Data Sources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** hipaa: 164.312(a)(1); nist_800_53_r5: AC-6; owasp_nhi: NHI5; soc2: CC6.1;

Bedrock knowledge base IAM role grants S3 access broader than the buckets / prefixes declared in the knowledge base's dataSources. The collector compares the role's effective S3 resource set against the knowledge base's declared data-source ARNs; this control fires when the role can read S3 objects outside the declared sources. RAG retrieval becomes a data- exfiltration surface: queries that slip past topic filtering can pull content from any bucket the role can reach, not only the buckets the knowledge base is supposed to index.

**Remediation:** Restrict the knowledge base role's S3 actions to the exact bucket ARNs (and inclusion prefixes) listed in the knowledge base's dataSources. Use StringEquals on s3:prefix conditions for prefix-scoped data sources.

---

### CTL.BEDROCK.KB.RETRIEVAL.OVERBROAD.001

**KB Retrieval Role Must Not Be Broader Than the Embedding Role**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

A Bedrock Knowledge Base has two roles: the embedding role (ingestion/sync — reads source data, writes the vector store) and the retrieval role (query — should only read the vector store and call bedrock:Retrieve). The retrieval role's effective permissions must be a strict subset of the embedding role's on data sources, and the retrieval role must hold no write access at all. If retrieval is broader — a wildcard the embedding role lacks, write access, or reach to a source the embedding role cannot touch — the query path can read or mutate data the KB was never designed to expose.
This is a two-role comparison, not a single-role check. The reasoning layer resolves each role's effective permissions (inline + attached managed + boundary, with wildcards expanded) and computes the set difference, emitting ai.knowledge_base.retrieval_broader_than_embedding. The reasoning spec — Soufflé set-difference plus a Z3 cross-check — lives at examples/rag-retrieval-vs-embedding/.

**Remediation:** Scope the retrieval role to read-only on exactly the vector store and the sources the embedding role reads, plus bedrock:Retrieve on the KB. Remove any write actions (s3:PutObject/DeleteObject, opensearchserverless Create/Update/Delete, bedrock:StartIngestionJob) and any wildcard grants. Check attached managed policies, not just inline.

---

### CTL.BEDROCK.KB.RETRIEVAL.SCOPE.001

**KB Retrieval Role Must Not Reach Data Beyond Declared Sources**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** identity
- **Compliance:** nist_800_53_r5: AC-6; soc2: CC6.1;

A Bedrock Knowledge Base declares its data sources (specific S3 prefixes, OpenSearch collections). The retrieval role must not be able to reach data outside that declared set — not through a wildcard S3 prefix that happens to match other buckets, not through an AssumeRole hop to a role with broader access, and not through a resource-based policy on some other bucket that grants the retrieval role. Any such path lets the retrieval connector pull data the Knowledge Base was never scoped to serve.
This is a compound (graph-reachability) control over a resource type that bridges IAM to data stores. The reasoning layer parses the KB's declared dataSourceConfiguration, resolves what the retrieval role can actually reach (IAM policies with wildcard expansion + assume chains + resource-based policies), and emits ai.knowledge_base.retrieval_exceeds_declared_scope when the reachable set is not contained in the declared set. The reasoning spec — Soufflé reachability plus a Z3 cross-check, including wildcard-prefix and resource-policy edges — lives at examples/rag-retrieval-scope/.

**Remediation:** Scope the retrieval role's resource ARNs to exactly the declared data sources (no wildcard prefixes that overmatch). Remove assume-role edges that widen reach. Audit bucket/collection resource policies for grants to the retrieval role on non-source stores and remove them.

---

### CTL.BEDROCK.LOG.CONTENT.001

**Bedrock Model Invocation Logging Must Include Input and Output Content**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-3; owasp_llm: LLM02; scs_c02: 13.2; soc2: CC7.1;

Bedrock model invocation logging must capture both input (prompt) and output (response) content, not just metadata. OWASP LLM02 (Insecure Output Handling) and LLM06 (Sensitive Information Disclosure) require visibility into what data flows through model invocations. Without content logging, prompt injection attacks and data exfiltration via model responses go undetected in forensic review.

**Remediation:** Update the model invocation logging configuration to include input and output data logging to S3 or CloudWatch Logs.

---

### CTL.BEDROCK.LOG.ENCRYPT.001

**Bedrock Invocation Logs Must Be Encrypted**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** encryption
- **Compliance:** hipaa: 164.312(a)(2)(iv); nist_800_53_r5: SC-28; soc2: CC6.7;

Bedrock model invocation logs must be stored in encrypted destinations — S3 with bucket encryption and CloudWatch Logs with KMS. Invocation logs contain prompts and responses which frequently include sensitive business data, PII, and confidential queries.

**Remediation:** Enable KMS encryption on the CloudWatch Logs group and/or S3 bucket used for invocation log delivery.

---

### CTL.BEDROCK.LOG.INVOCATION.001

**Bedrock Model Invocation Logging Must Be Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

Bedrock model invocation logging must be enabled to capture request/response data for Converse, InvokeModel, and streaming calls. Without invocation logs, there is no audit trail for what prompts were sent or what the model responded — credential misuse, prompt injection, and data exfiltration go undetected.

**Remediation:** Enable model invocation logging via aws bedrock put-model-invocation-logging-configuration with S3 and/or CloudWatch Logs destinations.

---

### CTL.BEDROCK.VPC.ENDPOINTS.001

**VPC Must Have Bedrock Interface Endpoints Configured**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: SC-7; soc2: CC6.6;

VPCs using Bedrock must have interface endpoints for all Bedrock services (bedrock, bedrock-runtime, bedrock-agent, bedrock-agent-runtime). Without private endpoints, API traffic exits the VPC via internet gateway, exposing it to network-path threats and adding an internet dependency.

**Remediation:** Create interface VPC endpoints for bedrock, bedrock-runtime, bedrock-agent, and bedrock-agent-runtime services.

---

