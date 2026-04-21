# Lambda Security Coverage Audit

Audited: 2026-04-21
Request: BMW Lambda security detection
Catalog: 685+ controls (22 dedicated CTL.LAMBDA.* + 8 IAM/VPC)

## Summary

**18 of 20 vectors fully covered.** 1 partially covered, 1 not
covered. The catalog has 22 dedicated Lambda controls plus 8
related IAM and VPC controls. 10 chain definitions model compound
Lambda attack paths. The observation contract defines
`aws_lambda_function` assets with `compute.*` properties covering
execution roles, environment, function URLs, VPC, logging,
tracing, runtime, concurrency, code signing, and layers.

Lambda is one of Stave's strongest-covered domains. BMW can enable
30 controls and 10 chains today with zero implementation work.

## For BMW: what's ready today

### Lambda Controls

| Vector | Control | What it detects |
|--------|---------|-----------------|
| Over-privileged role | CTL.LAMBDA.ROLE.LEASTPRIV.001 | `execution_role.is_overprivileged` |
| Wildcard PassRole | CTL.LAMBDA.PASSROLE.001 | `execution_role.has_wildcard_passrole` |
| Shared roles | CTL.LAMBDA.ROLE.SHARED.001 | `execution_role.is_shared` |
| PassRole to Lambda | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 | PassRole + CreateFunction escalation path |
| PassRole conditions | CTL.IAM.POLICY.PASSROLE.001, CTL.IAM.POLICY.PASSROLE.CONDITION.001 | Unrestricted PassRole, missing service condition |
| Plaintext env secrets | CTL.LAMBDA.ENV.SECRETS.001 | `env.has_plaintext_secrets` |
| Missing KMS on env | CTL.LAMBDA.ENV.ENCRYPT.001 | `env.kms_encrypted == false` |
| Untrusted layers | CTL.LAMBDA.LAYER.ORIGIN.001 | `layers.has_untrusted_origin` |
| Public URL no auth | CTL.LAMBDA.URL.AUTH.001 | `function_url.auth_type_none` |
| CORS wildcard + creds | CTL.LAMBDA.URL.CORS.001 | Wildcard origin + credentials |
| Public invoke policy | CTL.LAMBDA.INVOKE.PUBLIC.001 | `policy.public_invoke` |
| Broad UpdateCode | CTL.LAMBDA.UPDATECODE.SCOPE.001 | `update_code.broadly_granted` |
| Sensitive without VPC | CTL.LAMBDA.VPC.SENSITIVE.001 | `vpc.sensitive_without_vpc` |
| Public subnet in VPC | CTL.LAMBDA.VPC.SUBNET.001 | `vpc.has_public_subnet` |
| X-Ray tracing | CTL.LAMBDA.TRACE.001 | `tracing.mode_active == false` |
| CloudWatch logging | CTL.LAMBDA.LOG.001 | `logging.enabled == false` |
| Dead letter queue | CTL.LAMBDA.DLQ.001 | `async.dlq_configured == false` |
| Code signing | CTL.LAMBDA.CODESIGN.001, CTL.LAMBDA.CODESIGN.ENFORCE.001 | Missing or non-enforcing code signing |
| Deprecated runtime | CTL.LAMBDA.RUNTIME.001, CTL.LAMBDA.RUNTIME.EOL.001 | Deprecated or EOL runtimes |
| Reserved concurrency | CTL.LAMBDA.CONCURRENCY.001 | `concurrency.reserved_set == false` |
| Timeout threshold | CTL.LAMBDA.TIMEOUT.001 | `timeout.exceeds_threshold` |
| Broad list permissions | CTL.LAMBDA.LIST.RESTRICT.001 | `has_broad_lambda_list` |

### Chain Definitions

10 chains model compound Lambda attack paths:

| Chain | Attack path | Controls |
|-------|-------------|----------|
| `lambda_total_compromise` | Public URL + secrets + over-privileged role | ENV.SECRETS, ROLE.LEASTPRIV, URL.AUTH |
| `lambda_blind_execution` | Public URL + no logging → undetected abuse | LOG, URL.AUTH |
| `lambda_silent_exfiltration` | No logging + no encryption + over-privileged → silent data theft | ENV.ENCRYPT, LOG, ROLE.LEASTPRIV |
| `lambda_exfiltration_bridge` | Over-privileged + no logging + sensitive without VPC | LOG, ROLE.LEASTPRIV, VPC.SENSITIVE |
| `lambda_shadow_admin` | Wildcard PassRole + broad UpdateCode → shadow admin | PASSROLE, UPDATECODE.SCOPE |
| `lambda_resource_exhaustion` | No concurrency + timeout exceeded + public URL | CONCURRENCY, TIMEOUT, URL.AUTH |
| `lambda_unsigned_execution` | Unsigned images + no code signing + over-privileged | ECR.SIGNING, CODESIGN.ENFORCE, ROLE.LEASTPRIV |
| `supply_chain_code_injection` | No code approval + unsigned → code injection | CODECOMMIT.APPROVAL, ECR.SIGNING, CODESIGN.ENFORCE |
| `shadow_api_exposure` | API Gateway unauth + Lambda URL unauth | APIGATEWAY.AUTH, APIGATEWAY.STAGE.LIFECYCLE, URL.AUTH |
| `runtime_version_debt` | EOL Lambda + EOL EKS → compounding patch debt | EKS.VERSION, LAMBDA.RUNTIME |

### Configuration

```go
cfg := stave.Config{
    SnapshotsDir: "/path/to/lambda-observations",
    ChainsDir:    "/path/to/stave/chains",
    MaxUnsafe:    168 * time.Hour,
}
```

## IAM/Permissions Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 1 | Over-privileged role | CTL.LAMBDA.ROLE.LEASTPRIV.001 (`execution_role.is_overprivileged`), CTL.LAMBDA.PASSROLE.001 (wildcard PassRole on role) | **Full** |
| 2 | Wildcard Action | CTL.LAMBDA.ROLE.LEASTPRIV.001 (overprivileged detection includes Action:*), CTL.IAM.POLICY.ADMIN.001 (general admin detection) | **Full** |
| 3 | Broad Resource wildcards | CTL.LAMBDA.ROLE.LEASTPRIV.001 (overprivileged detection covers Resource:*) | **Full** |
| 4 | PassRole to Lambda | CTL.IAM.ESCALATE.PASSROLE.CREATEFUNCTION.001 (direct), CTL.IAM.POLICY.PASSROLE.001 (wildcard), CTL.IAM.POLICY.PASSROLE.CONDITION.001 (missing service condition). Verified Full in IAM escalation audit. | **Full** |

## Secrets/Environment Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 5 | Plaintext env secrets | CTL.LAMBDA.ENV.SECRETS.001 (`env.has_plaintext_secrets`). Also in `lambda_total_compromise` chain. | **Full** |
| 6 | Secrets in layers | CTL.LAMBDA.LAYER.ORIGIN.001 checks untrusted layer origins. Does not specifically scan layer content for secrets. | **Partial** |
| 7 | Missing KMS on env | CTL.LAMBDA.ENV.ENCRYPT.001 (`env.kms_encrypted == false`). Also in `lambda_silent_exfiltration` chain. | **Full** |

### Vector 6 detail: Partial coverage

LAYER.ORIGIN.001 detects layers from untrusted accounts (supply
chain risk). It does NOT scan layer content for embedded secrets.
Layer content scanning requires static analysis capabilities
beyond the observation-based detection model.

**Gap classification: Gap C.** Layer content analysis is not
representable as an observation property — it requires runtime
scanning (Lambda Layers are opaque archives). This is outside
Stave's observation-based detection model.

## Exposure Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 8 | Public URL no auth | CTL.LAMBDA.URL.AUTH.001 (`function_url.auth_type_none`), CTL.LAMBDA.URL.CORS.001 (CORS wildcard + credentials) | **Full** |
| 9 | Permissive resource policy | CTL.LAMBDA.INVOKE.PUBLIC.001 (`policy.public_invoke`) | **Full** |
| 10 | Public URL + over-privileged | `lambda_total_compromise` chain (URL.AUTH + ENV.SECRETS + ROLE.LEASTPRIV) | **Full** (chain-level) |

## Network Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 11 | VPC unrestricted egress | CTL.VPC.SG.EGRESS.001 (`egress.unrestricted_all_ports`). Operates on SG assets. `ecs_ssrf_credential_theft` chain composes with task role controls. | **Full** |
| 12 | Lambda not in VPC | CTL.LAMBDA.VPC.SENSITIVE.001 (`vpc.sensitive_without_vpc`). Only fires for functions accessing sensitive data. Non-sensitive functions outside VPC are not flagged (context-appropriate — VPC is not universally required). | **Full** |
| 13 | Missing VPC endpoints | No control checks for VPC endpoint configuration on Lambda functions. | **None** |

### Vector 13 detail: Not covered

No control verifies that VPC-attached Lambda functions route AWS
service calls through VPC endpoints instead of NAT gateways or
internet gateways. This is a network-efficiency and data-path
control, not a direct security exposure.

**Gap classification: Gap B.** Requires observation property
`compute.vpc.has_service_endpoints`. Lower priority — NAT gateway
routing is functional (just less efficient and potentially subject
to NAT gateway logging gaps).

## Encryption/Logging Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 14 | Missing KMS env encryption | CTL.LAMBDA.ENV.ENCRYPT.001 (same as vector 7) | **Full** |
| 15 | Missing X-Ray tracing | CTL.LAMBDA.TRACE.001 (`tracing.mode_active == false`) | **Full** |
| 16 | Missing structured logging | CTL.LAMBDA.LOG.001 (`logging.enabled == false`). In 3 chain definitions. | **Full** |
| 17 | Missing DLQ | CTL.LAMBDA.DLQ.001 (`async.dlq_configured == false`) | **Full** |
| 18 | Missing error alarms | No dedicated control for Lambda-specific CloudWatch alarms (error rate, throttles, permission denied). General monitoring controls exist (CTL.CLOUDWATCH.MONITOR.*) but none targets Lambda-specific metrics. | **None** |

### Vector 18 detail: Not covered

No control verifies that CloudWatch alarms are configured for
Lambda-specific metrics (Errors, Throttles, Duration anomalies).
The general CLOUDWATCH.MONITOR controls cover IAM events and
infrastructure changes, not per-function operational metrics.

**Gap classification: Gap B.** Requires observation property
`monitoring.metric_filters.lambda_errors.exists` following the
established CLOUDWATCH.MONITOR pattern.

## Operational Coverage Matrix

| # | Vector | Control(s) | Coverage |
|---|--------|------------|----------|
| 19 | Outdated runtime | CTL.LAMBDA.RUNTIME.001 (deprecated), CTL.LAMBDA.RUNTIME.EOL.001 (end-of-life). In `runtime_version_debt` chain. | **Full** |
| 20 | Missing concurrency | CTL.LAMBDA.CONCURRENCY.001 (`concurrency.reserved_set == false`). In `lambda_resource_exhaustion` chain. | **Full** |

## Gaps

| Gap | Vector | Type | Priority | Description |
|-----|--------|------|----------|-------------|
| 6 | Secrets in layers | C | Low | Layer content scanning outside observation model |
| 13 | VPC endpoints | B | Low | Network efficiency, not direct security exposure |
| 18 | Lambda error alarms | B | Medium | Missing metric filter for Lambda-specific errors |

## Chain Coverage

10 chain definitions model Lambda attack paths. Notable
compositions:

- **`lambda_total_compromise`** covers BMW's compound vector 10
  (public URL + secrets + over-privileged role = complete function
  compromise)
- **`lambda_shadow_admin`** covers PassRole abuse through Lambda
  (wildcard PassRole + UpdateCode = shadow admin via Lambda
  function)
- **`lambda_silent_exfiltration`** covers the data-theft-without-
  evidence path (no encryption + no logging + over-privileged role)

## Observation Schema Assessment

**Asset type:** `aws_lambda_function` — well-exercised across 30+
forge fixtures.

**Properties defined under `compute.*`:**
- `execution_role.*` (is_overprivileged, is_shared, has_wildcard_passrole)
- `env.*` (has_plaintext_secrets, kms_encrypted)
- `function_url.*` (auth_type_none, cors.*)
- `policy.*` (public_invoke)
- `vpc.*` (sensitive_without_vpc, has_public_subnet)
- `logging.*` (enabled)
- `tracing.*` (mode_active)
- `async.*` (dlq_configured)
- `code_signing.*` (config_arn_set, enforce_enabled)
- `runtime.*` (is_deprecated, eol)
- `concurrency.*` (reserved_set)
- `timeout.*` (exceeds_threshold)
- `update_code.*` (broadly_granted)
- `layers.*` (has_untrusted_origin)
- `image.*` (uses_latest_tag)

The Lambda observation schema is mature — 22 dedicated controls
exercise 20+ property paths.

## Recommendations

**Ship immediately (0 implementation):** BMW enables 30 Lambda +
IAM controls and 10 chain definitions. This covers 18 of 20
vectors fully. Each finding includes DEFECT, INFECTION, FAILURE,
OBSERVED, and DELTA sections.

**Close within one iteration (1 Gap B control):**
- Vector 18: Lambda error alarm control following the
  CLOUDWATCH.MONITOR pattern. Same pattern as Gap C closure in
  IAM escalation audit.

**Defer (Low priority):**
- Vector 6: Layer content scanning. Outside observation model
  (Gap C). Recommend AWS Lambda Layers scanning via GuardDuty
  or third-party tool.
- Vector 13: VPC endpoints. Network efficiency, not direct
  exposure.
