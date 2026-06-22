# Control Reference — APIGW2

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APIGW2.AUTH.001

**HTTP APIs Must Have Authorizers Configured**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3; soc2: CC6.1;

API Gateway v2 HTTP APIs must have an authorizer (JWT, Cognito, or Lambda) configured to authenticate requests. Without an authorizer, any client can invoke API routes without authentication.

**Remediation:** Configure a JWT, Cognito, or Lambda authorizer on the API routes.

---

### CTL.APIGW2.LOG.001

**HTTP API Stages Must Have Access Logging Enabled**

- **Severity:** medium
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AU-2; soc2: CC7.1;

API Gateway v2 HTTP API stages must configure access logging to capture request details. Without logging, API calls lack traceability for detecting abuse and supporting incident response.

**Remediation:** Configure access logging with a CloudWatch Logs destination.

---

