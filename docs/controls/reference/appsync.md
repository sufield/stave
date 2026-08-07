# Control Reference — APPSYNC

> Auto-generated from the built-in control catalog.
> Do not edit manually. Run: `go run ./internal/tools/gencontroldocs`
>
> Back to the [control reference index](../reference.md).

### CTL.APPSYNC.AUTH.REQUIRED.001

**AppSync API Must Require Authentication**

- **Severity:** high
- **Type:** unsafe_state
- **Domain:** exposure
- **Compliance:** nist_800_53_r5: AC-3, IA-2; pci_dss_v4.0: 7.2, 8.3; soc2: CC6.1;

AppSync GraphQL API does not require authentication. AppSync APIs can be configured with API_KEY auth (effectively public with a rotatable token) or no auth at all. Without IAM, Cognito, or OIDC authentication, any client with the API endpoint can execute queries and mutations. GraphQL APIs typically expose read and write operations on backend data sources (DynamoDB, RDS, Lambda) — unauthenticated access means anonymous internet users can query or mutate application data.

**Remediation:** Configure the AppSync API to require IAM, Cognito User Pool, or OIDC authentication. Remove API_KEY as the sole authentication type unless the API is intentionally public and documented as such. Use multiple auth modes with IAM as the default and API_KEY only for specific public operations.

---

### CTL.APPSYNC.LOG.REQUEST.001

**AppSync Request-Level Logging Must Be Enabled**

- **Severity:** low
- **Type:** unsafe_state
- **Domain:** detection
- **Compliance:** nist_800_53_r5: AU-2, AU-3; pci_dss_v4.0: 10.2; soc2: CC7.2;

AWS AppSync GraphQL API does not have request-level logging enabled. Without request logging, individual GraphQL queries and mutations are not recorded in CloudWatch Logs, limiting forensic capability after unauthorized data access.

**Remediation:** Enable request-level logging for the AppSync API to record GraphQL operations in CloudWatch Logs.

---

