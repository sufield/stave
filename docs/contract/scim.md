# SCIM Infrastructure Signals

Derived observation properties for the two SCIM infrastructure controls. A
collector populates these; Stave core only reads them. Infrastructure controls
inspired by Doyensec *SCIM Hunting — Beyond SSO*.

## What is already covered (do NOT duplicate)

The base SCIM misconfigurations already fire on existing controls — no
SCIM-named variants are built for them:

| SCIM concern | Already caught by |
|---|---|
| SCIM endpoint accessible without gateway auth | `CTL.APIGATEWAY.AUTH.001` (any unauthenticated route); `CTL.APIGATEWAY.AUTH.IAM.UNRESTRICTED.001` (IAM auth bypassed by `Principal:"*"` resource policy); `CTL.ELB.AUTH.UNAUTHENTICATED.ALLOW.001` (ALB) |
| SCIM bearer token in a Lambda env var | `CTL.LAMBDA.ENV.SECRETS.001` |
| SCIM token not in Secrets Manager / SSM SecureString | `CTL.LAMBDA.SECRETS.NOTMANAGED.001`, `CTL.LAMBDA.SECRETS.SSM.INSECURE.001` |
| SCIM token has no / stale rotation | `CTL.SECRETS.ROTATION.NEVER.001`, `…STALE.001`, `CTL.SECRETSMANAGER.ACCESS.001` |
| SCIM handler role overprivileged (generic) | `CTL.LAMBDA.ROLE.LEASTPRIV.001`, `CTL.IAM.POLICY.SERVICEWILDCARD.001` |

## `identity.escalation.cognito_updateattr_unscoped` — `CTL.IAM.ESCALATE.COGNITO.UPDATEATTR.001`

The one atomic gap the generic least-privilege checks miss.

| Field | Type | Meaning |
|-------|------|---------|
| `identity.escalation.cognito_updateattr_unscoped.present` | bool | The principal can call `cognito-idp:AdminUpdateUserAttributes` (directly, via `cognito-idp:Admin*`/`cognito-idp:*`, or an attached managed policy such as `AmazonCognitoPowerUser`) **without** an attribute-scoping Condition (`cognito-idp:AllowedAttributesForUpdate` / `AllowedAttributes`). Unconstrained, it can set any attribute including `custom:role`/`custom:isAdmin` — privilege escalation. Resolved across inline + attached managed policies. |

`AdminUpdateUserAttributes` *with* an attribute-scoping condition is legitimate
provisioning and does not fire.

## `compute.scim.*` — `CTL.LAMBDA.SCIM.TAKEOVER.001` (SCIM-004, compound)

On the SCIM handler asset (`aws_lambda_function`). Computed by
`examples/scim-provisioning-takeover/` (Soufflé + Z3, which agree), composing the
existing detections.

| Field | Type | Meaning |
|-------|------|---------|
| `compute.scim.takeover_chain_present` | bool | **Derived (graph)**. All three hold: the SCIM endpoint the handler serves is publicly reachable with no effective gateway auth (authorizationType `NONE`, **or** `AWS_IAM` with a `Principal:"*"` resource policy — the FN trap), the handler role is overprivileged, and the SCIM token is reachable (env var, or a secret with broad access / no rotation). |
| `compute.scim.takeover_endpoint` | string | The public SCIM route (evidence). |
| `compute.scim.takeover_token` | string | Where the reachable token lives (evidence). |
| `compute.scim.takeover_path` | string | Hop-by-hop chain (evidence). |

Inputs the collector folds in (no SCIM-named duplicate controls):
`scim_endpoint_public` (reuses `AUTH.001` + `AUTH.IAM.UNRESTRICTED.001` logic),
`scim_handler_overprivileged` (reuses `ROLE.LEASTPRIV.001`), `scim_token_reachable`
(reuses `ENV.SECRETS.001` / `ROTATION.*`).

## Out of scope (application code, not config posture)

Stave covers the **infrastructure misconfiguration surface**. These SCIM classes
are handler **code** behavior and require application-level security testing:
re-provisioning fallback logic; email/phone verification bypass via SCIM;
account-takeover via SCIM email change; internal attribute manipulation; parser
differentials / JSON interop; bulk-ops race conditions; SCIM `path=nil` syntax
bypass; sub-splitting (`split("_")`).
