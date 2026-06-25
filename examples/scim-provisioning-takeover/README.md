# SCIM-004 — provisioning-takeover reasoning spec

Three conditions that no individual control sees together: the SCIM endpoint the
handler serves is publicly reachable with no effective gateway auth, the handler
role is overprivileged, and the SCIM token is reachable. An attacker who obtains
the token hits the public endpoint and operates with the overprivileged handler's
permissions — creating admin users, setting passwords, modifying attributes.

This composes existing detections rather than re-deriving them:
- `scim_endpoint_public` ← `CTL.APIGATEWAY.AUTH.001` (authType NONE) **and**
  `CTL.APIGATEWAY.AUTH.IAM.UNRESTRICTED.001` (IAM auth + `Principal:"*"` resource
  policy = effectively no auth — the FN trap)
- `scim_handler_overprivileged` ← `CTL.LAMBDA.ROLE.LEASTPRIV.001`
- `scim_token_reachable` ← `CTL.LAMBDA.ENV.SECRETS.001` / `CTL.SECRETS.ROTATION.*`

## Engines
- `takeover.dl` — Soufflé. `scim_provisioning_takeover(api, lambda, token, path)`. Non-empty = FAIL.
- `query.smt2` — Z3, quantifier-free. `sat` = FAIL.

Collector signal: `compute.scim.takeover_chain_present` (read by `CTL.LAMBDA.SCIM.TAKEOVER.001`).

## Run
```bash
./run.sh
```
Expected (`expected/output.txt`):
```
vuln   souffle=TAKEOVER  z3=sat
fp     souffle=NONE      z3=unsat
fn     souffle=TAKEOVER  z3=sat
```

- **vuln** — public endpoint (authType NONE) + overprivileged handler + token in env var.
- **fp** — authed endpoint + scoped handler + secured token: chain broken.
- **fn** — `AWS_IAM` auth **but** a `Principal:"*"` resource policy makes the
  endpoint effectively public; handler overprivileged; secret with no resource
  policy. Must evaluate the resource policy, not just `authorizationType`.

Infrastructure control inspired by Doyensec *SCIM Hunting — Beyond SSO*.
