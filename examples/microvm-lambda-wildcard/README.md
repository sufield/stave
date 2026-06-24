# MICROVM-023 — lambda:* Silent Blast-Radius Expansion

Reasoning spec for `CTL.LAMBDA.MICROVM.WILDCARD.001` (HIGH) and
`.WILDCARD.ELEVATED.001` (CRITICAL). AWS folded the MicroVM actions into the
`lambda:` namespace, so a role with `lambda:*` — typically granted for ordinary
Lambda management before MicroVMs existed — now also holds RunMicrovm, the
auth/shell token actions, and lifecycle control. `role_permission` carries
EFFECTIVE permissions, so a wildcard from an attached managed policy (e.g.
`AWSLambda_FullAccess`) is present even when the inline policy looks scoped.

`PATH "$HOME/.local/bin:$PATH" bash run.sh`:
```
vuln_cicd   souffle=CRITICAL  z3=sat    CI/CD role, lambda:* (inline)               (FAIL)
fp          souffle=NONE      z3=unsat  microvm-admin role, lambda:*                (PASS)
fn_managed  souffle=HIGH      z3=sat    human role, lambda:* via AWSLambda_FullAccess (FAIL)
fn_agent    souffle=CRITICAL  z3=sat    agent: inline scoped + managed lambda:*     (FAIL)
```
Both managed-policy false-negative traps fire; severity splits agent/cicd
(CRITICAL) vs other (HIGH), matching the two disjoint catalog controls.
