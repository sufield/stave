# MICROVM Shell-Auth Restriction

Reasoning spec for `CTL.LAMBDA.MICROVM.SHELLAUTH.001` (HIGH) and
`CTL.LAMBDA.MICROVM.SHELLAUTH.ELEVATED.001` (CRITICAL).

`lambda:CreateMicrovmShellAuthToken` returns a bearer token granting an
interactive shell inside a running MicroVM. Only break-glass roles may hold it.
The catalog controls read a resolved `role.microvm_shell_auth` boolean; **this
spec is where that resolution comes from** — including that `lambda:*`
**includes** the shell action — and it is proved two independent ways, Soufflé
(Datalog) and Z3 (SMT), which must agree.

## The model

`role_permission` carries each role's *effective* permissions (inline + attached
managed policies + boundaries, resolved by the collector). `has_shell_access`
derives from the specific action **or** the `lambda:*` wildcard.
Severity splits on the workload class (the two catalog controls are disjoint):

- `agent_role` / `cicd_role` + shell + not break-glass → **CRITICAL**
- any other role + shell + not break-glass → **HIGH**
- break-glass → no finding

## Run it

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```

```
vuln      souffle=HIGH      z3=sat      developer role, lambda:*           (FAIL)
fp        souffle=NONE      z3=unsat    break-glass role with the shell action       (PASS)
fn_cicd   souffle=CRITICAL  z3=sat      CI/CD role, wildcard via managed policy      (FAIL)
fn_agent  souffle=CRITICAL  z3=sat      bedrock agent role, explicit shell action    (FAIL)
```

`expected/output.txt` is byte-identical. Soufflé reports the severity tier; Z3
independently confirms an unauthorized (non-break-glass) shell grant exists
(`sat`) or not (`unsat`). They agree on every scenario — existence and tier —
including the two **managed-policy false-negative traps** (the wildcard grant
arrives through an attached managed policy, not an inline statement) and the
CRITICAL escalation for non-human automation identities.
