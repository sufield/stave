# MICROVM Auth-Token Port Scoping

Reasoning spec for `CTL.LAMBDA.MICROVM.AUTHTOKEN.PORTSCOPE.001`. A token-creating
role must scope `allowedPorts`, and the allowed set must never include the
MicroVM lifecycle hook port (the internal `/suspend`, `/terminate` API). The
catalog control reads collector-resolved `role.microvm_authtoken_*` signals;
this spec derives the verdict and proves it two ways (Soufflé + Z3).

`can_create_auth_token` derives from the action or the `lambda:*`
wildcard. A finding is: no port constraint (`unscoped`) **or** the allowed set
intersects the configured lifecycle port (`lifecycle`). Soufflé derives the
lifecycle exposure from `allowed_port ∩ lifecycle_port`; Z3 takes the resolved
`allows_lifecycle` boolean — they agree.

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```
```
vuln      souffle=unscoped   z3=sat      no port condition                  (FAIL)
fp        souffle=NONE       z3=unsat    allowed={8080}, lifecycle=9090     (PASS)
fn        souffle=lifecycle  z3=sat      allowed={8080,9090}, lifecycle=9090 (FAIL)
wildcard  souffle=unscoped   z3=sat      lambda:* , no condition   (FAIL)
```
`expected/output.txt` is byte-identical. Safe default: if no port constraint is
resolvable (incl. when AWS has not published an allowed-ports condition key), the
collector emits `port_scoped=false` → FAIL. The `wildcard` row also trips
MICROVM-018 and MICROVM-019.
