# MICROVM Auth-Token Expiration (≤ 30 min)

Reasoning spec for `CTL.LAMBDA.MICROVM.AUTHTOKEN.EXPIRY.001`. A role that can
call `CreateMicrovmAuthToken` must constrain token expiration to 30 minutes or
less. The catalog control reads collector-resolved `role.microvm_authtoken_*`
signals; this spec derives the verdict from the underlying permission +
condition facts and proves it two ways (Soufflé + Z3, which must agree).

`can_create_auth_token` derives from the specific action **or** the
`lambda:*` wildcard (which includes it). A finding is: no expiration
constraint (`unconstrained`) **or** a constraint above 30 min (`excessive`) —
"has a condition" is not the same as "has an adequate condition."

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```
```
vuln      souffle=unconstrained z3=sat      create, no expiration condition   (FAIL)
fp        souffle=NONE          z3=unsat    condition <= 30 min               (PASS)
fn        souffle=excessive     z3=sat      condition = 480 min               (FAIL)
wildcard  souffle=unconstrained z3=sat      lambda:* , no condition  (FAIL)
```
`expected/output.txt` is byte-identical. The `wildcard` row also trips
MICROVM-018 (shell) and MICROVM-020 (ports) — one `lambda:*` grant
fails all three.

Note: the exact AWS IAM condition key for token expiration may not be published
yet. The collector matches whatever key AWS uses; if it cannot resolve a
constraint it emits `expiry_constrained=false` (fail-loud → FAIL).
