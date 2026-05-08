# z3-rhino-pattern2-credential-creation

Rhino Pattern 2 — Credential Creation / Theft. Same template
as Pattern 1; different action disjunction. The principal
creates or hijacks credentials for a more privileged
principal **without modifying any policy** — Rhino's named
methods 4, 5, 6, 14 (CreateAccessKey, CreateLoginProfile,
UpdateLoginProfile, UpdateAssumeRolePolicy), plus the
MFA-virtual-device and federated-token methods the example
prover added.

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `rhino-vulnerable` | **sat** | `(timeout)` | `rhino-attacker` user with `iam:EnableMFADevice` on `*` |
| `remediated` | **unsat** | unsat | n/a |

cvc5 times out on rhino-vulnerable (~115 assertions, large
disjunction in the `has_action` closed-world axiom). Z3 alone
validates; cvc5 cross-checks on the smaller remediated
fixture.

## Run

```bash
cd stave
make build
bash examples/z3-rhino-pattern2-credential-creation/run.sh
```

Expected output is in `expected/output.txt`.

## See also

- `z3-rhino-pattern1-self-mutation/` — same template, policy-
 mutation actions. The shared README pattern carries.
- this example prover at
 `examples/iam-21-privesc-5-patterns/z3prove/patterns.go`
 enumerates the canonical method registry this disjunction
 mirrors.
