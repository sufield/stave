# z3-rhino-pattern5-trust-modification

Rhino Pattern 5 — Role Trust Modification. Same template as
Pattern 1; different action disjunction. The principal
modifies a role's trust policy to admit self-assumption — or
creates a new role whose trust the principal controls.

Rhino's named method 14: `iam:UpdateAssumeRolePolicy` on an
admin role. The iter-15 prover added the create-and-assume
pair (`iam:CreateRole + iam:AttachRolePolicy` on a fresh
role) and the strip-and-assume flow (`iam:DeleteRolePolicy`
to widen, then `sts:AssumeRole`).

This pattern overlaps with Pattern 2 on
`iam:UpdateAssumeRolePolicy` — Rhino lists method 14 in both.
The disjunction doesn't dedupe Rhino's numbering; it captures
the structural shape: trust-mutation gives the principal a
way to assume what it couldn't before.

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `rhino-vulnerable` | **sat** | `(timeout)` | `rhino-attacker` user with `iam:UpdateAssumeRolePolicy` on `*` |
| `remediated`       | **unsat** | unsat | n/a |

## Run

```bash
cd stave
make build
bash examples/z3-rhino-pattern5-trust-modification/run.sh
```

## See also

- `z3-rhino-pattern1-self-mutation/` — same template
- iter-15 prover at
  `examples/iam-21-privesc-5-patterns/z3prove/patterns.go`
  — pattern5Methods registry
