# z3-rhino-pattern3-passrole-compute

Rhino Pattern 3 — Compute + PassRole. The only Rhino pattern
that's a **compound** rather than a single-asset disjunction:
the exploit needs three facts on different assets to compose.

## The compound

```
Fact 1: attacker has iam:PassRole
Fact 2: attacker has at least one compute-launch action
 (ec2:RunInstances, lambda:CreateFunction, etc.)
Fact 3: a target role exists that trusts a compute service
 (the role the attacker would pass to the launched compute)

Conjunction → attacker can launch compute that runs with
 the privileged target role's credentials.
```

This is structurally identical to the Bybit pattern
in shape — multi-asset existential — and to
`z3-compound-overperm-assumable` (which checks step 3 alone).
Pattern 3 adds the attacker-side conjuncts (PassRole + launch
action) that turn "role is overpermissioned and trusted by
compute" into "an attacker who holds these actions can
exploit it."

## Verdicts

| Fixture | Z3 | cvc5 | Witness |
|---|---|---|---|
| `rhino-vulnerable` | **sat** | `(timeout)` | see below |
| `remediated` | **unsat** | unsat | n/a |

Z3 witness on rhino-vulnerable:

```
attacker = arn:aws:iam::111122223333:user/rhino-attacker
launch_action = autoscaling:CreateAutoScalingGroup
target_role = arn:aws:iam::111122223333:role/admin-multi-trust-role
service = batch.amazonaws.com
```

The over-approximation: Z3 doesn't bind the launch action to
its expected service principal — autoscaling launches
naturally pair with `ec2.amazonaws.com`, not
`batch.amazonaws.com`. Z3's witness is a satisfying
assignment of the disjunction, not the most-natural pairing.
For chain reachability that's fine — SAT is the correct
verdict because the launch action exists, the target role
exists, and the trust exists. Tightening the action↔service
binding would need a ternary
`launch_pair_valid(launch_action, service)` predicate; the
existing this example Z3 prover (via the go-z3 binding) does this
binding directly. The SMT-LIB version trades precision for
solver-portability — the same verdict any SMT solver agrees
on.

## Run

```bash
cd stave
make build
bash examples/z3-rhino-pattern3-passrole-compute/run.sh
```

## See also

- `z3-rhino-pattern1-self-mutation/` — single-asset
 disjunction template
- `z3-compound-overperm-assumable/` — the simpler "role
 trusts compute service" half of this pattern, without the
 attacker-side conjuncts
- this example prover at
 `examples/iam-21-privesc-5-patterns/z3prove/patterns.go`
 — pattern3Methods registry with action↔service binding
