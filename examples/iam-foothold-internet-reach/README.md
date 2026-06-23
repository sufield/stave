# IAM-FOOTHOLD-001 — Internet-Facing Compute Reaching Sensitive Resources

Graph-reachability reasoning spec for `CTL.IAM.FOOTHOLD.INTERNET.SENSITIVE.001`.

The per-resource catalog control reads a derived `identity.reaches_sensitive`
boolean. **This spec is where that boolean comes from** — and it proves the
verdict two independent ways, Soufflé (Datalog) and Z3 (SMT), which must agree.
Per-resource CEL alone can flag *direct* access, but it is blind to the
transitive path (role → AssumeRole → intermediate role → secret); reachability
is what graph engines see.

## The graph

Six input relations, modeled from the captured IAM/resource configuration:

| Relation | Meaning |
|---|---|
| `internet_facing_role(role)` | role attached to internet-facing compute (EC2 public IP, ECS behind a public LB, Lambda URL / API GW) |
| `sensitive_resource(res, type)` | Secrets Manager secret, customer KMS key, RDS instance/cluster, or sensitive-tagged S3 |
| `can_assume(a, b)` | `a` has `sts:AssumeRole` on `b` |
| `can_pass(a, b)` | `a` has `iam:PassRole` for `b` |
| `has_access(role, res, action)` | role policy grants `action` on `res` |
| `resource_policy_grants(res, principal)` | resource-based policy grants a role |

`reachable.dl` computes transitive `controls_role` (assume/pass chains) and
`can_reach` (direct, resource-policy, or via a controlled role), then
`reachable(internet_role, sensitive_res)`. `query.smt2` asks Z3 the same question
over closed-world `define-fun` facts (it cannot invent an edge), bounded to one
control hop — which covers the direct and two-hop cases.

## Run it

```bash
PATH="$HOME/.local/bin:$PATH" bash run.sh
```

`run.sh` builds three trap-triplet scenarios, runs both engines on each, and
prints whether a path exists:

```
vuln   souffle=PATH  z3=sat      EC2 public IP -> role with direct secretsmanager access     (FAIL)
fp     souffle=NONE  z3=unsat    EC2 private IP only -> same secrets access (not internet)    (PASS)
fn     souffle=PATH  z3=sat      EC2 public IP -> assume -> intermediate role -> secret (2-hop) (FAIL)
```

The committed `expected/output.txt` is byte-identical. `PATH`/`sat` = a path
exists (FAIL); `NONE`/`unsat` = no internet-facing role reaches a sensitive
resource (PASS). The two engines agree on every scenario — including the
**two-hop false-negative trap**, which a direct-permission check misses but
reachability proves.
