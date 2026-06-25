# ALB-ROUTING-006 — path-equivalence reasoning spec

The master compound check behind ALB routing: a backend EC2 instance can be
reached through multiple ALB/listener/rule paths. If one path carries a security
control (authenticate-oidc/cognito, a source-ip gate, or a fronting WAF) and
another path to the **same instance** does not, the control is bypassable. This
subsumes ALB-ROUTING-003 (source-ip gate bypass) and the auth/WAF dimensions.

Reachability resolves to the **instance**, not the target-group ARN — two
different target groups that share an instance are the same backend (the
instance-level FN trap). A listener's **default rule** is just another
`path_to_tg` tuple, so within-listener default-rule bypass is caught too.

## Engines

- `path_equivalence.dl` — Soufflé. Derives `path_to_instance`, then
  `inconsistent(instance, controlled_rule, bypass_rule)` for auth, source-ip,
  and WAF dimensions. Non-empty `inconsistent.csv` = FAIL.
- `query.smt2` — Z3. Quantifier-free: two explicit paths resolving to the same
  instance, asserted to differ on at least one control. `sat` = FAIL.

A collector populates the derived signal `network.elb.tg_path_controls_inconsistent`
(read by `CTL.ELB.ALB.ROUTING.PATHEQUIV.001`) from this logic; the spec proves
the two engines agree.

## Run

```bash
./run.sh        # prints souffle vs z3 verdict per scenario; they must agree
```

Expected (`expected/output.txt`):

```
vuln   souffle=INCONSISTENT  z3=sat
fp     souffle=CONSISTENT    z3=unsat
fn     souffle=INCONSISTENT  z3=sat
```

- **vuln** — `tg-shared` reachable via `alb-1` (auth + source-ip + WAF) and
  `alb-2` (none). Every control on `alb-1` is bypassed through `alb-2`.
- **fp** — `tg-shared` reachable via `alb-1` and `alb-2`, both auth + source-ip
  + WAF. Consistent — no finding.
- **fn** — `i-abc` is registered in `tg-app` (auth rule) **and** `tg-catchall`
  (default rule, no auth) on the same listener. Different target groups, same
  instance — instance-level overlap must be detected, not just ARN match.

Inspired by Doyensec CloudsecTidbits No. 5 — *Navigating Lax Load Balancers*.
Validated against doyensec/ELBaph.
