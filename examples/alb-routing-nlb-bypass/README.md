# ALB-ROUTING-008 — NLB-bypass reasoning spec

An NLB operates at Layer 4 — no listener rules, auth actions, or path
conditions. If it forwards to an EC2 instance that also sits behind an ALB
carrying security controls, every ALB-layer control is bypassable at the
network level through the NLB. Reachability is at the **instance** level; the
collector resolves NLB IP-type targets to instance IDs first, so an
IP-targeted NLB pointing at the same private IP as an ALB-registered instance
is caught (the FN trap).

## Engines

- `nlb_bypass.dl` — Soufflé. `nlb_bypasses_alb(nlb, alb, instance)` — an
  instance reached by both an NLB and a gated ALB. Non-empty = FAIL.
- `query.smt2` — Z3. Quantifier-free: one instance reached by both. `sat` = FAIL.

A collector populates `network.elb.nlb_shares_gated_alb_instances` (read by
`CTL.ELB.ROUTING.NLBBYPASS.001`) from this logic.

## Run

```bash
./run.sh        # souffle vs z3 per scenario; they must agree
```

Expected (`expected/output.txt`):

```
vuln   souffle=BYPASS   z3=sat
fp     souffle=CLEAN    z3=unsat
fn     souffle=BYPASS   z3=sat
```

- **vuln** — `alb-1` (gated) and `nlb-1` both target `i-abc`/`i-def`. The NLB
  gives direct L4 access to the same instances, bypassing all ALB auth.
- **fp** — `nlb-1` targets `i-ghi`/`i-jkl`; no overlap with the ALB's instances.
- **fn** — `alb-1` targets `i-abc` via a target group; `nlb-1` targets it by IP,
  resolved to `i-abc`. Same instance — must be caught despite the IP target.

Inspired by Doyensec CloudsecTidbits No. 5 — *Navigating Lax Load Balancers*.
Validated against doyensec/ELBaph.
