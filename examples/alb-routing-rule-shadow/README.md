# ALB-ROUTING-002 — rule-shadowing reasoning spec

ALB listener rules evaluate in ascending priority order. A non-auth rule at a
lower priority number (higher precedence) whose path condition subsumes an auth
rule's path makes the auth action unreachable — an authentication bypass that is
purely an ordering bug. A rule with **no path condition** matches everything;
the collector normalizes its prefix to `""` (empty), which is a prefix of every
path (the FN trap).

## Engines

- `rule_shadow.dl` — Soufflé. `subsumes(broad, narrow)` via prefix containment
  (`substr` clamps, so a longer broad prefix never spuriously matches), then
  `auth_shadowed(listener, auth_rule, shadowing_rule)`. Non-empty = FAIL.
- `query.smt2` — Z3. Quantifier-free, uses `str.prefixof`. `sat` = FAIL.

A collector populates `network.elb.auth_rule_shadowed` (read by
`CTL.ELB.ROUTING.RULESHADOW.001`) from this logic.

## Run

```bash
./run.sh        # souffle vs z3 per scenario; they must agree
```

Expected (`expected/output.txt`):

```
vuln   souffle=SHADOWED   z3=sat
fp     souffle=CLEAR      z3=unsat
fn     souffle=SHADOWED   z3=sat
```

- **vuln** — priority 10 `/*` (no auth) precedes priority 20 `/admin*` (auth).
  All `/admin` traffic matches priority 10 first; auth never fires.
- **fp** — priority 10 `/api/*` (no auth) precedes priority 20 `/admin/*`
  (auth). Disjoint prefixes — auth rule is reachable.
- **fn** — priority 5 host-wildcard with **no path condition** (no auth)
  precedes priority 15 `/admin*` (auth). No-path normalizes to `/*` and shadows.

Inspired by Doyensec CloudsecTidbits No. 5 — *Navigating Lax Load Balancers*.
Validated against doyensec/ELBaph.
