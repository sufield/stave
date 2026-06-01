# game-theory-cost

Cost-to-compromise + remediation ROI ranking. Every other
engine in `examples/` says **what** is wrong; this engine
says **how much it costs the attacker** to exploit and
**how much each remediation increases that cost**.

The output turns security findings into a financial
decision: spend $50 to add $3000 to the attacker's bill, or
spend $1000 elsewhere for an $800 increase. CISOs get ROI
per remediation, not a flat list of vulnerabilities.

## What this answers vs the other engines

| Engine | Output |
|---|---|
| Z3 | "A path exists" (binary) |
| Soufflé | "6 reachable paths" (count) |
| Risk model | "P(exploitation) = 41%" (likelihood) |
| TLA+ temporal | "1 hop from unsafe" (drift distance) |
| **game theory** | "Attacker $300 → Defender $50 → ROI: blocks path" |

The attacker is modelled as a rational economic actor: cheapest
path wins. The defender's job is to maximise the attacker's
*minimum* cost (maximin). The remediation ranking is the
ordered list of one-step moves the defender can take, sorted
by ROI = `(attacker_cost_increase / defender_cost)`.

## The model

### Attacker steps

Each step in an attack path has a fixed RELATIVE cost. The
calibration constants ship at the top of `cost_model.py`:

| Step | Cost | Why |
|---|---:|---|
| `discover_endpoint` | $100 | Shodan / Google dorking is cheap |
| `unauthenticated_access` | $50 | Just call the API, trivial |
| `self_registration` | $200 | Email confirm, minor friction |
| `role_assumption` | $500 | Need to know role name + invoke STS |
| `additional_hop` | $800 | Each transitive hop adds discovery + execution |
| `compute_trust_passrole` | $200 | PassRole-then-launch primitive |
| `broad_action_exploitation` | $100 | `s3:*` — no precision needed |
| `scoped_action_exploitation` | $300 | Specific verb — must know what to call |
| `wildcard_resource` | $50 | `*` — hit anything |
| `scoped_resource` | $400 | Specific ARN — must discover it |
| `evade_no_logging` | $0 | Free — no logs to dodge |
| `evade_with_logging` | $2,000 | CloudTrail data events — real cost |
| `evade_no_scp` | $0 | No guardrail to bypass |
| `evade_with_scp` | $3,000 | Must work within SCP constraints |

### Defender remediations

Each remediation has a defender cost and an effect on the
attacker's path (block, replace a step with a costlier
alternative, or increase a step's price):

| Remediation | Defender $ | Effect |
|---|---:|---|
| `disable_unauth` | $50 | blocks `unauthenticated_access` |
| `close_self_registration` | $50 | blocks `self_registration` |
| `enable_mfa` | $200 | adds $5,000 to `self_registration` |
| `scope_actions` | $500 | swaps `broad_action_exploitation` → `scoped_action_exploitation` |
| `scope_resources` | $500 | swaps `wildcard_resource` → `scoped_resource` |
| `enable_data_events` | $1,000 | swaps `evade_no_logging` → `evade_with_logging` |
| `apply_scp` | $800 | swaps `evade_no_scp` → `evade_with_scp` |
| `remove_compute_trust` | $300 | blocks `compute_trust_passrole` |
| `add_permissions_boundary` | $400 | adds $2,000 to `role_assumption` |
| `restrict_ip_range` | $200 | adds $3,000 to `discover_endpoint` |

### Output (live, recorded in `expected/output.txt`)

| Fixture | Cheapest path | Cost | Top remediation | Verdict |
|---|---|---:|---|---|
| Cognito writeup | Unauthenticated → S3 | $300 | disable_unauth (blocks) | CRITICAL |
| Cognito remediated | (no viable path) | — | — | MINIMAL |
| Multi-hop vulnerable | 3-hop assume chain | $2,300 | restrict_ip_range | MEDIUM |
| Multi-hop remediated | 2-edge chain | $1,500 | restrict_ip_range | HIGH |
| Rhino vulnerable | Compute PassRole | $1,800 | remove_compute_trust | HIGH |
| Rhino remediated | Compute PassRole | $1,800 | remove_compute_trust | HIGH |
| Bybit before | (no viable path) | — | — | MINIMAL |
| Bybit after | (no viable path) | — | — | MINIMAL |

The Cognito pair tells the whole story: a $300 attack path
exists today; **disable_unauth costs $50 and blocks it
entirely.** "Infinite ROI" — the defender spends nothing on
the next-cheapest control because the path is gone. That's
the slide a CISO puts in front of a board.

## Run

```bash
cd stave
make build
bash examples/game-theory-cost/run.sh
```

Pure stdlib Python; no pip install required. The model uses
manual maximin (sort remediations by ROI, take the first);
multi-remediation Nash equilibria via `nashpy` are a future
extension when multi-step defender strategies become
foundational.

## What this is not

- **Not a precise cost predictor.** The dollar values are
 RELATIVE rankings. "$300 vs $18,000" means "60× harder,"
 not literal dollars. Calibrate the constants per
 organisation; the model's value is the ordering, not the
 absolute number.

- **Not a single-attacker model.** Real environments face
 multiple attackers with different cost tolerances (script
 kiddie, pentester, APT). This version assumes one rational
 actor; multi-persona modelling (where each persona has its
 own cost weights) is a future extension.

- **Not a literal Nash equilibrium.** Two-player simultaneous
 games with mixed strategies need `nashpy`'s linear-program
 or vertex-enumeration solvers. The current ranking is a
 one-step maximin: best defender response to the cheapest
 attacker path. Iterating both sides to fixed-point is the
 follow-up when multi-step defender plans matter.

- **Not a substitute for the boolean engines.** A SAFE
 attacker-cost verdict (no path under modeled shapes) does
 not imply zero risk. Bybit's wildcard prefix-match misses
 here for the same reason it misses the wildcard_resource
 shape in the risk model — string-prefix reasoning is SMT
 territory. Use the comparison harness to triangulate.

- **Not a budget tool.** ROI ranking shows which remediation
 buys the most attacker-cost increase per defender dollar.
 It does NOT account for organisational priority, regulatory
 requirements, or stakeholder politics. Pair it with those
 external constraints; don't replace them.
