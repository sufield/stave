# prism-risk-prioritization

Probabilistic attack-path prioritisation. Z3 says "this path
exists" (binary). The risk model assigns each known attack
shape a probability of exploitation conditioned on the
specific facts present, and reports the worst-case
probability across applicable shapes.

The output answers a different question than every other
engine in `examples/`:

| Engine | Output for the same fixture |
|---|---|
| Z3 | `sat` — path exists |
| Soufflé | `6 reachable paths` — blast radius |
| Clingo | `violation: ...` — atoms |
| Prolog | proof tree — derivation chain |
| **risk model** | `P(exploitation) = 41.2%` — prioritisation score |

The delta between vulnerable and remediated is the
**quantified security improvement**, not a checkbox.

## Five attack shapes

Each shape evaluates only when its prerequisites are present
in the fact base; otherwise it scores 0. The fixture's
overall `P(exploitation)` is the MAX across applicable
shapes — the worst attack the configuration permits.

| Shape | Fires when… | Probability source |
|---|---|---|
| `cognito_unauth` | `allows_unauthenticated="true"` | discover × unauth-creds × assume × access × exfil |
| `cognito_self_reg` | `self_registration_unrestricted="true"` | discover × self-register × assume × access × exfil |
| `multi_hop_chain` | longest `can_assume` chain has depth ≥ 2 | `P_PER_HOP ^ depth`, floored at `P_PRIVESC_FLOOR` |
| `overperm_compute` | a role has both `contributed_by` and `trusts_service` | flat `P_OVERPERM_COMPUTE` (= 0.65) |
| `wildcard_resource` | a role has `s3:*`/`*` action AND `*` resource | flat `P_WILDCARD_BROAD` (= 0.40) |

Constants live at the top of `risk_model.py` and are meant
to be **calibrated per organisation**. The numbers shipped
here are starting estimates; their job is to *rank* paths
against each other (path A is 3× more likely than path B),
not to predict exploitation in absolute terms.

## Output (live, recorded in `expected/output.txt`)

Run `bash run.sh` to evaluate eight fixtures. Verdict
matrix:

| Fixture | P(exploitation) | Risk |
|---|---:|---|
| Cognito writeup | 41.2% | CRITICAL |
| Cognito remediated | 0.0% | NONE |
| Multi-hop vulnerable | 72.9% | CRITICAL |
| Multi-hop remediated | 40.0% | CRITICAL (residual wildcard) |
| Rhino vulnerable | 65.0% | CRITICAL |
| Rhino remediated | 65.0% | CRITICAL (residual hygiene) |
| Bybit before | 0.0% | NONE (literal-wildcard miss) |
| Bybit after | 0.0% | NONE |

Two read-thrus:

1. **Cognito writeup → remediated: 41.2% → 0.0%.** Disabling
   unauthenticated access and closing self-registration drops
   `P(exploitation)` to zero. Other engines say
   UNSAFE→SAFE; the model says "we removed 41 points of
   exploitation probability" — a financial metric a CISO can
   put in a slide.

2. **Multi-hop vulnerable → remediated: 72.9% → 40.0%.**
   Cutting the middle trust admit collapses the 3-hop chain
   to disconnected 1-hops; `multi_hop_chain` shape no longer
   applies (it requires depth ≥ 2). The residual 40% comes
   from `wildcard_resource` — admin-role still holds `s3:*`
   on `*` because it's an admin role, by design. The
   reduction (33 points) is the chain-cut value; the residual
   is the latent role-design risk.

## Honest limitations

- **Probabilities are calibration starting points.** The
  shipped constants reflect rough industry intuition; an org
  with its own threat-intel should tune them. The model's
  *value* is in ranking paths against each other; absolute
  numbers should not be quoted as predictions.

- **Shape catalogue is not exhaustive.** Five shapes capture
  the threats the existing fixtures exercise. Real risk
  modelling needs more shapes (cross-account, KMS misuse,
  CloudTrail tampering with logging-data joints, etc.) and
  a way to compose them when multiple paths contribute to
  the same target. This is a foundation, not a finished
  catalogue.

- **Bybit's literal-wildcard miss.** The wildcard_resource
  shape requires the resource literal to be `"*"`. The bybit
  fixture's developer policy uses `arn:aws:s3:::company-
  frontend-*` (a prefix wildcard pattern, not `"*"`), so the
  shape misses it. Z3's SMT string theory catches the prefix
  pattern; the comparison harness routes the bybit case
  there.

- **Rhino remediated doesn't drop.** Both rhino fixtures
  show 65% because `overperm_compute` fires whenever any
  control + service-trust overlap on a role, and the full
  Stave catalog includes hygiene controls that fire on every
  role lacking attribution tags. This is the same Soufflé
  blind-spot the comparison harness already documents — the
  shape doesn't weight controls by severity.

## Why this isn't PRISM (yet)

The original spec proposed a [PRISM
DTMC](https://www.prismmodelchecker.org/) model with
parametric transitions and PCTL temporal-property
verification. PRISM brings:

- **Steady-state analysis** — long-run probability of
  detection vs successful exfiltration.
- **Eventually-detected** properties — `P=? [F detected]` —
  even when the chain succeeds, what's the probability the
  attacker is eventually caught?
- **Conditional expectations** — `R{"detection_time"}=?` —
  expected time to detection given exfiltration occurs.

These require a Java runtime + PRISM binary (~200MB) and
the verification has more ceremony than a CISO triage
report needs. The Python multiplications shipped here are
the closed-form solution for the same DTMC under
sequential-step independence; the result agrees with what
PRISM would compute for the same parameters. Switch to
PRISM when temporal properties become load-bearing — the
`model.pm` template documents the upgrade path. Today the
calibrated constants are the lever; the verification engine
is bookkeeping.

## Run

```bash
cd stave
make build
bash examples/prism-risk-prioritization/run.sh
```

Pure stdlib Python; no pip install, no PRISM, no Java
required. The runner shells through `risk_model.py` once
per fixture.

## What this is not

- **Not an actuarial model.** The probabilities are
  ordinal rankings, not insurance-grade predictions.

- **Not a substitute for the boolean engines.** A SAFE
  Z3 verdict doesn't imply 0% risk under every model; this
  shape catalogue might miss the actual exploitation path.
  Use the comparison harness to triangulate.

- **Not a remediation prioritiser by itself.** P(exploitation)
  ranks paths; it does not estimate fix cost. Pair the
  output with cost-of-fix data for full ROI ranking.

- **Not a temporal model.** Time-to-detection, detection
  recovery rate, and persistent-attacker scenarios are
  PRISM territory; the multiplicative model here is a
  point-in-time estimate of "given the attacker tries
  today, what's the chance the chain completes?"
