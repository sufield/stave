# tlaplus-temporal-safety

State-space exploration over a small set of mutable
configuration knobs. Z3 / Soufflé / Clingo / Prolog answer
questions about the *current* snapshot; this engine answers
questions about the *transitions* between snapshots — the
drift margin from "safe today" to "unsafe in N API calls."

| Engine | Time horizon |
|---|---|
| Z3 | one snapshot |
| Soufflé | one snapshot |
| Risk model | one snapshot |
| **temporal** | every state reachable through one-knob flips |

## What this answers

Three questions the other engines don't:

1. **Initial-state safety.** Does the current snapshot
 already violate any invariant?
2. **Drift margin.** If the snapshot is safe today, how
 many configuration toggles separate it from the nearest
 invariant violation?
3. **State-space topology.** Of the reachable states, how
 many are unsafe? (This is fixture-independent under the
 simple "any single knob may flip" transition relation,
 so the count itself is constant — but the per-invariant
 nearest-distance is not.)

The engine doesn't replace Z3 / Soufflé / etc. on the
single-snapshot question; it *extends* them with a
forward-look across legitimate API calls.

## State machine

Seven boolean variables, one knob per legitimate API call:

| Variable | Flips when… | Stave fact source |
|---|---|---|
| `unauth_enabled` | identity-pool toggles `allows_unauthenticated` | `allows_unauthenticated="true"` |
| `self_reg_open` | user-pool toggles self-registration | `self_registration_unrestricted="true"` |
| `auth_role_broad` | auth-mapped role gets/loses `s3:*` on `*` | `has_action`+`has_resource` on the auth role |
| `unauth_role_broad` | unauth-mapped role gets/loses `s3:*` on `*` | `has_action`+`has_resource` on the unauth role |
| `data_logging` | CloudTrail data-event logging toggles | (no SIR projection today; defaults False) |
| `scp_applied` | SCP applied/removed | (no SIR projection today; defaults False) |
| `mfa_required` | user-pool MFA toggles | (no SIR projection today; defaults False) |

State space = 2⁷ = **128 states**. Transitions = single-knob
flip. Every state reachable from any other in ≤ 7 hops.
Exhaustive BFS in milliseconds.

The last three knobs (`data_logging`, `scp_applied`,
`mfa_required`) lack direct SIR projections today, so the
loader defaults them to False. The conservative read: under
the assumption that those guards are absent, what's the
drift margin? Extending the SIR to project these gives a
precise initial state. The state-space search over
hypothetical flips still produces a useful drift number
without it.

## Safety invariants

| Name | Holds when… |
|---|---|
| `NoAnonBroadAccess` | NOT (`unauth_enabled` AND `unauth_role_broad`) |
| `NoSelfRegBroadAccessWithoutMFA` | NOT (`self_reg_open` AND `auth_role_broad` AND NOT `mfa_required`) |
| `NoBroadAccessWithoutLogging` | NOT (`auth_role_broad` AND NOT `data_logging`) |
| `NoBroadAccessWithoutSCP` | NOT (`auth_role_broad` AND NOT `scp_applied`) |

Of the 128 states, 71 violate at least one invariant; 57
are clean.

## Output (live, recorded in `expected/output.txt`)

Eight fixtures evaluated. Verdict matrix:

| Fixture | Initial state | Verdict |
|---|---|---|
| Cognito writeup | `{unauth, self_reg, auth_broad}` | UNSAFE (3 invariants) |
| Cognito remediated | `{}` | AT_RISK (drift ≤ 2) |
| Multi-hop vulnerable | `{auth_broad}` | UNSAFE (2 invariants) |
| Multi-hop remediated | `{auth_broad}` | UNSAFE (2 invariants) |
| Rhino vulnerable | `{}` | AT_RISK |
| Rhino remediated | `{}` | AT_RISK |
| Bybit before | `{}` | AT_RISK |
| Bybit after | `{}` | AT_RISK |

Read the Cognito pair: writeup violates 3 invariants out of
the box; remediation flips all three flags off, leaving the
initial state empty. The "AT_RISK" verdict on remediated is
the unique signal — even with all gates closed, the
configuration is **1 hop** from `NoBroadAccessWithoutSCP`
(toggle `auth_role_broad` on without an SCP) and **2 hops**
from each of the other invariants. Z3 says "safe today";
this engine says "but only one Terraform apply away from
broken."

The Multi-hop fixtures are UNSAFE both before and after
remediation because the remediation cuts the *trust chain*
without touching the admin role's broad permissions —
`auth_role_broad` is still True. The TLA+ model surfaces
this: remediation reduced the privesc *path*, not the
underlying role-design risk. Same insight as the Soufflé /
risk-model residual readings, surfaced through a different
lens.

Rhino and Bybit fixtures map to `{}` initial state because
the loader's heuristics (auth/unauth role substring match)
don't fit those naming conventions. The engine still
computes the drift margin — useful as a signal for "this
fixture's threat model isn't captured by the seven knobs
shipped here." Adding shape-specific knobs (e.g., a
`passrole_compute` boolean) is a follow-up extension.

## Run

```bash
cd stave
make build
bash examples/tlaplus-temporal-safety/run.sh
```

Pure stdlib Python; no Java, no `tla2tools.jar`, no pip
install.

## TLA+ / TLC upgrade path

`CognitoSafety.tla` and `CognitoSafety.cfg` model the same
state machine in TLA+. Two reasons to switch to TLC:

1. **Temporal-logic properties.** TLC handles `[]` (always),
 `<>` (eventually), and fairness assumptions natively.
 Questions like "if the system reaches an unsafe state, is
 it eventually detected?" are ergonomic in TLA+ and
 awkward in Python.

2. **Larger state spaces.** Beyond ~20 boolean variables
 Python BFS becomes slow. TLC has decades of optimisation
 (symmetry reduction, partial-order reduction, parallel
 workers) and runs comfortably on millions of states.

To run TLC against the same model:

```bash
curl -fsSL -o tla2tools.jar \
 https://github.com/tlaplus/tlaplus/releases/latest/download/tla2tools.jar
java -cp tla2tools.jar tlc2.TLC \
 CognitoSafety.tla -config CognitoSafety.cfg -workers auto
```

The Python and TLC results agree on the safety-invariant
verdict (both check the same logical formulas over the same
state machine); TLC additionally produces a counterexample
trace — the specific sequence of `Toggle*` actions that
reaches a violating state.

## What this is not

- **Not a full AWS API model.** Seven booleans can't
 capture every configuration knob. The model is
 intentionally narrow — adding knobs doubles state space
 per knob, and at some point switching to TLC's symmetry
 reduction is the right move.

- **Not a substitute for the boolean engines.** A SAFE
 initial state under this model only means the seven knobs
 here don't currently violate the four invariants here. A
 fuller threat picture needs the other engines composing.

- **Not a temporal-logic verifier.** This Python runner
 enumerates reachable states and checks safety invariants
 at each. Liveness (`<>P`), fairness (`WF_v(A)`), and other
 temporal-logic properties require TLC. The `.tla` file
 ships those concerns to TLC when needed.

- **Not a drift detector.** Stave already has `stave drift`
 for diffing two snapshots. This engine answers a
 forward-looking *what-if*: given the current snapshot,
 which legitimate flips break safety? Drift detection is
 *post-hoc* (this changed); drift margin is *prospective*
 (this can change).
