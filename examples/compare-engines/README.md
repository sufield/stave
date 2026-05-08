# compare-engines

Multi-engine comparison harness. Runs every available
reasoning engine against the same fixture set and reports
per-fixture verdict.

## Why this matters

Each engine answers a different KIND of question:

| Engine | Native question | Verdict normalization |
|---|---|---|
| Stave CEL | "Does this snapshot violate any rule in the narrow control set?" | `status` field: COMPLIANT → SAFE, NON_COMPLIANT → UNSAFE |
| Z3 | "Is this query satisfiable on this fact base?" | `z3=sat` → UNSAFE; `z3=unsat` → SAFE |
| cvc5 | (cross-check Z3 with an independent solver) | same as Z3 |
| Clingo | "Which violation atoms exist under stable-model semantics?" | any `violation:` line → UNSAFE; `(clean)` or only latent_risk → SAFE |
| pysat | "Are any boolean compound rules satisfied by current verdicts?" | `UNSAFE` line → UNSAFE; `SAFE` line → SAFE |
| Soufflé | "Are any unsafe-pattern relations non-empty?" | `anonymous_reachable` ∨ `self_register_reachable` ∨ `exploitable_overperm` ∨ `privesc_chain` > 0 → UNSAFE |

**Consensus** = all decided engines agree → high confidence.
**Disagreement** = engines disagree → blind spot in at least
one of them. The disagreement IS the finding.

## Run

```bash
cd stave
make build
bash examples/compare-engines/run.sh # human output (with timings)
bash examples/compare-engines/run.sh --no-timing # stable for golden capture
bash examples/compare-engines/run.sh --json # machine-readable
bash examples/compare-engines/run.sh --strict # exit 1 on any disagreement (CI gating)
```

The wrapper activates `.tools-venv` (Clingo + pysat) and
adds `~/.local/bin` to `$PATH` (Soufflé). Each engine's
`available_check` runs first; missing engines are skipped
gracefully.

## What the eight fixtures look like

Eight fixtures across four threat shapes (vulnerable +
remediated for each). Each engine that has coverage gives
its verdict; the row marked `==` is consensus; `!=` is
disagreement.

```
=== Cognito self-register (writeup) (expected UNSAFE) ===
 [ok] stave-cel UNSAFE
 [ok] z3 UNSAFE
 [--] cvc5 no example covers this fixture
 [ok] clingo UNSAFE
 [ok] pysat UNSAFE
 [ok] souffle UNSAFE
 == CONSENSUS: UNSAFE (5 engine(s))

=== Multi-hop can_assume (vulnerable) (expected UNSAFE) ===
 [ok] stave-cel SAFE
 [ok] z3 UNSAFE
 [ok] clingo UNSAFE
 [--] pysat no example covers this fixture
 [ok] souffle UNSAFE
 != DISAGREEMENT: clingo=UNSAFE; souffle=UNSAFE; stave-cel=SAFE; z3=UNSAFE
```

Full expected output is in `expected/output.txt`.

## Reading the disagreements

The shipped fixture set produces five disagreements. Each
points to a real model gap in one of the engines:

### Multi-hop vulnerable: stave-cel says SAFE; everyone else UNSAFE

The narrow `iam-multi-hop-trust/controls/` directory has
only the placeholder control (`CTL.IAM.CHAIN.PLACEHOLDER.001`),
which by design never fires. CEL with this narrow set
reports COMPLIANT. The full Stave catalog *does* have IAM
controls that fire on this fixture (e.g., role hygiene),
but the narrow set is what the example ships.

Lesson: **CEL is only as strong as its narrowest configured
control set**. The harness surfaces this immediately. Z3,
Clingo, Soufflé reason directly over fact composition, so
they flag the chain regardless of the active control set.

### Multi-hop remediated: souffle UNSAFE; everyone else SAFE

Soufflé's `privesc_chain` rule emits every chain prefix
including 1-hop edges. After remediation, two single-hop
`can_assume` edges survive (the broken chain leaves
`developer→onboarding` and `operator→admin` as disconnected
1-hops). Soufflé sees `privesc_chain` count > 0 and reports
UNSAFE under the harness's "any unsafe relation non-empty"
criterion.

Lesson: **Soufflé's reach predicates are coarse**. A 1-hop
assume edge is technically "privesc-able" in isolation, but
Z3 / CEL recognize that a single hop from a low-privilege
user to a low-privilege role is not the same as a 3-hop
privilege escalation. Tightening Soufflé to filter
`privesc_chain` to chains of length ≥ 2 is a reachability.dl
refinement, not a harness bug.

### Rhino vulnerable: clingo SAFE; everyone else UNSAFE

Clingo's `constraints.lp` rule V1
(`exploitable_overperm`) requires `contributed_by(R, _)`
AND `trusts_service(R, _)` on the **same** subject. The
the rhino fixture attaches `contributed_by` to the
`rhino-attacker` *user* (the privesc primitive holder),
while `trusts_service` is on the *roles* the attacker
escalates to. Different subjects → no violation atom
fires.

Z3 and pysat compose across subjects (Z3 via SMT
existentials; pysat via boolean control-firing flags).
CEL fires the per-control wildcard finding directly.
Soufflé enumerates the cross-asset reach.

Lesson: **Clingo violation rules are subject-bound**. To
catch the rhino compound, Clingo would need a rule that
joins `contributed_by(U, _)` (user-side) with
`trusts_service(R, _)` (role-side) — the harness exposes
this gap.

### Rhino remediated: souffle UNSAFE; everyone else SAFE

Soufflé's `exploitable_overperm` fires when ANY control
fires on a role that ALSO trusts a service. The full Stave
catalog includes hygiene controls (e.g., `INTENTTAG`) that
fire on every role lacking attribution tags. So
`exploitable_overperm` produces 1 row per service-trusting
role even on remediated fixtures.

Lesson: **Soufflé does not weight controls**. A hygiene
finding contributes the same to `exploitable_overperm` as a
critical privesc finding. Tightening would require either a
control-severity filter in the Datalog or a per-control
allowlist.

### Bybit before: stave-cel + clingo + souffle SAFE; z3 + cvc5 UNSAFE

The bybit-before fixture has the developer's policy at
`Resource: arn:aws:s3:::company-frontend-*`. The production
bucket is `arn:aws:s3:::company-frontend-prod`. **Z3 + cvc5
catch the wildcard match via SMT string theory
(`str.prefixof`); CEL, Clingo, Soufflé do not.**

CEL evaluates the wildcard policy in isolation but does not
join with the bucket's `environment=production` tag.
Clingo's V6 rule looks for `s3:*` action AND production
tag, but the developer's policy uses specific actions
(`s3:GetObject`, `s3:PutObject`), not `s3:*`. Soufflé does
literal joins; the wildcard string doesn't match the prod
bucket ARN.

Lesson: **wildcard matching is a string-theory problem**.
Z3 + cvc5 are the right tools; the comparison harness
correctly routes the case to them. The other engines'
SAFE verdicts here aren't bugs — they're honest reports
of "I cannot reason about this composition under my
vocabulary."

## Why the harness exits 0 even with disagreements

A reporting tool, not a gate. Disagreements are the
output, not the failure. Pass `--strict` to flip the
semantics for CI gating:

- `bash run.sh` — exits 0 on successful end-to-end run
 regardless of disagreements (default; informational).
- `bash run.sh --strict` — exits 1 if any disagreement
 remains. Use this only after you've reconciled known
 blind-spots (e.g., resolving each disagreement as either
 "engine X has a known gap" or "engine X needs to be
 fixed").

The `expected/output.txt` golden is captured with
`--no-timing` so it stays byte-stable across runs.

## Adding a new engine

1. Add an entry to `engines.json` with `name`, `type`
 (`per_fixture` or `batch`), and `available_check`.
2. Add a parser function in `compare.py` that takes the
 engine's batch output + a fixture's `engine_label` and
 returns one of {SAFE, UNSAFE, INCONCLUSIVE}.
3. Wire the parser into `evaluate_fixture` next to the
 other engines.
4. Add the engine's label key to each fixture's
 `engine_labels` (or set to `None` where the engine has
 no example covering that fixture).
5. Re-run with `--no-timing` and capture the new golden.

Engines like Yices, Bitwuzla, or Prolog would slot in
along the same path. The harness is engine-agnostic; the
shape is "run a batch, parse per-fixture verdict, compare."

## What this is not

- **Not a CI gate by default.** Use `--strict` if you want
 to fail builds on disagreement. The default is reporting.

- **Not a substitute for individual engines' golden tests.**
 Each engine's example folder has its own `expected/output.txt`
 asserting that engine's behavior on its own fixtures. The
 harness adds cross-engine consensus on top — orthogonal
 signal.

- **Not a forcing function for engine convergence.** When
 engines disagree, the answer is usually "they're modeling
 different aspects of the same configuration." The
 harness's job is to surface the disagreement; choosing
 which engine to trust per case is the user's job (often
 routing each case to the engine that scales for it).

- **Not a benchmarking tool.** The timing fields are
 approximate (subprocess overhead dominates the small
 fixtures used here). For real benchmarking, run each
 engine in isolation on larger inputs.
