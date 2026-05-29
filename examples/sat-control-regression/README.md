# sat-control-regression

Boolean compound-of-finding regression check via pysat
(Glucose3). The third reasoning engine on top of the JSONL
export.

## What this answers

> "Given these N control verdicts as boolean flags, which
> combinations of verdicts constitute a compound failure?"

Z3 reasons about policy semantics over individual fixtures
(per-asset, per-control). ASP enumerates the complete set
of ground-atom violations. SAT scales the boolean check
across the full control catalog: each control becomes one
variable; each compound is one AND-clause; the formula
asks whether any compound is satisfied under the observed
verdicts. The encoding is linear in rules; the solve is
near-instant on hundreds of variables.

This is the regression-detection layer. When a new control
is added or a finding starts firing on a fixture that
previously didn't, the SAT check re-runs in milliseconds
and tells you whether any compound just lit up — without
re-traversing the asset graph or replaying the policy
engine.

## Two modes

| Mode | Question | When to use |
|---|---|---|
| `check` | Given the *current* fired set, which compounds fire? | After a normal scan; the regression alert. |
| `what-if` | Given the *current* fired set, what minimal set of additional findings would tip the configuration into UNSAFE? | Pre-merge gating: estimate blast radius of accepting a new finding. The genuine SAT-scaling demonstration. |

The `what-if` mode is where the boolean encoding genuinely
exploits combinatorial structure. With K candidate controls
there are 2^K possible extensions; pysat decides in linear
time over the encoded clauses. Returns the smallest tipping
set the solver finds.

## The compound rules

Nine rules in `compound_rules.py`, all conjunctions of
control-firing flags. Each is an unsafe shape that holds
*only* when every conjunct fires. The most illustrative are
shown here; see `compound_rules.py` for the full set:

| Rule | Conjuncts | Catches |
|---|---|---|
| `rhino_passrole_with_role_hygiene_gap` | `IAM.ESCALATE.PASSROLE.AUTOSCALING.001` ∧ `IAM.ROLE.INTENTTAG.001` | The deny-list bypass on a fixture without role-attribution tagging — the lateral targets aren't reviewable. |
| `cognito_anon_to_aws_2of3` | `COGNITO.SELFREG.001` ∧ `COGNITO.MFA.001` | Self-register + no MFA — the anonymous-to-AWS-credentials path. |
| `cognito_full_id_bypass_3of3` | `COGNITO.SELFREG.001` ∧ `COGNITO.MFA.001` ∧ `COGNITO.ADVANCED.SECURITY.001` | Strict variant: the complete identity-bypass cascade — no rate-limit, no second factor, no anomaly detection. |
| `staging_endpoint_exposed` | `LIFECYCLE.STAGING.STALE.001` ∧ `S3.PUBLIC.LIST.002` | A stale non-production resource that is also publicly listable — the HIGH-severity compound the `staging_endpoint_exposed` chain escalates. |

The 2-of-3 and 3-of-3 are deliberately stratified — the
relaxed compound matches more configurations; the strict
compound matches only the worst. CISO triage typically
wants both views.

## Output (live, recorded in `expected/output.txt`)

```
=== rhino-vulnerable ===
  SAFE: no compound rule fires on this fixture

=== rhino-remediated ===
  SAFE: no compound rule fires on this fixture

=== cognito-writeup ===
  UNSAFE: 2 compound(s) fire
    - cognito_anon_to_aws_2of3
    - cognito_full_id_bypass_3of3

=== cognito-remediated ===
  SAFE: no compound rule fires on this fixture

=== staging-stale-public ===
  UNSAFE: 1 compound(s) fire
    - staging_endpoint_exposed
        fired: CTL.LIFECYCLE.STAGING.STALE.001
        fired: CTL.S3.PUBLIC.LIST.002

=== staging-active ===
  SAFE: no compound rule fires on this fixture

=== rhino-remediated-what-if (current verdicts) ===
  SAFE: no compound rule fires on this fixture

=== what-if: smallest tip-into-unsafe extension ===
  Adding 2 finding(s) tips configuration into UNSAFE:
    + CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001
    + CTL.IAM.ROLE.INTENTTAG.001
  Compound(s) triggered: rhino_passrole_with_role_hygiene_gap
```

The cognito writeup-config triggers two stratified
compounds simultaneously (the 2-of-3 is implied by the
3-of-3 in the firing set). The remediated config silences
both. `staging-stale-public` is the single-asset compound:
one demo-tagged bucket trips both the staleness and the
public-list control, so `staging_endpoint_exposed` fires;
`staging-active` is stale-but-not-public, so it stays clean.
The rhino fixtures are SAFE on their own — only
`PASSROLE.AUTOSCALING` fires there, not the role-hygiene
conjunct — so the what-if demonstrates the regression-
prediction shape: adding *both* missing findings
(`PASSROLE.AUTOSCALING` + `ROLE.INTENTTAG`) is the smallest
set that tips rhino-remediated into unsafe, a clean signal
for "do not let these controls start co-firing without
re-reviewing."

## Why SAT not Z3 / Clingo

- **Z3** carries policy semantics — string theory, integer
 arithmetic, function symbols. Overkill when the question
 is "AND over boolean flags."
- **Clingo** does default negation and disjunctive
 enumeration but its solve cost grows with rule complexity.
 Boolean conjunction over flags is below ASP's complexity
 floor.
- **SAT** is the *natural* language for "given these flags,
 is the formula satisfied?" — and modern SAT solvers
 (Glucose, Cadical) handle millions of variables in
 seconds. When the control catalog reaches 2,100+, only
 SAT runs in CI-time.

The three engines compose. CEL produces the per-asset
verdicts; SAT regression-checks the verdicts against
compound rules; ASP enumerates triples; Z3 produces
witnesses. Each is the right tool at its layer; together
they cover the question space without a single engine
having to scale beyond its sweet spot.

## Run

```bash
# One-time tooling setup:
python3 -m venv .tools-venv
.tools-venv/bin/pip install python-sat

# Then any time:
cd stave
make build
bash examples/sat-control-regression/run.sh
```

If `PYSAT_VENV` is unset, the runner expects `.tools-venv`
at the repository root (sibling of `stave/`).

Most fixtures use `--controls controls/` (the full Stave
catalog) rather than per-example dirs, because the compound
rules need multiple controls to fire on the same fixture
and a narrow per-example controls dir would usually have
only one control fire. The `staging-*` fixtures are the
exception: they use the `staging-stale-endpoint/controls`
dir because both conjuncts of `staging_endpoint_exposed`
(`LIFECYCLE.STAGING.STALE.001` and `S3.PUBLIC.LIST.002`)
live there and are not in the default catalog.

## What this is not

- **Not a policy engine.** Compound rules don't replace
 CEL's per-asset reasoning. They compose its outputs.
 When CEL's verdict on a control changes, the compound
 check re-runs; the underlying control YAML is unchanged.

- **Not a unified solver.** Some compounds need
 cross-asset string matching (bybit) or transitive closure
 (multi-hop privesc). Those belong in SMT or Datalog. The
 compound ruleset is deliberately narrow: only patterns
 expressible as boolean-AND over already-evaluated
 findings.

- **Not a fixture-coverage tool.** A SAFE verdict means "no
 compound rule fires on this fixture under these
 verdicts." It does NOT mean the fixture is policy-clean —
 individual findings can still be present. The compound
 layer adds an *additional* gate, not a substitute for the
 per-finding gate.

- **Not a min-cut analyzer.** The what-if mode finds *a*
 minimal trigger set, not *the* minimum (it's whichever
 the solver returns first). For genuinely-minimum
 enumeration, switch to MaxSAT / hitting-set reasoning.
 The current shape is sufficient for "show me one path
 to unsafe" — the regression alert.
