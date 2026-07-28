# Blind Trial Results — Prolog + Clingo

Per the reviewer's "one fully-blind re-run of the hardest trial" —
extended to both Prolog and Clingo because both had spec changes
landed in the prior trial round that needed re-validation.

## Method

Each trial executed via a fresh sub-agent (`Agent` tool with
`general-purpose` subagent_type, no prior context from this
conversation). Each agent's prompt:

- Pointed at exactly three permitted files per trial:
  `spec-trial.yaml`, `input.jsonl`, `export-schema.md`
- Listed forbidden files explicitly: the unstripped `spec.yaml`
  (contains the answer), `golden.yaml` (the answer key), and
  the source `examples/<engine>/` directory
- Required output in a structured ANSWER / REASONING /
  CONFIDENCE shape so failure modes are explicit

The sub-agents had no access to this session's prior turns, so
they could not know what the answers were or that this is a
multi-round trial.

## Prolog — PASS (medium confidence)

The blind agent indexed facts, identified one unauth-admitting
pool (`…:abc-app-pool`), traced it to `Cognito_appUnauth_Role`,
and computed the cartesian product:
4 actions × 3 resources = 12 derivable tuples.

Validation outcome:

| Field | Trial | Golden | Rule | Outcome |
|---|---|---|---|---|
| proof_trees_count | 12 | 12 | exact_match | PASS |
| edges_per_proof | 4 | 4 | exact_match | PASS |
| first_proof_root | `…dynamodb…via dynamodb:GetItem` (alphabetical sort) | `…app-public-assets…via s3:GetObject` | semantic_match — "at least one proof rooted at that pair" | PASS |

The agent's confidence note flagged two spec gaps:

1. The spec does not pin output ordering for the 12 proofs.
   The agent chose alphabetical-by-action then alphabetical-by-
   resource. Different orderings produce structurally
   equivalent answers but byte-different output.
2. The spec does not pin indentation width. The agent
   defaulted to 2 spaces per level matching the template.

Neither is a defect — the validation block was authored with
ordering and whitespace explicitly in the `ignore:` list. The
agent's flag confirms the spec's ignore-list lines are
foundational; they prevent false-FAIL outcomes on a correct
answer.

## Clingo — PASS (high confidence)

The blind agent applied all four named rules to the JSONL facts
and produced exactly the 4 violation atoms in the golden:

| Atom | Subject | Found? |
|---|---|---|
| advanced_security_off | `…userpool/us-east-1_appPool` | ✓ |
| mfa_disabled | `…userpool/us-east-1_appPool` | ✓ |
| unauth_cognito_s3_read | `…identitypool/us-east-1:abc-app-pool` | ✓ |
| wildcard_action_resource | `…role/Cognito_appAuth_Role` | ✓ |

Set equality, order-independent per the validation rules.

The critical signal: the blind agent **correctly used
`has_mfa_enforced`** (with the `has_` prefix) — the fix from
the last round. The convention note added to the spec
("the catalog's JSONL export uses the `has_<property>`
naming convention; do not strip the prefix") was understood
by an agent with no prior context. The spec carries the
naming rule explicitly enough that fresh agents recover it.

## What the blind runs validate

Three claims that could not be validated in the same-session
runs:

1. **The reasoning steps are agent-comprehensible.** Both
   blind agents arrived at the correct answer following the
   spec's steps. No appeals to prior context, no leaked
   answer keys.
2. **The Clingo fix holds.** Last round's spec correction
   (`mfa_enforced` → `has_mfa_enforced` + convention note)
   survives a fully-blind run. The naming-convention rule is
   recoverable from the spec alone.
3. **The Prolog fix holds.** Last round's golden correction
   (6 → 12) is consistent with what an agent derives blind
   from the input. The 12-count cartesian-product semantic
   was applied without needing the example comment in
   `spec.yaml` (the comment is in `spec.yaml`, not
   `spec-trial.yaml` — the blind agent saw only the latter).

## What still requires care

The Prolog spec's `ignore` list is doing real work — without
those entries the trial would FAIL on ordering and indentation
even when the underlying reasoning is correct. Future specs
should default to listing ordering and whitespace under
`ignore:` unless the engine being modelled actually pins
either.

The Clingo spec's structural leak (the four violation atom
names are part of the rule definitions and therefore visible
to the trial agent) is not a defect — the agent must still
correctly identify which subjects each named rule fires on.
The blind run confirms the agent doesn't simply echo the
atom names; it pairs them with the right subjects derived
from the facts.

## Status

Five trials run total:
- z3-public-read-bucket: PASS (same-session)
- souffle-anonymous-reachability: PASS (same-session)
- prism-risk-probability: PASS (same-session)
- prolog-proof-chain: PASS (blind, after Phase 1 golden fix)
- clingo-violation-atoms: PASS (blind, after spec predicate fix)

The reasoning-spec format is validated. The five trial packages
under `reasoning-specs/trials/` are ready for use as a
regression suite: re-running them after spec changes or catalog
projections evolve will surface either spec drift or catalog
drift, depending on the failure category.
