# Compatibility Check — Contradiction Detection in Requirements

Iteration 2 of the perturbation/compatibility/mutation tooling
plan. Reads a `requirements.yaml`, compiles every requirement
into one combined SMT-LIB query with named assertions, asks
Z3: "can all of these requirements hold simultaneously?"

```
requirements.yaml         → compile_requirements.py → query.smt2
                                                        ↓
                            z3 (with :produce-unsat-cores)
                                                        ↓
                            translate_core.py reads the unsat core
                            back through the YAML → human report
```

## Verdict semantics

| Z3 verdict | Meaning |
|---|---|
| `sat`   | **COMPATIBLE** — Z3 found a model that satisfies every requirement. The requirements describe a reachable configuration. |
| `unsat` | **CONTRADICTORY** — no configuration satisfies every requirement. The unsat core names the minimal subset that conflicts. |
| `unknown` | inconclusive — Z3 timed out or hit a logic it can't decide |

## Run

```bash
cd <repo-root>/stave
bash examples/compatibility-check/run.sh
```

Runs both bundled fixtures. Expected output:

```
=== compatible-requirements ===
  compiled: compatible-requirements (5 decls, 2 premises, 2 requirements)
  COMPATIBLE — compatible-requirements
    All requirements hold simultaneously in at least one model.
    ...

=== contradictory-requirements ===
  compiled: contradictory-requirements (6 decls, 3 premises, 3 requirements)
  CONTRADICTORY — contradictory-requirements

    3 requirements cannot all be satisfied under the listed premises:

    • PHI_MUST_NOT_BE_PUBLIC (HIPAA)
        PHI buckets must never allow anonymous read.
    • MARKETING_MUST_BE_PUBLIC (business)
        Marketing bucket must serve public web content.
    • IDENTICAL_PAB (ops)
        All buckets in the account must have identical PAB settings ...

    Scenario premises that activated the contradiction:
    • PHI_BUCKET_EXISTS: (assert (has_tag phi_bucket "data_classification:phi"))

    Resolution requires dropping or weakening at least one of the
    requirements above. Common patterns: scope a requirement to a
    subset (different accounts / different bucket classes), serve
    the public-read need through a different mechanism (CloudFront
    origin-access identity), or relax the symmetry constraint.
```

Run a single requirements file:

```bash
bash examples/compatibility-check/run.sh path/to/requirements.yaml
```

## requirements.yaml schema

```yaml
name: my-requirements
description: |
  Free-form prose; appears as a header comment in the
  generated SMT query.

# (declare-const ...) and (declare-fun ...) lines that the
# requirement bodies reference. Free-form SMT-LIB so authors
# can encode whatever uninterpreted predicates the
# requirements need.
declarations:
  - "(declare-const phi_bucket String)"
  - "(declare-fun has_public_read (String) Bool)"

# Optional. Premises stamp the scenario context every
# requirement is checked against. Without these the solver
# may discharge requirements trivially (e.g., no PHI bucket
# exists → "PHI must not be public" trivially holds).
premises:
  - id: PHI_BUCKET_EXISTS
    smt: '(assert (has_tag phi_bucket "data_classification:phi"))'

# The actual requirements. Each must lower to a single
# `(assert ...)` form; the compiler wraps it as
# `(assert (! ... :named ID))` so the unsat core can name it.
requirements:
  - id: PHI_MUST_NOT_BE_PUBLIC
    source: HIPAA           # free-form; surfaced in the report
    description: |
      PHI buckets must never allow anonymous read.
    smt: |
      (assert (=> (has_tag phi_bucket "data_classification:phi")
                  (not (has_public_read phi_bucket))))
```

## Why the unsat core is the killer feature

Without `(get-unsat-core)`, an UNSAT verdict says only "your
requirements can't all be satisfied" — operators don't know
WHICH ones conflict. With the named-assertion + unsat-core
mechanism, Z3 returns the minimal subset whose conjunction is
unsatisfiable, and `translate_core.py` joins those IDs back
through the YAML to produce a human-readable conflict report.

The contradictory fixture demonstrates the value: 3 each
independently-defensible requirements (HIPAA, business, ops)
combine into a no-go. The report names exactly which 3 conflict
and why; the developer sees the full triangle, not just one
finding at a time as they hit deployment failures.

## Architecture

This tool extends the Z3 surface that
`examples/z3-forbidden-state/` shipped — same SMT-LIB
vocabulary, same Z3 invocation pattern, same Python compiler
shape. The differences:

- **Source** is `requirements.yaml`, not the catalog's
  `forbidden_state` blocks. The compatibility check is a
  cross-stakeholder reasoning surface (HIPAA + business +
  ops), not a per-control invariant check.
- **Direction** is "can all requirements hold simultaneously?"
  rather than "can the forbidden state be reached?"
  — `forbidden_state` queries ask about a conjunction the
  catalog wants to disprove; compatibility queries ask about
  a conjunction the user wants to confirm.
- **Output** is the unsat core mapped back to requirement IDs
  (`translate_core.py`), not just SAT/UNSAT.

## Constraints (matches the iteration plan)

- **External tool only** — no Stave core changes. All three
  scripts live in `examples/`.
- **Reads YAML + invokes Z3** — no Stave binary required for
  the compatibility check itself; the YAML schema is
  self-contained. (A future extension can pull catalog
  forbidden_states by ID, see below.)
- **Custom YAML parser** — uses a minimal hand-rolled parser
  to avoid the PyYAML dependency for the `examples/` set.
  The schema is small enough to keep the parser short.

## Future extensions (out of scope)

- **Pull catalog forbidden_states by ID.** Today every
  requirement is hand-authored SMT in the YAML. A future
  `requirements.yaml` could reference a catalog control by
  ID (`invariant_id: CTL.S3.ACCESS.EXTERNAL.ORG.001`) and
  the compiler would pull the forbidden_state predicate from
  `stave export-controls` and emit its negation
  automatically. This couples the compatibility check to the
  catalog vocabulary; useful when the requirement IS a
  catalog invariant.
- **Z3 timeout + degraded reporting.** Today the Z3
  invocation is unbounded. For a CI/CD gate, a
  per-requirement-set timeout with a "INCONCLUSIVE" exit
  code would let the gate fail-open on slow queries.
- **Multi-engine cross-check.** A second SMT solver (cvc5)
  re-runs the same query as a sanity check. Disagreement
  means a vendor extension was used; agreement strengthens
  the verdict.
