# explain — Translation Layer Quality (Iterations 1 + 2 + 3)

Three human-readable layers around the SMT solver:

- **Encoding report** (`format_facts.py`) — renders the SIR
  fact export (solver input) as a per-asset summary in
  cloud-security language. Engineer verifies "did Stave
  understand my configuration?" without reading SMT-LIB.
- **Encoding verifier** (`verify_encoding.py`) — for each
  verifiable fact, navigates the asset's actual observation
  JSON at the provenance path and compares the value to
  `fact.object`. Catches projector bugs (wrong path, wrong
  value, type coercion drift) BEFORE the solver runs.
- **Verdict report** (`verdict.py`) — renders the solver's
  sat/unsat/unknown answer as **UNSAFE / SAFE / INCONCLUSIVE**
  with a numbered chain of contributing facts and a
  remediation. Engineer reads "an anonymous internet user can
  read PHI..." rather than "sat".

```
stave export-sir --format jsonl  →  format_facts.py  →  Configuration Summary: ...
                                                         Asset: arn:aws:s3:::prod-phi (aws_s3_bucket)
                                                           ├── Public read access: ENABLED
                                                           │     Source: ...
                                                           ├── Tag: data-classification=phi
                                                           │     Source: ...
                                                           └── ...
```

## What these layers are

The pipeline crosses two translation boundaries — both can
contain bugs that the solver itself cannot. The solver
(Z3 / cvc5 / Yices) is trusted; the **encoding** of the
observation into SMT-LIB and the **decoding** of the verdict
back into cloud-security language are not.

```
Cloud Security Domain          Math Domain          Cloud Security Domain
(what the engineer knows)      (what Z3 knows)      (what the engineer reads)

  Observation JSON        →    SMT-LIB assertions   →    UNSAFE / SAFE / INCONCLUSIVE
                                                         "Anonymous internet user can
                                                          read PHI from prod-phi..."

  ENCODING BOUNDARY            SOLVER                    DECODING BOUNDARY
  Iter 1: format_facts.py      (trusted)                 Iter 2: verdict.py
  Iter 3: verify_encoding.py
  (correctness check)
```

Both layers speak cloud-security, never math. The word "sat"
never appears in user-facing output. The word "unsat" never
appears. Predicate names ("has_public_read") never appear.
Engineers read **Public read access: ENABLED** and **UNSAFE:
anonymous user can read PHI** — domain language on both
sides.

## Run

```bash
cd <repo-root>/stave
make build

# Default fixture: cognito-iteration2-unauth/cross-resource-config
bash examples/explain/run.sh

# Any observation directory
bash examples/explain/run.sh path/to/observations
```

## Output

```
Configuration Summary: 3 asset(s), 34 encoded fact(s) (non-control records from the SIR)

Asset: arn:aws:cognito-identity:us-east-1:111122223333:identitypool/... (aws_cognito_identity_pool)
  ├── Asset type: aws_cognito_identity_pool   fact_id: c9fbc2af28c4
  │     Source: assets[0].type (path: type)
  ├── Cloud vendor: aws                       fact_id: 255bfca8b6b2
  │     Source: assets[0].vendor (path: vendor)
  ├── Exposure contributed by control: CTL.COGNITO.IDENTITY.GUEST.001
  │     Source: temporal.windows[0].contributing_controls
  ...

Asset: arn:aws:s3:::acme-phi-records (aws_s3_bucket)
  ├── Asset type: aws_s3_bucket               fact_id: 025c4d9b38d1
  ├── Tag: data-classification=phi            fact_id: ...
  └── ...
```

Each row carries:
- **Predicate label** in cloud-security language
  (`has_public_read` → "Public read access")
- **Value** with legible interpretation
  (`true` → "ENABLED" — coloured red when permissive, green
  when protective)
- **Source** — which observation property the projector read,
  with full path
- **fact_id** — the deterministic SHA-256 the SMT side uses,
  so the human and the solver share the same identifier

The label dictionary lives at the top of `format_facts.py`
(`PREDICATE_LABELS`); every predicate Stave's catalog ships
gets a one-line cloud-domain translation. Predicates not in the
table render under their predicate name unchanged so the output
stays readable when a new projector ships before the table
catches up.

## Verdict report (Iteration 2 — the decoding boundary)

`verdict.py` translates a solver result + the invariant
metadata + the contributing facts into cloud-security language.

Input shape:

```json
{
  "verdict": "sat" | "unsat" | "unknown" | "timeout",
  "query":   "<query name or file>",
  "invariant": {
    "id":          "<control ID>",
    "name":        "<one-line title from YAML>",
    "description": "<forbidden_state description from YAML>",
    "remediation": "<remediation.action from YAML>",
    "remediation_cost":   "<optional, e.g. '$0'>",
    "remediation_time":   "<optional, e.g. '30 seconds'>",
    "remediation_effect": "<optional>"
  },
  "contributing_facts": [
    { "predicate": "...", "object": "...", "subject": "...",
      "evidence": "...", "provenance": {"property_path": "..."} },
    ...
  ]
}
```

Renders to:

```
UNSAFE: An anonymous internet user can read PHI data from the prod-phi bucket.

The forbidden state is reachable because:
  1. Unauthenticated (guest) access: ENABLED
     on arn:aws:cognito-identity:...:identitypool/abc
     (properties.identity.access.allow_unauthenticated)
  2. Maps unauthenticated users to: arn:aws:iam::...:role/AppUnauthRole
     ...
  3. IAM action allowed: s3:GetObject
     ...
  4. Tag: data-classification=phi
     on arn:aws:s3:::prod-phi
     (properties.storage.tags.data-classification)

Fix: Disable unauthenticated access on the identity pool.
     Cost: $0  Time: 30 seconds
     Effect: Breaks the chain at step 1. Z3 confirms the forbidden
     state becomes unreachable.
```

Verdict vocabulary:

| Solver result | User-facing label | Color |
|---|---|---|
| `sat` | `UNSAFE: <description>` | red |
| `unsat` | `SAFE: <description>` | green |
| `unknown` / `timeout` | `INCONCLUSIVE: <description>` + possible-causes list | yellow |

`PREDICATE_LABELS` and `VALUE_LABELS` are imported from
`format_facts.py` so the encoding side and the decoding side
use the same cloud-domain vocabulary. A reader who learns the
encoding vocabulary reads the verdict report without
re-learning anything.

## Encoding verifier (Iteration 3 — projector correctness)

`verify_encoding.py` reads a JSONL fact export plus the
observation directory the facts claim to come from. For each
verifiable fact (source ∈ {asset, tag, policy}), it:

1. Looks up the asset by `fact.subject` in the loaded
   observations.
2. Walks the `provenance.property_path` against the asset's
   actual JSON.
3. Compares the value found at the path to `fact.object`,
   with type coercion (bool → "true"/"false") and a
   special case for tag facts (`key=value` split + path-key
   alignment check).

A green report means every emitted fact faithfully reflects
its observation source. A red report names the bug category
and the likely cause:

| Mismatch category | Likely cause |
|---|---|
| Property path absent from observation | Stale projector — the property moved or the path was hand-edited |
| Value at the path differs from the fact object | Type coercion bug, case-folding drift, or stale denormalisation |
| Asset id has no matching observation entry | Fact references a subject not in the loaded observation set |

Sources NOT verified (synthetic — computed by the SIR
builder, not read directly from observations): `lifecycle`
(first_seen / last_seen), `exposure` (temporal windows /
contributed_by), `invariant` (forbidden_state metadata),
`control` (catalog records). Flagging these would be a
false positive.

Sample output on a clean encoding:

```
Encoding verified: 8/8 verifiable facts match observations ✓
```

Sample output on a value mismatch:

```
Encoding mismatch: 2 of 3 verifiable fact(s) do NOT match the observations they claim to come from

  Value at the path differs from the fact object  (2 fact(s))
    likely cause: Type coercion bug, case-folding drift, or a stale denormalisation.
    • has_public_read  fact_id: badval000000
        Expected (from fact): false
        Actual (from observation): true
        Path: properties.storage.access.public_read
        File: phi-bucket.obs.json
        Projector: propertyFacts
```

What this catches | What this does NOT catch
---|---
Wrong property path | Predicate naming errors (semantic, not data — is `has_public_read` the right name for this property?)
Wrong value at path | Missing facts (`stave export-sir --validate` covers projection gaps)
Type coercion bugs (`true` vs `True`) | Wrong observation file (the observation itself is wrong — upstream of Stave)
Stale projector (path moved) |
Tag-path key mismatch (path drift) |

## Test all three layers in isolation

```bash
bash examples/explain/tests/encoding/run_tests.sh   # 2 tests
bash examples/explain/tests/verify/run_tests.sh     # 3 tests
bash examples/explain/tests/decoding/run_tests.sh   # 3 tests
```

Each test pair is a fixture + an expected golden. **No Stave
binary, no solver, no observation pipeline involved**: all
three Python tools are tested in isolation.

Encoding tests:

| Test | Input | Verifies |
|---|---|---|
| `public_bucket` | bucket with `public_read=true`, PAB off, PHI tag | "Public read access: ENABLED" + "PublicAccessBlock fully enforced: DISABLED" |
| `private_bucket` | same shape with `public_read=false`, PAB on | flipping each boolean flips its legible label |

Verifier tests:

| Test | Input | Verifies |
|---|---|---|
| `good` | 5 facts that all match the bundled `phi-bucket.obs.json` | "Encoding verified: 5/5 ✓" — clean projection passes |
| `bad_value` | 2 facts with wrong values (`has_public_read=false` vs obs `true`; tag value flipped) | Both flagged as `value_mismatch` |
| `bad_path` | 2 facts with wrong paths (`storage.visibility.*` instead of `storage.access.*`; tag path names a different key) | Both flagged as `wrong_path` |

Decoding tests:

| Test | Input | Verifies |
|---|---|---|
| `sat_cognito_chain` | sat verdict + 4 contributing facts + remediation | UNSAFE rendering with numbered chain steps |
| `unsat_remediated` | unsat verdict | SAFE rendering with verification note |
| `unknown_timeout` | unknown verdict | INCONCLUSIVE rendering with possible-causes list |

A failing test points at the formatter or translator
specifically — independent of solver behaviour or observation
correctness. Per the iteration plan: encoding bugs and
decoding bugs don't get confused with solver bugs.

## Constraints (matches the iteration plan)

- **External tool only** — no Stave core changes. Pure
  Python script reading existing JSONL output.
- **Cloud-security language, not math** — predicate names
  ("has_public_read") never appear in the user-facing label.
  SMT-LIB never appears.
- **Brevity in domain language is clarity** — the report
  shows facts, not all metadata. Control-catalog records
  (`source: control`) are filtered out by default; the
  reader sees the encoding of THIS observation, not the
  catalog they're checking against.
- **Testable in isolation** — encoding tests don't run
  Stave or Z3. Pure Python diff against goldens.

## CI gate — encoding verification on every commit

The verifier is wired into the Makefile so projector
regressions fail the build automatically — no manual step
required.

```bash
make verify-encoding-demos   # runs verify_encoding --strict
                             # against every demo scenario.
                             # Hooked off `make demo-check`,
                             # which the demo workflow already
                             # exercises.

make verify-encoding-e2e     # runs verify_encoding --strict
                             # against every testdata/e2e/<name>/
                             # observations directory.

make regenerate-goldens-strict
                             # wraps `make regenerate-goldens`
                             # and runs verify-encoding-e2e
                             # afterward. Use this in CI so a
                             # regen that produces drifted
                             # encoding fails the pipeline.
                             # `make regenerate-goldens` itself
                             # stays unchanged so day-to-day
                             # local regen is unaffected.
```

Three layers of defense, each catching a different bug class:

| Layer | What it catches | When |
|---|---|---|
| `stave export-sir --validate` | Missing projections (CEL evaluates a property, no SIR fact) | Developer runs manually |
| `verify_encoding.py` | Wrong values, stale paths, missing subjects, tag-path drift | Every demo / e2e run via Makefile |
| `regenerate-goldens-strict` | Regen that produces drifted encoding | Every CI golden-update step |

The `--strict` flag on `verify_encoding.py` is the documented
CI-gate flag — the script always exits 1 on any mismatch
regardless of the flag, but `--strict` makes the gate
semantics visible at the call site so a Makefile reader
recognises it as a fail-fast check.

## Projector coverage audit (development time)

```bash
bash examples/explain/audit_projector_coverage.sh
```

Cross-checks every observation property path that appears in
fixtures (under `examples/` and `testdata/`) against the
`propertyAllowlist` entries in `cmd/exportsir/facts.go`.
Outputs:

1. **Observation paths no projector reads** — properties
   exercised by fixtures that no projector emits a SIR fact
   for. Most are legitimate (the projector allowlist is
   intentionally narrow); the list surfaces candidates worth
   projecting when a new SMT query needs them.
2. **Projector entries no fixture exercises** — paths the
   allowlist names but no observation hits. Catches stale
   projector entries left behind by a refactor.

This is a development-time triage tool, not a CI gate. Run
after adding a new control or projector to see what
shifted — read the orphan list, decide whether each entry
needs a projector, ignore the rest.

## Future iterations (not built here)

- **Iteration 4 — Run-script overhaul.** Apply iterations
  1–3 across every example so `bash run.sh` produces
  cloud-domain output by default with `--raw` for the
  technically-inclined reader. (Already shipped in commit
  `60c90c909`.)
- **Gap A — Cross-fact consistency.** The verifier checks
  each fact against its observation independently. It
  doesn't catch the case where one fact is right in
  isolation but inconsistent with another fact about the
  same asset (e.g. `has_public_read=true` matches the raw
  property but the bucket has `BlockPublicAccess=true`,
  which overrides effective behaviour). Defer until the
  EffectivePermissionResolver port work resumes — that's
  where effective-permissions semantics live.
