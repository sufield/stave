# Conflict Report Schema — Design Sketch (Node 2a)

**Status:** Draft, awaiting approval before schema implementation (Node 2b).
**Iteration:** 3, Node 2a.
**Scope:** Two candidate shapes for the conflict report emitted by catalog
conflict detection. Taxonomy fixed by Node 1:
`CONTRADICTION`, `REDUNDANCY`, `EMPIRICAL_SUBSUMPTION`, `DIVERGENCE`.

The decision point is which shape makes cross-category queries ergonomic,
because downstream apps will ask both category-scoped questions (*"all
contradictions"*) and control-scoped questions (*"all conflicts involving
CTL.IAM.POLICY.001"*).

---

## Shared assumptions (both shapes)

Regardless of shape, each conflict pair carries:

- `control_a`, `control_b`: stable control IDs, ordered lexicographically
  so a pair has one canonical representation.
- `corpus_coverage`: object with `fixtures_evaluated` (int),
  `fixtures_matched` (int — where at least one control fired), and
  `corpus_version` (string — git SHA of the fixture tree at eval time).
  Surfaces confidence honestly; authors read it to judge whether the
  finding is load-bearing.
- Category-specific payload (the part that differs by category).

Report-level metadata:

- `report_id`: SHA-256 of (catalog_version, fixture_corpus_version).
- `catalog_version`: git SHA of `stave/controls/` at eval time.
- `fixture_corpus_version`: git SHA of the fixture tree at eval time.
- `generated_at`: RFC3339 timestamp.
- `stave_version`: binary version that produced the report.

---

## Shape A — Common superstructure

One top-level `pairs` array. Every entry has the same top-level keys.
`category` is a closed enum. Category-specific fields live under
`payload`.

### JSON structure

```jsonc
{
  "report_id": "sha256:...",
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.2",
  "pairs": [
    {
      "category": "CONTRADICTION" | "REDUNDANCY" | "EMPIRICAL_SUBSUMPTION" | "DIVERGENCE",
      "control_a": "CTL.X.001",
      "control_b": "CTL.X.002",
      "corpus_coverage": {
        "fixtures_evaluated": 142,
        "fixtures_matched": 18,
        "corpus_version": "def5678"
      },
      "payload": { /* category-specific */ }
    }
  ]
}
```

### Representative example

```json
{
  "report_id": "sha256:a3f2...",
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.2",
  "pairs": [
    {
      "category": "CONTRADICTION",
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.042",
      "corpus_coverage": {
        "fixtures_evaluated": 142,
        "fixtures_matched": 7,
        "corpus_version": "def5678"
      },
      "payload": {
        "subcategory": "MISSING_ASSET_CLASS_GUARD",
        "shared_dependencies": [
          "properties.storage.access.public_read"
        ],
        "disagreement_witnesses": [
          {
            "fixture_path": "aws-lab/fixtures/s3-static-site.json",
            "asset_id": "arn:aws:s3:::example-site",
            "verdict_a": "VIOLATION",
            "verdict_b": "PASS",
            "observed_values": {
              "properties.storage.access.public_read": true
            },
            "diagnostic": "control_b guards on asset_class=static-site; control_a does not — authors should add matching guard, not fix logic"
          }
        ]
      }
    },
    {
      "category": "REDUNDANCY",
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.019",
      "corpus_coverage": {
        "fixtures_evaluated": 142,
        "fixtures_matched": 34,
        "corpus_version": "def5678"
      },
      "payload": {
        "shared_dependencies": [
          "properties.identity.policies.attached[*].arn"
        ],
        "shared_compliance": ["cis_aws_v1.4.0:1.16", "nist_800_53_r5:AC-6"],
        "shared_attack_stage": "privilege_escalation",
        "shared_remediation_hash": "sha256:9c1e..."
      }
    },
    {
      "category": "EMPIRICAL_SUBSUMPTION",
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.014",
      "corpus_coverage": {
        "fixtures_evaluated": 142,
        "fixtures_matched": 12,
        "corpus_version": "def5678"
      },
      "payload": {
        "narrower": "CTL.S3.PUBLIC.001",
        "broader": "CTL.S3.PUBLIC.014",
        "dependency_delta": [
          "properties.storage.access.public_list"
        ],
        "note": "Empirical against current corpus. Static predicate logic not proven to subsume."
      }
    },
    {
      "category": "DIVERGENCE",
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.022",
      "corpus_coverage": {
        "fixtures_evaluated": 142,
        "fixtures_matched": 28,
        "corpus_version": "def5678"
      },
      "payload": {
        "agreement_rate": 0.89,
        "minimal_disagreement_fixtures": [
          {
            "fixture_path": "aws-lab/fixtures/iam-cross-account.json",
            "asset_id": "arn:aws:iam::111122223333:role/DataIngest",
            "verdict_a": "VIOLATION",
            "verdict_b": "PASS",
            "differing_values": {
              "properties.identity.trust.external_ids": ["shared-external-id"]
            }
          }
        ]
      }
    }
  ]
}
```

### Python: "show me all CONTRADICTIONs"

```python
import json
report = json.load(open("conflict-report.json"))
contradictions = [p for p in report["pairs"] if p["category"] == "CONTRADICTION"]
for p in contradictions:
    print(p["control_a"], "vs", p["control_b"], "—", p["payload"]["subcategory"])
```

### Python: "show me all conflicts involving CTL.IAM.POLICY.001"

```python
import json
report = json.load(open("conflict-report.json"))
target = "CTL.IAM.POLICY.001"
involved = [p for p in report["pairs"] if target in (p["control_a"], p["control_b"])]
for p in involved:
    other = p["control_b"] if p["control_a"] == target else p["control_a"]
    print(f"{p['category']:25s} {target} ~ {other}")
```

---

## Shape B — Four distinct arrays

Separate top-level array per category. Each array holds category-specific
objects with no `category` discriminator field (the array name carries it).

### JSON structure

```jsonc
{
  "report_id": "sha256:...",
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.2",
  "contradictions":         [ /* Contradiction[] */ ],
  "redundancies":           [ /* Redundancy[] */ ],
  "empirical_subsumptions": [ /* EmpiricalSubsumption[] */ ],
  "divergences":            [ /* Divergence[] */ ]
}
```

Each element still carries `control_a`, `control_b`, and
`corpus_coverage`; the category-specific fields are hoisted to the top
level of each element (no nested `payload`).

### Representative example

```json
{
  "report_id": "sha256:a3f2...",
  "catalog_version": "abc1234",
  "fixture_corpus_version": "def5678",
  "generated_at": "2026-04-17T14:03:22Z",
  "stave_version": "0.1.2",
  "contradictions": [
    {
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.042",
      "corpus_coverage": { "fixtures_evaluated": 142, "fixtures_matched": 7, "corpus_version": "def5678" },
      "subcategory": "MISSING_ASSET_CLASS_GUARD",
      "shared_dependencies": ["properties.storage.access.public_read"],
      "disagreement_witnesses": [ /* ... */ ]
    }
  ],
  "redundancies": [
    {
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.019",
      "corpus_coverage": { "fixtures_evaluated": 142, "fixtures_matched": 34, "corpus_version": "def5678" },
      "shared_dependencies": ["properties.identity.policies.attached[*].arn"],
      "shared_compliance": ["cis_aws_v1.4.0:1.16", "nist_800_53_r5:AC-6"],
      "shared_attack_stage": "privilege_escalation",
      "shared_remediation_hash": "sha256:9c1e..."
    }
  ],
  "empirical_subsumptions": [
    {
      "control_a": "CTL.S3.PUBLIC.001",
      "control_b": "CTL.S3.PUBLIC.014",
      "corpus_coverage": { "fixtures_evaluated": 142, "fixtures_matched": 12, "corpus_version": "def5678" },
      "narrower": "CTL.S3.PUBLIC.001",
      "broader":  "CTL.S3.PUBLIC.014",
      "dependency_delta": ["properties.storage.access.public_list"]
    }
  ],
  "divergences": [
    {
      "control_a": "CTL.IAM.POLICY.007",
      "control_b": "CTL.IAM.POLICY.022",
      "corpus_coverage": { "fixtures_evaluated": 142, "fixtures_matched": 28, "corpus_version": "def5678" },
      "agreement_rate": 0.89,
      "minimal_disagreement_fixtures": [ /* ... */ ]
    }
  ]
}
```

### Python: "show me all CONTRADICTIONs"

```python
import json
report = json.load(open("conflict-report.json"))
for p in report["contradictions"]:
    print(p["control_a"], "vs", p["control_b"], "—", p["subcategory"])
```

### Python: "show me all conflicts involving CTL.IAM.POLICY.001"

```python
import json
report = json.load(open("conflict-report.json"))
target = "CTL.IAM.POLICY.001"
CATEGORIES = ("contradictions", "redundancies", "empirical_subsumptions", "divergences")
for cat in CATEGORIES:
    for p in report[cat]:
        if target in (p["control_a"], p["control_b"]):
            other = p["control_b"] if p["control_a"] == target else p["control_a"]
            print(f"{cat:25s} {target} ~ {other}")
```

---

## Decision

**Shape A wins.**

The two queries expose the asymmetry:

| Query | Shape A | Shape B |
|-------|---------|---------|
| All CONTRADICTIONs | one filter on `pairs` | direct array access |
| All conflicts involving CTL.X | one filter on `pairs` | nested loop over four hard-coded array names |
| All correctness defects (CI gate) | one filter on `category` | direct array access |
| Filter by `corpus_coverage.fixtures_matched > N` | uniform field, one pass | four separate passes |

Shape B is marginally cleaner for pure category-scoped access, but any
cross-category traversal requires callers to hard-code the full list of
array names. Adding a fifth category later is a breaking change for every
caller that iterates (they silently miss the new category until updated).
Shape A adds a category by extending an enum; existing iterators keep
working and filters that don't care about the new category still behave
correctly.

Additional Shape A benefits:

- Uniform JSON-schema validation: one `ConflictPair` definition with
  `oneOf` on `payload` keyed by `category`. Shape B needs four
  definitions and four array validations.
- Stable pagination / streaming. A single `pairs` array sorts and pages
  naturally; Shape B needs per-category paging.
- Uniform `corpus_coverage` field location across entries.

Shape B's only real advantage — slightly terser category-scoped reads —
is not worth the cross-category tax given that control-scoped queries
are at least as common as category-scoped ones.

### Shape A tradeoff acknowledged

Shape A elements have a `payload` indirection that Shape B avoids. A
downstream reader writing category-specific logic pays one extra key
lookup per access. This is a small ergonomic cost paid by a narrow
audience (category-specialist code) in exchange for a large ergonomic
gain for generalist code (CI gates, dashboards, cross-cutting queries).
Accept the tradeoff.

---

## Open questions for Node 2b

- `disagreement_witnesses` and `minimal_disagreement_fixtures` can grow
  large on wide corpora. Node 2b should specify a cap (e.g., max 5
  witnesses per pair, with a `witnesses_truncated` flag) so reports
  stay readable.
- `shared_remediation_hash` vs inlining remediation text. Proposal:
  hash in the report, full text resolvable via control catalog lookup.
  Keeps reports compact; downstream apps already have the catalog.
- Exit code wiring: per Node 1, CONTRADICTION gates CI (exit 1),
  others are informational (exit 0). Node 2b must specify the CLI
  contract (`stave conflicts check`) separately from the schema —
  schema is data, exit code is CLI behavior.

---

## Decision request

Approve Shape A to proceed to Node 2b (write the JSON Schema at
`stave/docs/ontology/v0.1/conflict-report.schema.json`, update
`CHANGELOG.md` draft entry, update `README.md` ontology primitive
section).
