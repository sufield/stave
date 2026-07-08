# reasoning-trace

Unified linker. Reads what the demo pipeline left in `results/`
and emits one JSON document that connects each CEL finding to its
contributing SIR facts (with provenance + freshness) and surfaces
every engine's verdict against the same fact base. The narrative
scripts and any future MCP `stave.explain` tool read this single
file instead of doing bespoke parsing across five.

## What it answers

Before this iteration: "why did the engines say UNSAFE?" required
opening `findings.json`, `prove-summary.json`,
`enumerate-summary.json`, `quantify-summary.json`, and the raw
.txt outputs, then correlating asset ARNs and timestamps by hand.

After: one `jq '.findings[0]'` returns:

- the failing control + asset
- the SIR fact_ids the CEL evaluator reached (PR 6's
  `contributing_fact_ids`)
- each fact's predicate, object, provenance.property_path,
  freshness.age_seconds (PRs 6a / 6b / 6c / Iter 3)
- the per-engine verdict for the whole fact base — Z3, Soufflé,
  Clingo, Risk, Game theory, Contrast — in one place

## Trace shape

```jsonc
{
  "generated_at": "2026-01-09T00:00:00Z",
  "fixture": "capital-one/capital-one",
  "consensus": "UNSAFE",
  "engines_reporting": 7,

  "engine_verdicts": {
    "cel":         {"verdict":"non_compliant", "findings_count":5},
    "z3":          {"verdict":"sat",  "queries":[ ... ]},
    "souffle":     {"verdict":"63 reachable rows", "counts":{ ... }},
    "clingo":      {"verdict":"2 violation(s)", "atoms":[ ... ]},
    "risk":        {"verdict":"P=41.2%", "probability":0.412},
    "game_theory": {"verdict":"$300 attack", "cheapest_path":{ ... }},
    "contrast":    {"rows":[ ... ], "config_changes":[ ... ]}
  },

  "findings": [
    {
      "control_id": "CTL.COGNITO.SELFREG.001",
      "control_severity": "...",
      "asset_id": "arn:aws:cognito-idp:...:userpool/abc",
      "contributing_facts": [
        {
          "fact_id": "8bf76b03b87f",
          "predicate": "self_registration_unrestricted",
          "object": "true",
          "provenance": { "property_path": "...", "projector": "..." },
          "freshness":  { "captured_at": "...", "age_seconds": 86400 }
        }
      ]
    }
  ],

  "attack_chain": {
    "steps": [
      { "step": 1, "predicate": "allows_unauthenticated", "fact_id": "...", ... },
      { "step": 2, "predicate": "self_registration_unrestricted", ... },
      ...
    ]
  },

  "quantification": {
    "exploitation_probability": 0.412,
    "attacker_cost": 300,
    "remediation_cost": 50,
    "remediation_roi": "INFINITY",
    "anonymous_reachable": 12,
    "total_reachable": 42
  }
}
```

The `fixture`, `generated_at`, and per-engine block names are stable
across runs when `--eval-time` is pinned (which `run.sh` does, mirroring
the demo's pin).

## Running

```bash
# 1. produce the demo's results
cd $REPO/demos/nodes-2026 && make demo-no-graph

# 2. link them
bash $REPO/stave/examples/reasoning-trace/run.sh
```

Output lands in `examples/reasoning-trace/results/capital-one/reasoning-trace.json`.

## Design notes

- **No Stave source changes.** This is a pure consumer of files
  that already exist; new engines can be added by writing a new
  `adapt_<name>(summary)` function in `link.py`.
- **Tolerant of missing summaries.** Engines whose summary file
  doesn't exist (or whose summary doesn't carry recognisable
  shape) are silently absent from the trace — see Iteration 4's
  rule "do not require all engines to have run." The
  `engines_reporting` count tracks who showed up.
- **Predicate-driven attack chain, not inferred.** The chain
  walker reads facts whose predicate matches a fixed sequence
  (`allows_unauthenticated` → `self_registration_unrestricted` →
  `maps_unauth_to` → `has_action` → `has_resource` → ...). Steps
  appear only when the predicate exists in the JSONL; the chain
  reflects what the fixture actually contains, not what the
  demo's narrative claims.
- **Read what's actually present.** The summary files the demo
  emits today have shapes that differ from the iteration-4 spec
  sketch (e.g. `prove-summary.json`'s `queries` is an array, not
  a dict; clingo reports `clingo_atoms` not `violations`). The
  linker reads the actual shapes; adapters are localised so a
  schema change is a one-function fix.

## What this enables next

- **Demo narrative scripts** (the `06-quantify` and `09-compare`
  steps in `demos/nodes-2026/scripts/`) can read the trace
  instead of opening five files separately.
- **MCP `stave.explain` tool** can return the trace for a finding
  to an AI agent, replacing prose summaries with structured data.
- **Compliance evidence** (the `compliance-evidence` example) can
  cite specific fact_ids and engine verdicts from the trace
  rather than re-deriving them.

## Golden

`expected/capital-one/reasoning-trace.json` is the trace the
linker emits today against the current demo output. Re-running
`bash run.sh` after a clean demo run produces a byte-stable
result when `--eval-time` is pinned. To refresh after an intentional
change:

```bash
cd $REPO/demos/nodes-2026 && make demo-no-graph
cd $REPO/stave/examples/reasoning-trace && bash run.sh
diff -r expected/ results/   # confirm the diff matches the change
cp -r results/* expected/
```
