examples/ vs experiments/ — different audiences, different lifecycles                                                     
                                                                                                              
  stave/examples/ — runnable demonstrations of shipped features                                                             
                                                                                                
  24 self-contained directories, each pairing one already-shipped Stave control (or compound chain) with a fixture that     
  proves it fires correctly. Audience: a developer who wants to see Stave do something concrete on their machine.
                                                                                                                            
  ┌───────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────┐
  │       Trait       │                                            Value                                             │
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Audience          │ Developers, article readers, evaluators kicking the tires                                    │
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤      
  │ Build             │ make build of the main stave binary, no extra deps                                           │      
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤      
  │ Modules           │ All in the parent stave module — except per-example z3prove/ sibling modules that link libz3 │      
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤      
  │ Determinism       │ Each ships an expected/output.txt that's diffed byte-for-byte                                │
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Failure mode      │ If an example regresses, the change broke a shipped feature                                  │
  ├───────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────┤
  │ Ships in articles │ Each example pairs with a channels/devto/<name>.md post                                      │
  └───────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────┘

  The structure is roughly:

  examples/<name>/
  ├── README.md
  ├── main.go              # drives stave.Apply, asserts findings
  ├── controls/            # the YAML control(s) under demonstration
  ├── fixtures/before/     # observations that should fire
  ├── fixtures/after/      # observations that should be silent
  ├── expected/output.txt  # captured golden
  └── z3prove/             # OPTIONAL — sibling Go module with Z3 prover

  stave/experiments/ — research code that may or may not ship

  Two large research projects, each its own Go module:

  ┌────────────────────────────┬─────────────────────────────────────────────────────────────────────────────────────────┐
  │          Project           │                                   Question it answers                                   │
  ├────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
  │                            │ Can a Z3-backed prover answer compatibility / reachability / conflict / choke-point /   │
  │ experiments/z3-solver/     │ invariant / shadow queries against pkg/stave.PolicyExport, GraphExport,                 │
  │                            │ InvariantExport?                                                                        │
  ├────────────────────────────┼─────────────────────────────────────────────────────────────────────────────────────────┤
  │                            │ When Z3 disagrees with CEL, who's right? Per-service migration harness that runs both   │
  │ experiments/z3-validation/ │ engines on the same fixture corpus and classifies disagreements before any CEL→Z3       │
  │                            │ cutover                                                                                 │
  └────────────────────────────┴─────────────────────────────────────────────────────────────────────────────────────────┘

  ┌─────────────────────┬────────────────────────────────────────────────────────────────────────────────────┐
  │        Trait        │                                       Value                                        │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ Audience            │ Formal-methods engineers, future Stave contributors                                │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ Build               │ cd experiments/<name> && make build — separate Go module, libz3 needed             │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ Modules             │ Their own go.mod + replace ../../ pointing back at the stave workspace             │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ CGO                 │ Yes — CGO_ENABLED=1 for the libz3 binding                                          │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ Failure mode        │ Experiments can be broken without blocking the main build                          │
  ├─────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤
  │ Ships in production │ No. The Stave core has cel-go only; no Z3 import anywhere in pkg/, cmd/, internal/ │
  └─────────────────────┴────────────────────────────────────────────────────────────────────────────────────┘

  The architectural reason for the split

  The Stave core is intentionally small, deterministic, and CGO-free. Pulling Z3 in would:

  - Bring libz3 into every build (libz3 is ~10 MB and not in most package managers without apt install libz3-dev)
  - Force CGO_ENABLED=1 on the main binary
  - Tie the release cadence to a research-grade dependency

  The experiments/ tree solves this by treating Z3 as a separate workspace module that consumes Stave's exports rather than
  being part of the engine. The earlier session's audit flagged this directly: "The main go.mod has zero Z3 dependencies.
  Dependencies are: cel-go v0.28.0, cobra v1.10.2, yaml.v3, jsonschema/v6. Z3 exists only in isolated experiment modules
  under experiments/z3-solver/ and experiments/z3-validation/, each with their own separate go.mod files."

  How they interact

  pkg/stave (core, CEL only, no Z3)
      │
      ├──→ examples/<name>/           runnable demo of shipped features
      │     └─ optional z3prove/      sibling module, libz3, demonstrates SMT angle
      │
      └──→ experiments/z3-solver      whole-repo Z3 reasoner (research)
           experiments/z3-validation  CEL↔Z3 differential testing (research)

  The 12 z3prove/ directories scattered under examples/*/ are not part of experiments/. They're per-example Z3 proofs sized
  to the article's teaching beat. Each is its own micro-module. The big experiments/z3-solver/ is the systemic version of
  what those per-example provers do — wholesale, across all controls, with shadow-mode validation against the CEL engine.

  - examples/ = "here's Stave doing X, run it." Ships in articles, tied to releases.
  - experiments/ = "here's research toward what Stave might be." Lives outside the main module so it can fail without
  blocking releases.
