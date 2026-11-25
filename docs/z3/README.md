# How Stave Uses Z3

Stave uses the Z3 SMT solver for formal verification of cloud
configuration safety properties. Z3 integration serves two distinct
purposes: **policy reasoning** (CGO-linked, in-process) and **universal
property evaluation** (subprocess, no CGO required).

## Two Integration Modes

### 1. In-Process Z3 (CGO Build)

Build tag: `cgo,z3`. Requires `libz3` installed and
`go build -tags 'cgo z3'`.

Go binding: `github.com/aclements/go-z3/z3`.

**Pipeline:**

```
Observations + Controls
        │
        ▼
  stave.Apply()          ← CEL evaluation engine
        │
        ├── ExportPolicies()   → IAM/resource/KMS/trust policies
        ├── ExportGraph()      → asset relationships
        └── ExportInvariants() → control predicate trees
                │
                ▼
      compiler.Compile()       → CompiledModel (Z3 sorts, constants, assertions)
                │
                ▼
         queries.Query*()      → QueryResult (sat/unsat, witness, certificate)
```

**Entry point:** `pkg/stave/prove.go` → `Prove(ctx, ProveConfig)`.

**Compiler** (`internal/adapters/z3solver/compiler/`):
- Creates Z3 sorts for Principal, Action, Resource.
- Maps each IAM policy statement to Z3 boolean constraints
  (`PrincipalMatch ∧ ActionMatch ∧ ResourceMatch ∧ ConditionMatch`).
- Records trust edges (assume-role chains) and encryption edges (KMS).
- Compiles control invariants from predicate trees into Z3 formulas.

**Queries** (`internal/adapters/z3solver/queries/`):

| Query | Question | SAT means |
|-------|----------|-----------|
| `compatibility` | Can principal X perform action Y on resource Z? | Access is possible |
| `reachability` | Can principal X reach resource Y through role assumption chains? | Attack path exists |
| `conflict` | Do any Allow and Deny statements overlap? | Policy contradiction found |
| `choke-point` | What is the minimum set of statements to remove to break a reachability path? | Identified the fix |
| `invariant` | Is a control's unsafe condition reachable for ANY input? | Violation is possible |
| `shadow` | Is any Deny statement bypassed by a broader Allow? | Deny is ineffective |

**Proof certificates:** Every query can emit an SMT-LIB file
(`--certificate proof.smt2`) that is independently verifiable:
`z3 proof.smt2`. The certificate contains all assertions plus the
expected result.

**Stub build:** Without the `cgo,z3` build tags, `pkg/stave/prove_stub.go`
returns `errors.New("Z3 solver not available")`. The rest of Stave
(CEL evaluation, chains, SIR export) works without Z3.

### 2. Universal Property Evaluation (Subprocess)

No CGO required. Calls the `z3` binary on PATH.

**Pipeline:**

```
Observations
        │
        ▼
  LoadAssetsFromDir()
        │
        ▼
  GenerateGrounding()    ← asset properties → SMT-LIB assertions
        │                   (declare-const, assert predicates,
        │                    forall closure over known universe)
        ▼
  EvaluateAll()          ← for each *.smt2 formula:
        │                   1. Read formula template
        │                   2. Prepend grounding assertions
        │                   3. Write temp .smt2 file
        │                   4. Exec `z3 <file>`
        │                   5. Parse verdict: sat/unsat/unknown
        ▼
  UniversalSummary       ← per-universal results
```

**Entry point:** `pkg/stave/prove_universal.go` → `ProveUniversal(ctx, cfg)`.

**Universals** (U26–U33): cross-cutting security properties that must
hold across all assets of a given type.

| ID | Property |
|----|----------|
| U26 | Service-level logging enabled |
| U27 | Endpoint authentication required |
| U28 | Deletion protection enabled |
| U29 | Backup configured |
| U30 | No plaintext secrets in config |
| U31 | Version currency maintained |
| U32 | IMDSv2 enforced on compute |
| U33 | Required security services enabled |

**sat = violation** (a counterexample exists), **unsat = property holds**
(no assignment of the grounded universe violates the property).

**Grounding** (`internal/app/universals/grounding.go`): translates
observation assets into Z3 constants with predicate truth values, plus a
`forall` closure that bounds the universe to exactly the observed assets
(closed-world assumption at the asset level).

## SIR as Z3 Input Format

`stave export sir --format smt2` serializes the Stave Intermediate
Representation as SMT-LIB v2.

**Location:** `internal/core/sirfacts/facts.go` → `SerializeSMT2()`.

**Output structure:**

```smt2
; Stave SIR facts export — SMT-LIB v2
(set-logic ALL)

; --- Predicate declarations ---
(declare-fun has_encryption (String String) Bool)
(declare-fun public_access_enabled (String String) Bool)
...

; --- Facts ---
(assert (has_encryption "arn:aws:s3:::my-bucket" "AES256"))
(assert (not (public_access_enabled "arn:aws:s3:::my-bucket" "true")))
...

; --- Closed-world axioms (with --closed-world) ---
(assert (forall ((s String) (o String))
  (=> (has_encryption s o)
      (or (and (= s "arn:aws:s3:::my-bucket") (= o "AES256")) ...))))
```

**Modes:**
- **Open-world** (default): facts are asserted but not bounded. Suitable
  for targeted queries appended to the file.
- **Closed-world** (`--closed-world`): adds `forall` axioms per predicate
  so only the asserted tuples are true. Required for complete enumeration
  queries (Souffle, Clingo).

The SMT2 export is a **facts-only file**. Append your query before invoking
the solver: `cat sir.smt2 my-query.smt2 | z3 -in`.

## Z3 Proof Examples

The `examples/` directory contains 13 standalone Z3 proof scenarios in
`*/z3prove/` subdirectories. Each is a self-contained Go program that:

1. Builds a Z3 model from hand-crafted observations.
2. Asserts the security property under test.
3. Checks satisfiability and prints the witness or proof.

These validate Stave controls against real-world vulnerability patterns
(IAM privilege escalation, S3 cross-account replication, API Gateway
scoped deny, CloudTrail stop-logging, Cognito self-registration, etc.).

## Architecture

```
cmd/prove/           CLI entry point (stave prove)
pkg/stave/
  prove.go           Facade (CGO build) — loads, compiles, dispatches queries
  prove_stub.go      Stub (non-CGO build) — returns error
  prove_universal.go Facade — subprocess Z3 for universals
internal/
  adapters/z3solver/
    compiler/        Observation → Z3 model compilation
      compiler.go    CompiledModel: sorts, constants, statements
      conditions.go  IAM condition → Z3 boolean
      graph.go       Asset graph → reachability constraints
      invariant.go   Control predicate → Z3 formula
      policy.go      IAM statement → Z3 assertion
      scalars.go     Wildcard/glob → Z3 string matching
    queries/         Z3 model → sat/unsat verdicts
      compatibility  Can X do Y on Z?
      reachability   Can X reach Y via role chains?
      conflict       Allow ∧ Deny overlap?
      choke_point    Minimum fix to break a path
      invariant      ∀-verification of control predicates
      shadow         Deny bypassed by broader Allow?
  app/universals/    Subprocess Z3 for universal properties
    evaluate.go      Formula loading + Z3 invocation
    grounding.go     Asset → SMT-LIB constant generation
  core/sirfacts/
    facts.go         SerializeSMT2() — SIR → SMT-LIB export
```

## CLI Reference

```bash
# doctest:skip — requires CGO z3 build + observation fixtures
# In-process Z3 queries (requires CGO build)
stave prove -o observations --query compatibility \
  --principal arn:aws:iam::123:role/X --action s3:GetObject \
  --resource arn:aws:s3:::bucket

stave prove -o observations --query reachability \
  --principal arn:aws:iam::123:user/attacker \
  --resource arn:aws:s3:::sensitive

stave prove -o observations --query conflict
stave prove -o observations --query choke-point \
  --principal ... --resource ...
stave prove -o observations --query invariant --invariant CTL.S3.PUBLIC.001

# Proof certificate (independently verifiable)
stave prove -o observations --query compatibility \
  --principal ... --action ... --resource ... \
  --certificate proof.smt2
z3 proof.smt2  # verify independently

# Universal properties (no CGO, z3 binary on PATH)
stave prove -o observations --query universal \
  --formulas formulas/ --grounding-map grounding-map.yaml
```

```bash
# doctest:skip — requires observation fixtures
# SIR as SMT-LIB (facts for external solver)
stave export sir -o observations --format smt2
stave export sir -o observations --format smt2 --closed-world
```
