# 21 IAM Privesc Methods → 5 Z3 Patterns

## Prerequisites

This example's `z3prove/` binary links against libz3 via CGO.
Install the development headers before running:

| OS | Command |
|---|---|
| Ubuntu 22.04 / 24.04 | `sudo apt-get install -y libz3-dev pkg-config` |
| macOS (Homebrew) | `brew install z3 pkg-config` |

Then build with `CGO_ENABLED=1 go run .` from inside `z3prove/`.
The Stave binary itself has no libz3 dependency; only the
per-example Z3 prover does. See [`../PREREQUISITES.md`](../PREREQUISITES.md)
for other platforms (Fedora, Arch, nix, Debian) and for the
prerequisites of the SMT CLI / Soufflé / Prolog / Python-venv
examples.

## What this demonstrates

Rhino Security Labs published the canonical reference for
AWS IAM privilege escalation in 2018 (Spencer Gietzen): 21
methods, each a specific action or action combination,
each a manual enumeration. Every checklist scanner —
PMapper, Pacu, Prowler, Stave's own per-technique
catalogue — turned that list into 21 individual checks.

This iteration recasts the 21 methods as **5 structural
patterns** and runs one Z3 query per pattern. The query
asks: "is there any method in this pattern's registry
whose actions are all effectively allowed for this
principal?" SAT means at least one method is reachable;
the model returns the witness.

## The headline numbers

| Metric | Count |
|---|---|
| Rhino's manual enumeration | 21 methods |
| Z3 structural queries | 5 |
| Methods reachable on rhino-vulnerable fixture | **50** |
| Rhino's 21 found by Z3 | **21 of 21** |
| Additional methods Z3 found beyond Rhino | **27** |
| Methods STILL reachable after blocking all 21 Rhino actions | **24** |
| Methods reachable on remediated (least-privilege) fixture | 0 |

The third row is the meta-finding. A defender who reads
Rhino's research, writes a deny policy listing all 21
actions, and ships it — that defender's principal can
still execute **24 escalation paths** Rhino didn't
enumerate. The deny-list approach is mathematically
insufficient against the structural pattern.

## The five patterns

| # | Name | Rhino methods | Total in registry |
|---|---|---|---|
| 1 | Policy Self-Mutation | 1, 2, 7-13 (9 methods) | 13 |
| 2 | Credential Creation / Theft | 4, 5, 6, 14 (4 methods) | 7 |
| 3 | Compute + PassRole | 3, 15-21 (8 methods) | 17 |
| 4 | Indirect Compute Invocation | 16 (1 method) | 10 |
| 5 | Role Trust Modification | 14 (1 method) | 3 |

Methods 14 and 16 each appear in two patterns (14:
Pattern 2 + Pattern 5; 16: Pattern 3 + Pattern 4). The
"Rhino's 21 hit" count uses a set, so each Rhino method
is counted once even when it satisfies multiple
patterns.

## Three fixtures

- **rhino-vulnerable** — a principal with permissions
 enabling every method across every pattern. The
 worst-case "data scientist" or "developer" role that
 accumulated permissions over time.

- **partial-deny** — same principal, plus an explicit
 Deny statement listing all 21 Rhino actions. This is
 the "informed defender" baseline. Z3 still finds 24
 reachable methods.

- **remediated** — least-privilege: scoped `iam:PassRole`
 on one role ARN, no self-mutation actions, no
 credential-modification actions. All 5 Z3 patterns
 return UNSAT.

## CEL side — `main.go`

Scoped to one of Stave's 44+ per-technique escalation
controls (`CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001`).
The control fires on rhino-vulnerable AND partial-deny
(the autoscaling chain remains open after the Rhino
actions are denied), and is silent on remediated. This
is the foil: the CEL approach catches *one method per
control*. Even with 44 controls, that's 44 individual
predicates against a growing universe of techniques.

Run from `stave/`:

```bash
go run ./examples/iam-21-privesc-5-patterns
```

## Z3 prover — `z3prove/`

Five queries × three fixtures = fifteen verdicts plus
per-fixture summary lines.

```bash
cd stave/examples/iam-21-privesc-5-patterns/z3prove
go mod tidy
CGO_ENABLED=1 go run .
```

The cross-pattern summary on the writeup config:

```
--- Cross-pattern summary ---
 registry total: 50 methods across 5 patterns
 reachable: 50 methods
 Rhino's 21 hit: 21 / 21
 Rhino IDs hit: [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21]
 beyond Rhino: 27 methods (cross-pattern, with overlaps)
 collapse: 21 manual enumerations → 5 Z3 queries
 → 50 methods reachable
```

The cross-pattern summary on partial-deny:

```
 registry total: 50 methods across 5 patterns
 reachable: 24 methods
 Rhino's 21 hit: 1 / 21
 Rhino IDs hit: [16]
 beyond Rhino: 23 methods (cross-pattern, with overlaps)
 collapse: 21 manual enumerations → 5 Z3 queries
```

The deny blocks 20 of Rhino's 21 (Rhino 16's
`dynamodb:PutItem` is the one Rhino-numbered method
that survives because it's an indirect-invoke action
the writeup didn't deny). 23 of the 27 non-Rhino
methods remain. Net: 24 reachable methods.

The cross-pattern summary on remediated:

```
 reachable: 0 methods
 Rhino's 21 hit: 0 / 21
 beyond Rhino: 0 methods
```

Least-privilege closes everything.

## What each pattern's encoding does

Each pattern is a Go function that walks its method
registry, computes for each method whether all required
actions are effectively allowed (in some Allow, not in
any Deny), and adds a service-trust check for compute-
launch patterns.

The Z3 step is structural: the indices of the reachable
methods form a finite witness set. The solver discharges
"there exists a satisfying index" — SAT iff the witness
set is non-empty. This is a cosmetic use of Z3 for the
demo (a `len(reachable) > 0` check would do); the
*shape* is what matters. The SAT formulation is what
extends naturally as registries grow.

## Adding a new escalation method

When AWS launches a new compute service that supports
instance roles, the procedure is one struct entry in
`patterns.go`:

```go
{label: "<service>:<launch-action> + iam:PassRole",
 actions: []string{"<service>:<launch-action>", "iam:PassRole"},
 target: "compute_role",
 serviceTrust: "<service>.amazonaws.com"},
```

No new Z3 code. No new CEL predicate. No new control
YAML. The next run finds the new method automatically.
This is what the article means by "structural patterns
beat enumeration as the API surface grows."

## Layout

```
examples/iam-21-privesc-5-patterns/
├── README.md
├── main.go # CEL foil
├── controls/
│ └── CTL.IAM.ESCALATE.PASSROLE.AUTOSCALING.001.yaml
├── fixtures/
│ ├── rhino-vulnerable/observations/{T1,T2}.json
│ ├── partial-deny/observations/{T1,T2}.json
│ └── remediated/observations/{T1,T2}.json
├── z3prove/
│ ├── go.mod
│ ├── patterns.go # 5 method registries
│ └── main.go # 5 queries × 3 configs + summary
└── expected/
 ├── cel-output.txt
 └── z3-output.txt
```

## Source

"AWS Privilege Escalation Methods" — Rhino Security
Labs, 2018, by Spencer Gietzen. The canonical IAM
privesc reference, cited by every AWS security tool.
The 21 methods listed in this iteration's registries
match the original numbering.

## Where this fits

The
climactic example. Three notable structural beats:

- **Pattern collapse**: 21 manual enumerations → 5
 structural queries, with mathematically equivalent
 coverage of the original list plus extension to
 methods Rhino didn't enumerate.

- **Deny-list refutation**: a Deny policy that blocks
 every Rhino action still leaves 24 methods open. The
 partial-deny fixture is the formal counterexample.

- **The stat for the talk**: *Rhino found 21. Z3 found
 50. 24 of those still work after blocking everything
 Rhino listed.* That's six sentences, two numbers, and
 a refutation of the dominant industry approach to
 IAM privesc prevention.

The cumulative encoder template now spans IAM identity
policies (this example family), bucket policies (this example, 2,
11), KMS key policies, API Gateway resource
policies, Allow-and-Deny effective-permission
resolution with `iam:PassedToService`,
cross-service data-flow conjunctions, and
**registry-based exhaustive method enumeration** (this
extension — extending this example's compute-launch idea to all
five Rhino patterns).
