# Stave Terminology

The vocabulary Stave uses with users — in the CLI, the docs, the MCP
tool descriptions, and external articles. One word per concept.
Anything in this column should appear on every user-facing surface;
anything in the "deprecated" column should be replaced or escaped only
where a domain term genuinely requires it (see the exceptions below).

| Canonical | Replaces | Why |
|---|---|---|
| **control** | invariant, rule, check, policy, assertion | "Control" is the industry-standard term for one catalog entry. The CLI subcommand and the catalog use it; the user-facing docs and MCP descriptions follow. |
| **finding** | violation, failure, alert, issue | "Finding" is what an evaluation produces. Neutral — not every finding is a "violation" (state-assertion vs SLA-overdue vs at-risk). |
| **catalog** | rule set, policy set, control library | "Catalog" is the collection of controls and chains the engine evaluates against. |
| **evaluation** | scan, check, assessment, analysis | "Evaluation" is what Stave does. "Scan" implies setting-by-setting node inspection, the wrong unit of analysis. |
| **verdict** | result, outcome, status | The per-asset evaluation result: `COMPLIANT`, `AT_RISK`, `NON_COMPLIANT`. |
| **chain** | compound, multi-resource, attack path | The compound-risk pattern — a set of co-failing controls crossing a threshold. *Chain control*, *chain finding*. |
| **observation** | snapshot, state, configuration | The input data, schema `obs.v0.1`. (A *snapshot* of observations is fine when the temporal unit matters.) |

## Why "control" and not "invariant"

The two are not synonyms: a *control* is the catalog entry users
configure and read; an *invariant* is the formal property the control
encodes. Inside the engine and in research material, "invariant" is
the precise term and stays. On user-facing surfaces — help text, the
CLI, the MCP tool catalog, the how-tos — "control" is what users
already know from compliance and security tooling, and is what the
catalog actually contains.

## Migration

- `stave export-invariants` → **`stave export-controls`**. The old
  name is retained as a deprecated alias and prints a warning; it
  will be removed in v1.0.
- The solver-import JSON keeps its top-level `invariants` array — that
  shape is a data contract with external SMT/Z3 compilers, not a
  user-facing surface.

## Why "scanner" stays in user-facing docs

An audit of the user-facing surfaces found ~90 occurrences of
"scanner" / "scan". Every one of them is *correct* — none describe
Stave. They fall into six legitimate categories that must not be
renamed:

1. **Comparative framing** — the contrast that defines Stave's
   category: *"Scanners vs Risk Reasoners"* (README), *"Stave doesn't
   replace your scanner — it finds what your scanner structurally
   cannot"* (README, kms-concentration, secret-blast-radius,
   entitlement-entropy). The whole point of the sentence is the word
   "scanner."
2. **Defining what Stave is NOT** — *"Not a secret scanner"*, *"Not a
   vulnerability scanner"* (new-readme). Removing the word removes
   the disambiguation.
3. **Competitor-category names** — "CSPM scanners", "IaC scanners",
   "pattern-matching scanners" (differentiation, faq) — these are
   real industry categories with established names. Renaming would
   misname the competition.
4. **Third-party products** — "Trusted Advisor scanning role" (faq),
   "AWS Security Hub", "Wiz", "Orca", "Prowler" (differentiation) —
   these are the actual names of the tools.
5. **Attack-tool references** — *"exposed to internet scanners"*
   (controls/reference) means port-scanning attackers. Renaming would
   change the threat model description.
6. **Real CLI surface** — `stave bisect --mode scan` is a flag value
   (linear vs binary search strategy). Docs reference it accurately;
   renaming would require a CLI breaking change.

The terminology lint deliberately does **not** ban "scanner" — too
many true positives in the comparative positioning. If a future doc
describes Stave itself as a scanner, that's a copy-edit fix, not a
mechanical rename.

## Where "invariant" deliberately stays

- **Internal Go type and package names** (e.g. `InvariantExportConfig`,
  the `exportinvariants` package). Renaming them would churn imports
  without changing what a user sees.
- **Research and explanation docs** that define the concept itself —
  e.g. `docs/explanation/system-invariants.md`, the
  "invariants-as-code" articles. The reader is being taught what an
  invariant *is*; using "control" would obscure that.
- **Go-level invariant comments** ("invariant under our control, not a
  runtime condition") — that's the programming-language sense, not the
  product term.
- **The solver-import JSON contract** described above.

## Enforcement

A user-facing terminology check runs in CI (see the docs-drift
workflow). It scans `cmd/`, `docs/` (excluding `explanation/` and
`audits/`), `examples/*/README.md`, and `README.md`/`README.md.tmpl`
for the deprecated terms, and fails the build on hits outside the
exceptions above.

Linked from [`CONTRIBUTING.md`](./CONTRIBUTING.md).
