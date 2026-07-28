# The Stave Doctrine

Nine principles. Each one is **already in the code** — this file
describes what was built, not what we hope to build.

A doctrine names the **rejections**. Saying what something *is*
without naming what it *isn't* is marketing. Saying what it isn't
forces the boundary that makes the thing decidable. Every principle
below is *X over Y*: the over-Y is the rejection.

---

## 1. Combinations Over Settings

Breaches happen in *combinations* of settings, not at individual
settings. An IAM role that's correctly scoped, a security group that
allows metadata access, and an S3 bucket containing PHI are each
acceptable alone; together they're an exfiltration path. The unit of
analysis is the tuple, not the row.

**In the code:** [`chains/`](./chains/) holds 585+ compound-risk
chains alongside 2,650+ single-resource controls in
[`controls/`](./controls/). The same `apply` engine evaluates both —
a single-resource control is a chain of size 1. The chain
visualizer (`stave-mcp --render-chains`) renders each chain's
co-failing controls flowing into a compound-risk node.

---

## 2. Prevention Over Detection

Detection is what you do after the unsafe state forms; prevention is
what you do so it doesn't form. The unsafe state forms through drift
over time, and the cheapest place to stop it is the merge gate.

**In the code:** [`stave ci gate`](./docs/workflows/06-ci-pipeline-gate.md)
returns exit 3 when the policy fails — the unsafe state never
reaches production. Three real policies, not arbitrary thresholds:
`fail_on_new_violation` (block regressions), `fail_on_overdue_upcoming`
(block what's been unsafe too long), `fail_on_any_violation` (zero
tolerance). `--max-unsafe` is a *duration* because drift is
temporal, not a count.

---

## 3. Intent Over Opinion

The catalog is operator-authored. You decide what "unsafe" means for
your account. Stave does not ship a vendor opinion that you cannot
inspect, fork, or contradict.

**In the code:** [`controls/`](./controls/) is plain YAML. The
[`stave forge`](./cmd/forge/) command authors and tests new controls.
Every control carries an `intent_rationale` field that the engine
surfaces verbatim into output — the *why* travels with the *what*.
`stave apply --controls ./my-controls` evaluates against your fork.

---

## 4. Determinism Over Probability

Same inputs + same `--eval-time` → byte-identical output. Every run. This
is not a feature; it's the condition that lets the verdict be
*evidence* instead of a vendor's claim. An auditor can re-run a
snapshot and get the same result. Two commands can compose because
one's output is trustworthy as another's input.

**In the code:** the predicate engine is CEL, deterministic and
non-Turing-complete. Golden tests pin every fixture's output
byte-for-byte (`make regenerate-goldens` regenerates, categorizes the
diff, and refuses BEHAVIORAL drift silently). `--eval-time` lets CI fix the
clock. No ML in the evaluation path — a model can *draft* a control;
the catalog decides.

---

## 5. Your Machine Over Our Cloud

Evaluation runs where the snapshot lives. We do not require — or
accept — credentialed access to your cloud.

**In the code:** the [`stave apply`](./cmd/apply/) path makes zero
network calls; [`--require-offline`](./cmd/apply/) makes that an
*assertion* (it fails if proxy env vars are even set). The [MCP
server's `--hosted` mode](./cmd/mcp/README.md) is the strongest
form: the snapshot-touching tools are physically absent from the
tool list and rejected on direct call, so a hosted server can't
receive snapshot data even if asked. Air-gapped by architecture, not
by policy.

---

## 6. Contracts Over Integration

We don't write integrations. We publish contracts — `obs.v0.1` for
observations, `ctrl.v1` for controls, deterministic JSON for output
— and anything that emits or consumes them composes for free.
Steampipe, Pulumi, AWS CLI, your custom Python script, an agent: all
produce `obs.v0.1`. Stave consumes it. The catalog produces verdict
JSON. Anything reads it.

**In the code:** the schemas are at [`schemas/`](./schemas/);
[`docs/how-to/generate-snapshots/steampipe.md`](./docs/how-to/generate-snapshots/steampipe.md)
shows the mapping query. The CLI is a Unix tool: stdout, stderr,
exit codes 0/2/3/4. `stave apply --format json | stave ci gate
--policy fail_on_any_violation --in -` works because both sides
agreed on the schema, not the transport.

---

## 7. Convention Over Configuration

`stave apply` with no flags evaluates `./observations` against the
embedded catalog and writes text to stdout. Defaults that work for
the common case; every default swappable through the contract for
the uncommon one. Not "you must configure 14 fields before the tool
runs."

**In the code:** every flag has a sensible default
([`cmd/cmdutil/cliflags/flags.go`](./cmd/cmdutil/cliflags/flags.go)
documents the stable names). The embedded catalog is the default
`--controls`. `./chains` is the auto-discovered chains directory.
The chosen defaults match the project layout the Coder workspace,
the Docker image, and the DO 1-Click all ship with — convention
holds across every distribution channel.

---

## 8. The Catalog Is the Product

The engine is infrastructure: small, stable, and easy to reason
about. The catalog is what compounds. Every new control added is
permanent organizational knowledge — a class of mistake encoded once
that the gate then enforces forever, against every snapshot, in
every account, in every CI run, with no ML drift and no vendor
roadmap.

**In the code:** 2,907 controls + 622 chains today, growing with
every incident. The engine in [`pkg/stave/`](./pkg/stave/) exposes
~16 public functions ([`pkg/stave/doc.go`](./pkg/stave/doc.go)) —
small enough to fit in your head. The catalog growth is the value
delta release-to-release.

---

## 9. Honest About Scope

Two things done well: deterministic catalog evaluation, and
compound-risk detection. Everything else is *delegated*, not
"deferred for v2." Snapshot generation belongs to Steampipe and
friends. Continuous scheduling belongs to your orchestrator.
Remediation execution belongs to Terraform. Multi-account
orchestration belongs to a matrix CI job. We do not pretend
otherwise.

**In the code:**
[`features/scope.yaml`](./features/scope.yaml) is the versioned
out-of-scope manifest. The
[`TestFeaturesScopeManifest_NoForbiddenCommands`](./cmd/features_scope_lint_test.go)
test fails the build if any of the 13 deliberately-out-of-scope
capabilities (continuous monitoring, remediation planning, incident
forensics, external enrichment, multi-account orchestration, …)
re-enters via a CLI command. The scope is *enforced*, not just
documented. The narrowing pass that deleted `monitor`, `watch`,
`plan`, `rank`, `simulate`, `forensics`, `budget`, `enrich`,
`inventory`, `consolidate`, and `deadline` is what made the
remaining surface coherent enough to ship.

---

## The founding bet

> **Cloud security failures are caused by drift and can only be
> prevented by invariants.**

Everything above derives from this. If drift is the cause, then:

- detection arrives too late (#2 Prevention),
- the engine has to be cheap to re-run constantly (#4 Determinism,
  #7 Convention),
- the failure mode is *combinations*, not single settings (#1
  Combinations),
- the catalog is where the organizational learning lands (#8
  Catalog),
- the operator owns what counts as drift (#3 Intent),
- the evaluation must run where the snapshot is taken so it can
  gate the merge (#5 Your Machine, #6 Contracts),
- everything not in that loop is somebody else's job (#9 Scope).

The bet was made before the AI-agent wave, before MCP, before the
2026 vendor-native-framework gold rush. The market moved to
validate it. When you build on the right abstraction, the market
comes to you.

---

*A note on language: in user-facing surfaces — the CLI, docs, MCP
tool descriptions — Stave says **control** (the catalog entry the
operator authors and edits). In this document, where the rationale
is the point, it sometimes says **invariant** (the formal property
each control encodes).*
