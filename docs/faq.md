---
title: "FAQ"
sidebar_label: "FAQ"
sidebar_position: 3
description: "Frequently asked questions about Stave's approach, terminology, and how it differs from existing tools."
---

# FAQ

## Why does Stave use "unsafe state" instead of "vulnerability" or "misconfiguration"?

Stave borrows from **systems safety engineering** (IEC 61508, DO-178C), not from the security vulnerability lexicon.

| Concept | Security terminology | Safety engineering terminology | Stave uses |
|---------|---------------------|-------------------------------|------------|
| A bad condition | Vulnerability, misconfiguration | Unsafe state | **Unsafe state** |
| A rule to check | Policy, rule, check | Safety invariant, control | **Control** |
| A detected problem | Alert, violation, issue | Finding, deviation | **Finding** |
| How long the problem persists | — (rarely tracked) | Unsafe duration, exposure window | **Unsafe duration** |
| Proof of the problem | Evidence (forensics) | Evidence (safety case) | **Evidence** |

**Why this matters:** security engineers are familiar with terms like "insecure configuration," "vulnerability," and "misconfiguration." Stave deliberately does not use these terms. Instead, it expresses the same concepts as "unsafe state," "unsafe duration," and "finding" — because Stave borrows its principles from mature engineering disciplines (aviation, aeronautics, systems safety) that have decades of rigorous methodology for proving system safety, but have no equivalent products in the cybersecurity domain.

No existing security tool applies safety engineering rigor to infrastructure configuration. CSPM tools detect misconfigurations but don't track duration, don't produce deterministic proofs, and don't work offline. IaC scanners check templates but not observed state. Policy engines make runtime decisions but don't evaluate historical evidence. Stave brings the safety engineering approach — state-based reasoning, duration tracking, deterministic proof, offline evaluation — to a domain that has never had it:

- **State-based reasoning** — Stave evaluates whether observed state satisfies a control, not whether a known CVE applies.
- **Duration tracking** — safety engineering cares about *how long* a system remains in an unsafe state, not just that it entered one. A bucket that was public for 5 minutes during a deploy is different from one that has been public for 6 months.
- **Deterministic proof** — same inputs always produce the same findings. This is a safety case requirement, not a typical security scanner feature.
- **Offline evaluation** — safety cases are evaluated against recorded evidence, not live systems. Stave works the same way.

The terminology reflects the origin. "Unsafe state" is not a synonym for "insecure configuration" — it carries the safety engineering semantics of state tracking, duration measurement, and provable assertion that the security term does not.

## What is "System Invariant as Code"?

A system invariant is a property that must always hold true for your infrastructure. "As Code" means you define these invariants as version-controlled YAML files and evaluate them programmatically.

Example invariant: "PHI buckets are never publicly readable."

This is different from:

- **Policy-as-Code** (OPA, Sentinel) — evaluates policy decisions at request time. Stave evaluates invariants over historical snapshots.
- **Infrastructure-as-Code scanning** (tfsec, Checkov) — checks templates before deployment. Stave checks actual observed configurations after deployment.
- **CSPM** (Wiz, Prisma, AWS Config) — continuously monitors live cloud APIs. Stave evaluates offline, with no credentials.

See [System Invariant as Code](https://www.systeminvariant.dev/docs/explanation/system-invariant-as-code) for the formal model.

## How does System Invariant as Code differ from OPA Rego and other policy engines?

The paradigm is different. OPA, Sentinel, and similar tools are **policy decision engines** — they answer "is this request allowed?" at a point in time, typically at an admission gate or CI step. Stave is a **safety evaluation engine** — it answers "does observed infrastructure state satisfy declared invariants, and for how long has it been unsafe?"

| | OPA / Rego | Stave |
|---|---|---|
| Input | Structured request or document | Timestamped observation snapshots |
| Evaluation model | Policy decision (allow/deny) | Invariant proof (safe/unsafe + duration) |
| Language | Rego (general-purpose logic) | YAML predicates (`ctrl.v1` schema) |
| Time awareness | Single point in time | Multi-snapshot duration tracking |
| Primary use | Admission control, CI gates | Offline audit, safety evidence, preflight |
| Output | Decision (boolean + reason) | Findings with evidence and remediation |

Stave's YAML controls are intentionally narrower than a general-purpose language like Rego. This is a deliberate trade-off: controls are constrained to a closed set of predicate operators (`eq`, `ne`, `in`, `missing`, `any_match`, etc.) so they can be statically analyzed, validated by JSON Schema, and evaluated deterministically without an interpreter. You cannot write arbitrary logic — only declare invariants the engine knows how to prove.

The two approaches are complementary. Use OPA for runtime policy decisions and admission control. Use Stave for offline, deterministic safety proofs over historical snapshots.

## Why "control" and not "rule" or "policy"?

Externally, Stave uses the new paradigm name **System Invariant as Code** — invariants are the formal concept. Internally, the codebase uses the term **control** (as in `ctrl.v1`, `CTL.S3.PUBLIC.001`) to align with NIST SP 800-53 and ISO 27001, where a control is a safeguard that reduces risk.

This is a deliberate choice to make the codebase accessible to security researchers and auditors who review it. Someone auditing Stave's control definitions should find familiar terminology — controls, findings, evidence — mapped to established security frameworks, not abstract formal language.

"Rule" is ambiguous (firewall rule? linting rule?). "Policy" implies runtime enforcement. "Control" is precise: a declarative assertion evaluated against evidence, which is exactly what each `ctrl.v1` YAML file defines.

## Why is there a semantic gap between the domain and the code?

In domain-driven design, you aim for zero semantic gap — the code should use the same language as the domain. Stave's domain is **System Invariant as Code**, so ideally the codebase would use "invariant" everywhere: `invariant.v1` schema, `INV.S3.PUBLIC.001` identifiers, `--invariants` flag.

We deliberately deviate from this ideal. The codebase uses "control" (`ctrl.v1`, `CTL.`, `--controls`) instead of "invariant." This is a conscious trade-off between two audiences:

| Audience | Preferred term | Why |
|----------|---------------|-----|
| Domain theory / formal methods | Invariant | Precise formal meaning: a property that must always hold |
| Security researchers / auditors | Control | Industry-standard term (NIST, ISO 27001) they already know |

We chose the security audience. Stave is a security tool, and the people who review its control definitions, audit its findings, and evaluate its codebase are security practitioners. If they open `controls/s3/CTL.S3.PUBLIC.001.yaml` and see a control with a finding and evidence, they know exactly what they are looking at. If they saw `invariants/s3/INV.S3.PUBLIC.001.yaml` with an "invariant violation," they would need to learn a new vocabulary to do the same review.

The paradigm name — System Invariant as Code — stays as-is in external documentation, talks, and comparisons. It accurately describes what Stave does and positions it in a category distinct from Policy-as-Code or IaC scanning. The codebase implements that paradigm using terminology that security professionals already understand.

This is the one place where we knowingly accept a semantic gap. It is documented here so future contributors understand the choice was intentional, not an oversight.

## Why does Stave need two snapshots?

One snapshot tells you the current state. Two snapshots (or more) let Stave calculate **how long** an asset has been unsafe.

A control with `type: unsafe_duration` and `--max-unsafe 168h` means: "this asset must not remain in an unsafe state for more than 7 days." To evaluate that, Stave needs at least two points in time to measure the duration window.

Controls with `type: unsafe_state` only need one snapshot — they check current state regardless of duration.

## Why does Stave work offline with no credentials?

Three reasons:

1. **Air-gapped environments** — security review and audit often happen in isolated networks where cloud API access is unavailable or prohibited.
2. **Deterministic replay** — the same snapshot files produce the same findings on any machine, any time. Live API queries introduce non-determinism (state changes, API throttling, clock differences).
3. **Separation of concerns** — calling cloud APIs to collect data is a different problem from evaluating safety invariants. Collection stays external (your tools, your credentials); Stave handles evaluation and ships a built-in converter, `stave transform` (jq filters), that reshapes raw snapshots into `obs.v0.1`. For data sources beyond the built-in filters you can still write an external extractor — see [Building an Extractor](extractor-prompt.md).

## How is "evidence" different from "observation"?

**Observations** are raw input — point-in-time snapshots of infrastructure state (`obs.v0.1` JSON files). They contain everything captured, whether relevant or not.

**Evidence** is output — the specific subset of observation data that proves a particular finding. When Stave detects a violation, it attaches the relevant property values, timestamps, and duration calculations as evidence.

Observations are what you feed in. Evidence is what Stave produces to support each finding.

## What S3 blind spots does Stave detect that AWS Trusted Advisor misses?

AWS Trusted Advisor checks whether S3 buckets are publicly accessible. Stave evaluates 43 controls that go deeper — detecting risks that Trusted Advisor cannot see because of how it collects data and what it checks.

### 1. Policy-denied scanning (the Fog Security bypass)

In August 2025, [Fog Security disclosed](https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets) that an attacker with AWS access can add a bucket policy denying `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`, and `s3:GetPublicAccessBlock` to the Trusted Advisor scanning role. The bucket can be fully public, but Trusted Advisor reports green — "no problems detected" — because it cannot read the policy. AWS [patched this](https://www.securityweek.com/aws-trusted-advisor-tricked-into-showing-unprotected-s3-buckets-as-secure/) to show a "Warn" status, but the underlying issue remains: if the scanner is denied access, it cannot prove safety.

Stave handles this via **`CTL.S3.INCOMPLETE.001`** — if required fields are missing from the observation (because the scanning role was denied access), the bucket is flagged as unsafe. Missing data is not safe data.

### 2. Latent public exposure behind Public Access Block

A bucket with Public Access Block (PAB) enabled may have an underlying policy granting `Principal: "*"`. Trusted Advisor reports it as safe because PAB prevents public access at the API level. But removing PAB — one toggle — immediately makes the bucket public.

Stave detects this via **`CTL.S3.PUBLIC.005`** — latent exposure is a finding even when masked by a compensating control.

### 3. ACL escalation paths

A bucket ACL may grant `WRITE_ACP` to public or authenticated users. This allows anyone to call `PutBucketAcl` and grant themselves `FULL_CONTROL`, then read or modify every object. Trusted Advisor checks whether a bucket is publicly readable — it does not check whether the public can modify the ACL itself.

Stave detects this via **`CTL.S3.ACL.ESCALATION.001`**.

### Detection comparison

| Blind spot | Trusted Advisor | Stave |
|---|---|---|
| Policy denies scanning role access | Reports green (or "Warn" post-patch) | `CTL.S3.INCOMPLETE.001` — flags missing data as unsafe |
| Latent exposure behind PAB | Reports safe (PAB is on) | `CTL.S3.PUBLIC.005` — flags underlying public policy |
| ACL escalation (WRITE_ACP) | Not checked | `CTL.S3.ACL.ESCALATION.001` — flags privilege escalation path |
| Unsafe duration tracking | Not tracked | All controls track how long a bucket has been unsafe |
| Cross-account policy grants | Limited checks | `CTL.S3.ACCESS.001` — flags unauthorized cross-account access |
| Authenticated-users group grants | Not distinguished from public | `CTL.S3.AUTH.READ.001`, `CTL.S3.AUTH.WRITE.001` — separate controls |

References:
- [Fog Security: Mistrusted Advisor — Evading Detection with Public S3 Buckets](https://www.fogsecurity.io/blog/mistrusted-advisor-public-s3-buckets)
- [SecurityWeek: AWS Trusted Advisor Tricked Into Showing Unprotected S3 Buckets as Secure](https://www.securityweek.com/aws-trusted-advisor-tricked-into-showing-unprotected-s3-buckets-as-secure/)
- [CheckRed: AWS Bypass — Misconfigurations Still Threaten Cloud Security](https://checkred.com/resources/blog/when-secure-isnt-what-the-trusted-advisor-s3-bypass-reveals-about-aws-misconfigurations/)

## How does Stave keep developer-only commands out of production?

Stave has **no destructive commands** — every command reads observation
snapshots and writes findings; nothing modifies or deletes infrastructure.
There is no "accidental destruction" for Stave to cause.

A few commands are **developer-workflow** tools, though, that have no place
in a production environment:

- `generate` — scaffolds starter artifacts (project/observation templates).
- `forge` — authors and tests custom controls.

These are tagged **dev-only** in the CLI (a Cobra annotation,
`cmdutil.AnnotationDevOnly`, on the command). Before any command runs, the
bootstrap guard checks two things:

1. **Is the command dev-only?** The check walks the command's ancestry, so
   tagging `forge` or `generate` automatically covers every subcommand
   (`forge new`, `generate observation`, …).
2. **Is this a production environment?** Detected via `STAVE_ENV=production`,
   or an active context with `production: true`:

   ```yaml
   contexts:
     prod-us-east:
       project_root: /ops/stave
       production: true
   ```

If both are true, the command is **rejected** with a clear error and a
non-zero exit code:

```bash
export STAVE_ENV=production
stave forge new        # error: command "new" is development-only and cannot run in production
stave apply ...        # runs normally — not a dev-only command
```

The dev-only set is declared **in code**, not via config — there is no
`blocked_commands` list to set or keep in sync. Marking a new command
dev-only is one annotation: `cmdutil.AnnotationDevOnly: "true"`.

## Why are there two binaries (`stave` and `stave-dev`)?

Both binaries contain **identical commands**. Every command — `apply`, `diagnose`, `trace`, `controls`, `lint`, `inspect`, `doctor`, `snapshot diff` — ships in both.

The only difference is the **edition label**:

| | `stave` | `stave-dev` |
|---|---|---|
| Edition | `production` | `dev` |
| `--version` output | `0.0.3 (production)` | `0.0.3 (dev)` |
| Panic recovery message | Suggests `doctor` | Suggests `bug-report` |

The edition is a **build-time diagnostic label** — it fixes what `--version`
and crash hints report, so there is no runtime `--dev` flag to accidentally
set in a CI script. It is *not* a safety toggle: the development-only command
guard (see above) is keyed on the production environment, not on the edition,
so **both** binaries reject `forge` / `generate` in production.

**When to use which:**

- **`stave`** — standard deployment for CI pipelines, production evaluation, and automated workflows.
- **`stave-dev`** — developer machines; its `--version` and crash hints point at developer tooling.

## Why is there an OSCAL control in core *and* an `oscal-gaps` command in stave-coverage?

They answer two different questions about OSCAL, so they live in two
different places. The shared word "OSCAL" is just the input format.

`CTL.COMPLIANCE.OSCAL.REPORT.CURRENT.001` (core catalog) is a runtime
invariant over a **customer's snapshot**. It asks: *"Is the SOC report this
account relies on present, unexpired (≤ 12 months past its coverage period),
and in scope for the snapshot's region?"* It evaluates a derived
`oscal_report` asset during `stave apply` and emits a finding — exactly what a
control is, so it lives in the catalog with every other control.

`stave-coverage oscal-gaps` never looks at a customer snapshot. It asks a
**meta question about the catalog itself**: *"Of the customer- and
shared-responsibility SOC 2 criteria AWS lists in its OSCAL report, which ones
does the Stave catalog have no control for?"* That is catalog-coverage
analysis, which is the entire reason `stave-coverage` exists as a separate
tool — coverage logic never lives in core.

| | Core control | `oscal-gaps` |
|---|---|---|
| Input | one account snapshot | the OSCAL report + the whole catalog |
| Question | *is my evidence fresh & in scope?* | *does our rulebook cover what AWS says is my job?* |
| Output | a finding in `stave apply` | a gap list (criteria with zero controls) |
| Runs against | customer infrastructure | Stave's own catalog |

No shared code (separate Go modules), no overlapping logic. The control is the
shippable customer-facing invariant; `oscal-gaps` is an internal
catalog-completeness tool that stands beside it.

## What is the output contract schema (`out.v0.1`)?

Every `stave apply` command produces JSON conforming to the `out.v0.1` schema. This is a stable machine-readable contract that downstream tools — CI pipelines, dashboards, SIEM integrations, custom scripts — can rely on.

The schema defines two output kinds:

- **`evaluation`** (`stave apply`) — findings from running controls against observations
- **`verification`** (`stave check`) — before/after comparison showing resolved, remaining, and introduced findings

### Evaluation output structure

| Field | Description |
|-------|-------------|
| `run` | Reproducibility metadata: tool version, `--eval-time`, `--max-unsafe`, snapshot count, input file hashes |
| `summary` | Aggregate counts: `assets_evaluated`, `attack_surface` (currently unsafe), `violations` (exceeded threshold) |
| `findings[]` | Each violation with control ID, asset ID, evidence (timestamps, duration, misconfigurations), and remediation guidance |
| `exempted_assets[]` | Assets skipped by exemption rules (with matched pattern and reason) |
| `excepted_findings[]` | Findings suppressed by exception rules — still evaluated, but partitioned out of the violation count |
| `remediation_groups[]` | Findings clustered by shared fix plan per asset |
| `skipped[]` | Controls that could not be evaluated (e.g., missing asset types) |
| `extensions` | Control source metadata, enabled packs, resolved control IDs |

### Design decisions

- **Exemptions vs exceptions** — Exemptions skip entire assets before evaluation. Exceptions suppress specific control+asset findings after evaluation. Excepted findings appear in `excepted_findings`, not `findings`, so nothing is silently dropped.
- **Input hashes** — SHA-256 hashes of every input file are included in `run.input_hashes` for audit reproducibility. Given the same files, the same output is produced.
- **Remediation groups** — When multiple findings on the same asset share a fix plan, they are grouped together so the operator sees one remediation action, not redundant steps.

### Accessing the output

```bash
# JSON output for piping to jq or other tools
stave apply --observations observations --format json

# Extract just the finding control IDs
stave apply --observations observations --format json | jq '[.findings[].control_id]'

# Count violations
stave apply --observations observations --format json | jq '.summary.violations'
```

Full field-by-field reference: [Output Schema (out.v0.1)](https://www.systeminvariant.dev/docs/reference/schema-out)

JSON Schema source: `schemas/output/v1/output.schema.json`

## What does Stave *not* do?

- **No live scanning** — it does not query cloud APIs during evaluation.
- **No auto-remediation** — it produces findings and fix guidance, not infrastructure changes.
- **No plugin execution** — it does not run arbitrary code, scripts, or third-party plugins.
- **No runtime agents** — nothing is deployed into your infrastructure.

Stave is a pure function: files in, findings out.

## Are all controls YAML or are some implemented in Go?

All 2,674 controls are declarative YAML. Zero controls are implemented as Go functions.

Every control is a YAML file with an `unsafe_predicate` evaluated by the CEL engine. Adding a new control means writing a YAML file — no Go code, no compilation, no engine changes.

Compliance profiles (HIPAA, CIS, SOC 2, PCI-DSS, NIST, FedRAMP, GDPR, FFIEC, ISO 27001, NIST CSF) are implemented as compliance tags on existing YAML controls, filtered by `--profile`. The engine doesn't know which framework is being evaluated — it evaluates the same predicates and attaches the compliance requirement IDs to the findings.

Compound risk detection, duration tracking, severity grouping, and compliance citations are features of the evaluation engine, not separate control implementations. They work across all YAML controls automatically.

## Google CEL Library

For the predicate engine that is mostly using google cel library, is it possible to open a PR that moves that functionality to it? Is it appropriate to ask the library maintainer to implement it (is it in their scope and generic enough?)                                                                               
No, it's not appropriate. Stave's CEL usage is domain-specific — it evaluates unsafe_predicate YAML structures (with all/any/field/op/value nodes) against asset property maps. This is a DSL built on top of CEL, not CEL itself.
                                                  
What stave does:
                                                  
1. Parses ctrl.v1 YAML predicates into an internal UnsafePredicate tree
2. Translates field ops (eq, ne, in, missing, present, not_subset_of_field) into CEL expressions
3. Compiles the CEL expression against asset properties
4. Evaluates with the CEL runtime

The google/cel-go library provides steps 3 and 4 — the expression compiler and runtime. Steps 1 and 2 are stave-specific domain logic that wouldn't belong in the CEL library because:

- The unsafe_predicate YAML schema is stave's invention, not a CEL concept
- The field operator set (eq, ne, missing, present, not_subset_of_field) is stave's domain language
- The translation from YAML tree → CEL expression string is stave's compiler, not a general-purpose tool
- The AssetEvalContext that maps properties.storage.encryption.enabled paths to CEL variables is stave's binding layer

The CEL library maintainers' scope is the CEL specification — a general-purpose expression language. They wouldn't accept a YAML-to-CEL translator for infrastructure control predicates. That's application logic.

What could be contributed upstream (if it doesn't already exist) would be generic CEL utilities like custom type adapters or extension functions. But stave's current usage of cel-go is standard — it creates programs, registers variables, and evaluates. Nothing is missing from the library.

How does the CI/CD workflow for stave work? Where is the snapshots stored?                                            
                                                                             
Stave's CI/CD integration works as a gatekeeper on locally stored snapshots — no cloud calls during evaluation.                                                

How it works:                                                                                                       
   
  1. A collector (external to stave) calls AWS APIs to capture raw snapshots; `stave transform` converts them to obs.v0.1 JSON (or an external extractor emits obs.v0.1 directly)
  2. Those JSON files are committed to the repo or stored as CI artifacts alongside the infrastructure code
  3. stave apply evaluates them in the pipeline — same as running locally

  Where snapshots are stored — it depends on the workflow:

  Option A: Committed to the repo (simplest)
  my-infra-repo/
    observations/
      2026-03-28T000000Z.json
      2026-03-29T000000Z.json
    controls/         # or use built-in packs
    stave.yaml
  The pipeline runs stave apply --observations observations/ on every PR. Snapshots are versioned with the code.

  Option B: CI artifact from a prior step
  A scheduled job runs the extractor, produces snapshots, and uploads them as artifacts. A downstream job downloads them
   and runs stave apply.

  Option C: Mounted volume in Docker
  The extractor writes to a directory, the stave container mounts it:
  docker run --rm -v $(pwd)/snapshots:/work/observations stave-tutorials \
    stave apply --observations observations --max-unsafe 7d --format json

  Stave itself never stores snapshots. It reads from a directory, evaluates, and writes findings to stdout. Where the
  snapshots live is the user's choice — repo, artifact store, S3, local disk.

  The CI workflow in stave-guide/how-to/ci-cd-integration.md documents all the patterns: GitHub Actions (build from
  source or Docker), GitLab CI, baseline tracking, SARIF upload, and gating.

## What is the purpose of now flag in apply command?

--eval-time overrides the current time used to calculate unsafe durations. Stave computes how long an asset has been in an unsafe state by measuring from when the violation was first observed to "now." Without --eval-time, that's the real wall clock — which means the output changes every second, making it impossible to reproduce results or write golden tests. 
                    
With --eval-time 2026-01-15T00:00:00Z, the evaluation is frozen in time: the same inputs always produce the same findings, same durations, same safety status. This is essential for:              
                                                                  
  - Golden tests — commit expected output, diff byte-for-byte
  - CI reproducibility — same commit produces same result regardless of when CI runs
  - Demo scenarios — the Docker demo pins --eval-time so findings are stable
  - Verification — stave apply verify uses --eval-time to confirm deterministic output

## Which ones are validated using JSON schema?

output of stave schemas

Data Contracts:
  control       ctrl.v1
  observation   obs.v0.1
  output        out.v0.1

Diagnostic Contracts:
  diagnose   diagnose.v1
  diff       diff.v0.1

Command Output Contracts:
  baseline           baseline.v0.1
  ci_diff            ci_diff.v0.1
  enforce            enforce.v0.1
  fix_loop           fix_loop.v0.1
  gate               gate.v0.1
  snapshot_archive   snapshot_archive.v0.1
  snapshot_plan      snapshot_plan.v0.1
  snapshot_quality   snapshot_quality.v0.1
  validate           validate.v0.1

Artifact Contracts:
  bug_report                     bug-report.v0.1
  control_crosswalk_resolution   control-crosswalk-resolution.v1
  security_audit                 security-audit.v1
  security_audit_artifacts       security-audit-artifacts.v1
  security_audit_run_manifest    security-audit-run-manifest.v1

Validated with JSON Schema (4):                                                                                       
                                                                                                                        
  ┌─────────────┬─────────────────────────────────────────────────────────────────┐                                     
  │   Schema    │                       Validation Function                       │                                     
  ├─────────────┼─────────────────────────────────────────────────────────────────┤                                     
  │ ctrl.v1     │ ValidateControlYAML() — control loader                          │                                     
  ├─────────────┼─────────────────────────────────────────────────────────────────┤                                     
  │ obs.v0.1    │ ValidateObservationJSON() — observation loader                  │                                     
  ├─────────────┼─────────────────────────────────────────────────────────────────┤                                     
  │ out.v0.1    │ ValidateEvaluation() / ValidateVerification() — safety envelope │                                     
  ├─────────────┼─────────────────────────────────────────────────────────────────┤                                     
  │ diagnose.v1 │ ValidateDiagnose() — safety envelope                            │
  └─────────────┴─────────────────────────────────────────────────────────────────┘

  Plus finding.v1 (internal, not in stave schemas output) — validated optionally in the finding writer.

  No JSON Schema (20):

  All command output contracts (baseline.v0.1, ci_diff.v0.1, enforce.v0.1, gate.v0.1, validate.v0.1, etc.), all artifact
   contracts (security-audit.v1, bug-report.v0.1, etc.), and diff.v0.1 exist only as version constants in
  kernel/schema.go. They're stamped into output JSON as schema_version fields but have no .schema.json file and no
  runtime validation.

  The validated schemas are the ones on the input boundary (control YAML, observation JSON) and the output contract
  (evaluation output, diagnose output) — the core data contracts that external tools and CI pipelines consume.

## How are the testscripts structured?

Stave uses [testscript](https://pkg.go.dev/github.com/rogpeppe/go-internal/testscript) (from `github.com/rogpeppe/go-internal`) for end-to-end CLI tests. The test harness lives in `cmd/stave/main_test.go`:

```go
func TestMain(m *testing.M) {
    testscript.Main(m, map[string]func(){
        "stave": staveMain,
    })
}

func TestScripts(t *testing.T) {
    testscript.Run(t, testscript.Params{
        Dir:                 "testdata/scripts",
        RequireExplicitExec: true,
    })
}
```

`TestMain` registers the `stave` binary as an in-process command via `testscript.Main`. This means each `.txtar` script can call `exec stave ...` and it runs the real CLI code in-process — no separate binary build needed, and coverage is collected.

`TestScripts` runs every `.txtar` file in `cmd/stave/testdata/scripts/`. Each script is a self-contained test scenario written in the [txtar format](https://pkg.go.dev/golang.org/x/tools/txtar): a sequence of shell-like commands followed by embedded files.

There are 21 scripts covering the full CLI surface:

| Script | What it tests |
|--------|---------------|
| `smoke.txtar` | Binary starts, `--version` works, `--help` produces output |
| `apply_pipeline.txtar` | Full `apply` workflow: load controls + observations, produce findings |
| `ci_workflow.txtar` | `ci baseline` and `ci diff` commands |
| `config_lifecycle.txtar` | `config get/set/show` commands |
| `controls_packs.txtar` | `controls list` and pack resolution |
| `determinism.txtar` | Same inputs + `--eval-time` produce identical output |
| `diagnose_trace_explain.txtar` | `diagnose`, `trace`, and `explain` commands |
| `doctor_bug_report.txtar` | `doctor` and `bug-report` commands |
| `exit_codes.txtar` | Exit code 0 (success), 3 (violations), 2 (input error) |
| `help_discovery.txtar` | Subcommand help text and flag documentation |
| `json_validity.txtar` | All JSON output is valid JSON |
| `lint_fmt_graph.txtar` | `lint`, `fmt`, and `graph` commands |
| `profile_builtin.txtar` | `apply --profile` with built-in controls |
| `quiet_verbose.txtar` | `--quiet` suppresses output, `-v` adds diagnostics |
| `report.txtar` | `report` command |
| `sanitize.txtar` | `--sanitize` redacts infrastructure identifiers |
| `sarif_output.txtar` | `--format sarif` produces valid SARIF v2.1.0 |
| `snapshot_commands.txtar` | `snapshot diff` subcommand surface |
| `snapshot_operations.txtar` | `snapshot diff` with real observation data |
| `streams.txtar` | stdout/stderr separation |
| `validate_lint_fmt.txtar` | `validate` command with lint and format checks |

To run them:

```bash
go test ./cmd/stave/ -run TestScripts -v
```

To run a single script:

```bash
go test ./cmd/stave/ -run TestScripts/smoke -v
```

These tests run as part of `make test` (which executes `go test ./...`). They are the primary integration test suite — each script exercises the real CLI binary against real control YAML and observation JSON files embedded in the `.txtar` archive.

## What is the Logic Trace (`--trace`)?

`stave apply --trace` records the evaluation engine's reasoning chain —
step-by-step decisions for every control × asset pair. It answers: *"Why did
the engine reach this verdict?"* It produces a `trace.v0.1` JSON with exemption
checks, predicate evaluations, threshold checks, and verdict decisions — the
evidence that builds trust in the **verdict**.

Example workflow:

```bash
stave apply --controls controls/s3 --observations obs/ \
  --max-unsafe 168h --trace audit_trace.json --format json > eval.json
```

For LLM-driven remediation, consume `eval.json` directly:
controls carry triage terms (defect, infection, failure) so the
findings are already self-explanatory.
