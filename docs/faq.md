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

See [System Invariant as Code](system-invariant-as-code.md) for the formal model.

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
3. **Separation of concerns** — extracting data from cloud APIs is a different problem from evaluating safety invariants. Stave handles evaluation; external extractors handle extraction. See [Building an Extractor](extractor-prompt.md).

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

## Why does `verify` exist when `ci diff` already compares evaluations?

They answer different questions for different personas.

`verify` answers: **"did my specific fix work?"** An engineer remediates three bucket misconfigurations, re-runs `apply`, and needs to know: are those three findings gone, and did the fix introduce anything new? `verify` closes the remediation loop with a formal answer.

`ci diff` answers: **"did the overall security posture regress?"** A CI pipeline compares the current evaluation against an accepted baseline to detect new findings introduced by a code change or configuration drift.

| | `verify` | `ci diff` |
|---|---|---|
| Question | Did my remediation resolve the findings? | Did the posture regress since baseline? |
| Persona | Engineer who just fixed something | CI pipeline checking for regressions |
| Input | Before/after evaluation files from the same remediation cycle | Current evaluation vs accepted baseline |
| Cares about | Resolved findings | New findings |
| Typical exit | 0 (all resolved) | 3 (new findings detected) |

Without `verify`, the remediation workflow has no formal end. You find the problem with `apply`, fix it, re-run `apply`, and manually scan the output hoping you didn't miss anything. `verify` makes the fix provable:

```bash
stave apply ... -f json > before.json    # 3 findings
# fix the cloud config, retake snapshot
stave apply ... -f json > after.json     # 0 findings
stave verify --before before.json --after after.json
# Resolved: 3, New: 0, Unchanged: 0
```

This is also why `verify` is a production command and not dev-only — it's part of the operational remediation cycle, not a debugging tool.

## Why does `stave snapshot archive` exist when Unix has `mv`?

`stave snapshot archive` is not a file mover — it is a retention-aware lifecycle command that understands your project's snapshot policies. A plain `mv` knows nothing about observation files, retention tiers, or evaluation requirements.

| Capability | `mv` | `stave snapshot archive` |
|---|---|---|
| Retention policy | None — you decide what to move | Reads `--older-than` and `--retention-tier` from `stave.yaml` |
| Safety guard | None — will move everything you tell it to | `--keep-min` (default 2) prevents archiving below the minimum needed for duration evaluation |
| Dry-run default | No — acts immediately | Dry-run by default; requires `--force` to move files |
| Determinism | Depends on wall clock | `--now` flag pins the reference time for reproducible decisions in CI |
| Tier awareness | None | Pulls per-tier retention settings (e.g., `critical: 30d`, `non_critical: 14d`) from project config |
| Machine-readable output | None | `--format json` produces structured results for pipeline integration |

The equivalent Unix script would need to: parse each JSON filename as a timestamp, look up the retention tier config, compare against a policy, verify the remaining count stays above `keep_min`, preview the plan, then move — a non-trivial amount of logic that `stave snapshot archive` encapsulates in a single command with safety defaults.

The same reasoning applies to `stave snapshot prune` (delete instead of move) and `stave snapshot plan` (preview without acting). These commands exist because snapshot lifecycle management is a first-class concern in Stave's safety engineering model — observation history is evidence, and managing it carelessly can break duration calculations.

## Can snapshot pruning or archiving conflict with compliance?

Yes. Observation snapshots are evidence — they prove what state your infrastructure was in at a specific point in time. Deleting or relocating that evidence can conflict with regulatory retention mandates.

| Framework | Minimum retention | What it covers |
|---|---|---|
| HIPAA | 6 years | Records documenting PHI safeguards |
| SOX (Sarbanes-Oxley) | 7 years | Audit records for financial system controls |
| PCI-DSS | 1 year | Security event logs and access records |
| FedRAMP / NIST 800-53 | 3 years | System security evidence and audit trails |
| GDPR | Varies by purpose | Processing records (but also right-to-erasure tension) |

**Pruning is the higher risk.** It permanently deletes snapshots. If your `stave.yaml` sets `snapshot_retention: 30d` but your compliance framework requires 6 years of evidence, pruning destroys records you are legally required to keep.

**Archiving is safer** because the data is preserved, but the archive location must be documented and accessible to auditors. Moving files to a path that is not part of your audit trail can create gaps if an auditor asks for evidence from a specific date range.

**`keep_min` protects evaluation, not compliance.** The default `keep_min: 2` ensures Stave can still calculate unsafe duration. It does not ensure you retain enough snapshots to satisfy an audit. Two snapshots out of a year is fine for duration math but useless for proving continuous compliance.

**Recommendations for regulated environments:**

1. **Set retention to match your longest compliance mandate** — if you are subject to HIPAA and SOX, set `snapshot_retention: 2557d` (7 years), not `30d`.
2. **Use archive, not prune** — move aged snapshots to cold storage rather than deleting them. Configure `--archive-dir` to point to a durable, backed-up location.
3. **Never prune without legal review** — if you are subject to any retention mandate, treat `stave snapshot prune --force` as a destructive operation that requires the same approval as deleting database backups.
4. **Use retention tiers to separate concerns** — configure a `compliance` tier with long retention for regulated assets and a shorter `operational` tier for non-regulated ones.
5. **Document your archive location** — auditors need to know where evidence lives. If you archive to `s3://audit-archive/stave/`, document that path in your security plan.

Stave's snapshot lifecycle commands give you the tooling to manage retention. They do not make compliance decisions for you — your retention settings must reflect your regulatory obligations.

## How do I prevent `stave-dev` from being used against production?

Three layers of defense, used together:

**Layer 1: Environment variable (`STAVE_ENV`)**

Set `STAVE_ENV=production` in your production CI/CD runners and deployment environments. The dev binary checks this automatically:

- Read-only commands (doctor, trace, explain) print a warning but proceed — this allows break-glass debugging.
- Destructive commands (prune) are hard-blocked with an error.

```bash
export STAVE_ENV=production
stave-dev snapshot prune --force   # BLOCKED: "command 'prune' is blocked in production"
stave-dev doctor                   # WARNING, then runs (read-only)
stave apply ...                    # No guard — production binary is always safe
```

**Layer 2: Context metadata (`production: true`)**

Mark production contexts in your contexts config:

```yaml
contexts:
  prod-us-east:
    project_root: /ops/stave
    production: true
  dev-sandbox:
    project_root: /home/user/stave
    production: false
```

The dev binary reads the active context and applies the same guards as `STAVE_ENV`.

**Layer 3: IAM boundaries (the gold standard)**

The most robust defense is ensuring developer credentials cannot modify production data:

- The IAM role used by developers should have **read-only** access to production snapshot storage.
- Only the production service account (used by the `stave` binary in CI/CD) should have write/delete permissions on the production archive.
- This ensures that even if someone bypasses the CLI guards, the cloud layer blocks the operation.

| Environment | Binary | Credentials | Can read | Can write/delete |
|---|---|---|---|---|
| CI/CD pipeline | `stave` | Service account | Yes | Yes (archive only) |
| Developer laptop | `stave-dev` | Developer IAM role | Yes (break-glass) | No |
| Local sandbox | `stave-dev` | Sandbox credentials | Yes | Yes |

**When is it okay for `stave-dev` to read production data?**

Break-glass debugging. If a production evaluation fails and logs don't explain why, a senior engineer may need `stave-dev trace` or `stave-dev diagnose` against production snapshots to identify the exact predicate logic that failed. The read-only warning acknowledges this is happening without blocking it.

## Why is there a separate `stave-dev` binary?

The dev binary provides tools for **authoring, debugging, and inspecting** the control evaluation system itself — things an operator running evaluations in CI never needs.

**Control authoring** — `controls list`, `packs show`, `lint`, `fmt`, `graph`. You need these when writing new controls or modifying existing ones. A production pipeline consumes controls; it doesn't author them.

**Deep debugging** — `trace`, `prompt`. When a control produces an unexpected finding, `trace` walks you through the predicate evaluation step-by-step for a single asset. `prompt` generates an LLM-ready context from results. These are investigation tools, not operational ones.

**Security posture** — `security-audit`, `bug-report`. Security-audit generates SBOM, vulnerability scans, and compliance matrices for the tool itself. Bug-report collects a sanitized diagnostic bundle. Both produce artifacts about Stave, not about your infrastructure.

**Introspection** — `schemas`, `capabilities`, `version` (verbose), `doctor`. These answer "what does this build of Stave support?" — schema versions, source types, pack metadata, local environment readiness. Useful when onboarding, upgrading, or filing issues.

**Extractor development** — `extractor scaffold`, `extractor validate`. For building custom observation extractors for new source types beyond AWS S3.

**Productivity** — `alias`, `docs search`, `docs open`. Developer conveniences that have no place in an automated pipeline.

**Destructive maintenance** — `snapshot prune`. Permanently deletes observation snapshots. This is the only write-destructive dev command and is blocked from running against production environments.

**Why a separate binary instead of hidden flags or feature gates?** The separation is at the compile level. The production binary does not contain the code for these commands. There is no `--enable-dev` flag to discover, no environment variable to flip, no config to override. The attack surface, the help output, and the dependency tree are all smaller by construction. A compromised CI runner cannot use `stave` to delete evidence, exfiltrate diagnostics, or run extractors against production APIs — because those capabilities do not exist in the binary.

### Production binary (`stave`)

Runs evaluations safely. Cannot delete evidence, cannot introspect the tool itself, cannot author controls.

**Setup** — run once when starting a new project.

| Command | Purpose |
|---|---|
| `init` | Scaffold a new project |
| `generate` | Create starter controls and observations |
| `config` | Manage project settings, contexts, and environment variables |
| `status` | Show next recommended workflow step |

**Data preparation** — run before every evaluation.

| Command | Purpose |
|---|---|
| `validate` | Pre-flight check that inputs are well-formed |

**Evaluation** — the core loop: evaluate, understand, fix, confirm.

| Command | Purpose |
|---|---|
| `apply` | Run control evaluation (with `--dry-run` for readiness checks) |
| `diagnose` | Root-cause guidance when results are unexpected |
| `explain` | Show how a specific control evaluates |
| `verify` | Confirm a remediation resolved a finding |

**CI/CD** — automated pipeline gates and regression analysis.

| Command | Purpose |
|---|---|
| `ci baseline` | Save/check accepted findings baseline |
| `ci gate` | Pass/fail gate for pipelines |
| `ci diff` | Regression analysis between two evaluations |
| `ci fix` | Machine-readable fix plan for a finding |
| `ci fix-loop` | Apply-before, apply-after, verify in one command |

**Remediation artifacts** — generate outputs for stakeholders and IaC.

| Command | Purpose |
|---|---|
| `enforce` | Generate Terraform/SCP remediation templates |
| `report` | Plain-text summary for stakeholders and auditors |

**Snapshot lifecycle** — manage observation history without destroying evidence.

| Command | Purpose |
|---|---|
| `snapshot plan` | Preview retention actions |
| `snapshot quality` | Check staleness, cadence gaps, missing fields |
| `snapshot upcoming` | Snapshots approaching retention deadlines |
| `snapshot archive` | Move aged snapshots to cold storage (non-destructive) |
| `snapshot hygiene` | Orphaned files, naming inconsistencies |
| `snapshot diff` | Drift detection between two snapshots |
| `snapshot manifest` | Generate and sign integrity manifests |

### Dev binary (`stave-dev`) — adds

Build and debug the evaluation system. Used at a workstation, not in a pipeline. Blocked from production environments by default.

**Control authoring** — write, validate, and visualize controls.

| Command | Purpose |
|---|---|
| `controls list` | Inventory of built-in controls |
| `packs show` | Pack metadata: version, control count, paths |
| `lint` | Design-quality linting of control YAML |
| `fmt` | Deterministic formatting |
| `graph` | Visualize control-to-asset relationships |

**Debugging** — investigate why a control matched or didn't.

| Command | Purpose |
|---|---|
| `trace` | Step-by-step predicate evaluation for one asset |
| `prompt` | Generate LLM-ready context from results |

**Extractor development** — build extractors for new source types.

| Command | Purpose |
|---|---|
| `extractor scaffold` | Generate boilerplate for a custom extractor |
| `extractor validate` | Validate extractor output against obs.v0.1 |

**Introspection** — understand what this build of Stave supports.

| Command | Purpose |
|---|---|
| `doctor` | Local environment readiness checks |
| `schemas` | List all wire-format contract schemas |
| `capabilities` | Supported schemas, source types, packs |
| `version` | Verbose version with schema and lockfile details |

**Security posture** — audit Stave itself and collect diagnostics.

| Command | Purpose |
|---|---|
| `security-audit` | SBOM, vulnerability scan, compliance matrix |
| `bug-report` | Collect sanitized diagnostic bundle |

**Productivity** — shortcuts and documentation lookup.

| Command | Purpose |
|---|---|
| `alias` | Create/list/delete command shortcuts |
| `docs search` | Full-text search across Stave documentation |
| `docs open` | Open a docs page in the browser |

**Destructive maintenance** — evidence deletion, blocked in production.

| Command | Purpose |
|---|---|
| `snapshot prune` | Permanently delete old snapshots |

## What does Stave *not* do?

- **No live scanning** — it does not query cloud APIs during evaluation.
- **No auto-remediation** — it produces findings and fix guidance, not infrastructure changes.
- **No plugin execution** — it does not run arbitrary code, scripts, or third-party plugins.
- **No runtime agents** — nothing is deployed into your infrastructure.

Stave is a pure function: files in, findings out.
