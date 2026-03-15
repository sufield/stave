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
3. **Separation of concerns** — extracting data from cloud APIs is a different problem from evaluating safety invariants. Stave handles evaluation; `stave ingest` or external tools handle extraction.

## How is "evidence" different from "observation"?

**Observations** are raw input — point-in-time snapshots of infrastructure state (`obs.v0.1` JSON files). They contain everything captured, whether relevant or not.

**Evidence** is output — the specific subset of observation data that proves a particular finding. When Stave detects a violation, it attaches the relevant property values, timestamps, and duration calculations as evidence.

Observations are what you feed in. Evidence is what Stave produces to support each finding.

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

## What does Stave *not* do?

- **No live scanning** — it does not query cloud APIs during evaluation.
- **No auto-remediation** — it produces findings and fix guidance, not infrastructure changes.
- **No plugin execution** — it does not run arbitrary code, scripts, or third-party plugins.
- **No runtime agents** — nothing is deployed into your infrastructure.

Stave is a pure function: files in, findings out.
