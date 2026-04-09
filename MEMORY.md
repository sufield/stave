# MEMORY.md — Stave Refactoring Context

What happened over 2 months, what's left, and what to never repeat.

## Refactoring Summary

3,448 commits. ~2,268 touching Go source. ~1,005 Go files deleted. ~728 renamed. 60+ domain term renames. 44 Strangler Fig feature extractions. 12+ linters enabled progressively.

### Major Shifts Completed

1. **Hexagonal architecture migration** — Flat `internal/domain/` + `pkg/alpha/` restructured into `core/` (domain), `app/` (services), `adapters/` (infrastructure), with compile-time boundary enforcement tests.

2. **Strangler Fig package extraction** — Monolithic `domain/usecases/` dissolved into 44 feature-specific packages, each with its own domain types and use case. Old packages fully deleted.

3. **Domain vocabulary overhaul** — 60+ renames from generic programming terms to security domain vocabulary. All renames atomic (Mikado Method), no transition periods, no aliases kept.

4. **Primitive obsession elimination** — Raw strings replaced with typed IDs (`ControlID`, `AssetType`, `Vendor`, etc.) with validation at parse boundaries via `UnmarshalText`.

5. **"Parse, don't validate"** — Input validation moved from evaluation time to deserialization time. Domain types enforce invariants at construction.

6. **"Design errors out"** — Programming errors panic. Operational errors return `error`. Constructors that can't fail don't return `error`.

7. **Error handling overhaul** — Sentinel errors with fix hints, `UserError` wrapping for exit code 2, verb-phrase error messages.

8. **CLI command standardization** — All commands follow `cmd.go`/`run.go`/`options.go`/`output.go`/`deps.go` convention with `Prepare(cmd)` pattern.

9. **Progressive linter hardening** — 12+ linters enabled one per commit: `nilerr`, `errorlint`, `containedctx`, `noctx`, `errname`, `hugeParam`, `rangeValCopy`, `revive` stuttering.

10. **Context migration** — `context.Context` moved from struct fields to function parameters. Enforced by `containedctx` linter.

11. **Positive logic pass** — Negated conditions and magic comparisons replaced with intent-revealing method names (`IsPublicAccessFullyBlocked`, `IsNetworkRestricted`, `ACLsDisabled`).

12. **Dead code removal** — Multiple `deadcode` passes. 207+ findings eliminated. 7 orphaned packages deleted. All backward-compatibility aliases removed.

## Technical Debt Remaining

### High Priority

1. **`cmdutil/compose/infra.go` is a service locator** — The `Provider` type acts as a god-object factory registry. It should be replaced with explicit dependency injection per command. Each command's `deps.go` should construct its own dependency tree without a shared registry.

2. **`bootstrap.go` does too much** — `PersistentPreRunE` handles config resolution, health checks, logger init, sanitizer setup, and context injection. These should be split into composable middleware steps.

3. **Some `app/` packages still reference `platform/`** — The platform layer was intended as OS utilities only, but some app services import `platform/fsutil` directly instead of going through a port. These should be injected.

4. **E2E HackerOne tests are skipped** — Per project memory, these were skipped during the refactoring period and need to be re-enabled now that the refactoring is complete.

5. **Test coverage gaps in compliance profile** — The HIPAA/compliance profile feature (47 controls) was built rapidly. Edge cases around compound risk detection and cross-control exemptions need targeted tests.

### Medium Priority

6. **`vendor/` is committed** — Vendored dependencies are checked in. Consider whether this is still the preferred strategy or if Go module proxy caching is sufficient.

7. **`cmd/stave-dev/main.go` bifurcation** — The dev entry point uses a build tag (`stavedev`) to include all commands. This means some commands are invisible in production builds. Document which commands are dev-only and why.

8. **Schema sync is a manual build step** — `make sync-schemas` must run before `go build`. This fails silently if forgotten. Consider `go generate` or build constraints to make this automatic.

9. **Remediation plan output is the newest feature** — `fix_plan` in findings output was added recently. The `enforce/fix` command acts on these plans. This code path has fewer miles on it than the evaluation engine.

10. **`internal/cel/` is a critical dependency** — The CEL predicate evaluator powers all control evaluation. It wraps `google/cel-go` with Stave-specific extensions. Changes here affect every control in the catalog. Treat with extreme care.

### Low Priority

11. **Some test files use `testify` patterns** — The migration from testify to `google/go-cmp` + `testutil` was not 100% complete. Remaining testify-style assertions should be migrated when touching those files.

12. **`internal/adapters/` naming inconsistency** — Some adapter packages use singular names (`baseline`, `telemetry`), others use path-style names (`output/json`, `controls/yaml`). Standardize on the path-style convention.

## Lessons Learned

### Architecture

- **Compile-time boundary tests prevent regression.** The `architecture_*_test.go` files in `app/` catch hexagonal violations at `go test` time. Without them, the hexagonal boundaries eroded within days during rapid development.

- **Strangler Fig is the only safe way to decompose monoliths.** Attempting big-bang package splits caused cascading compile errors. The 44-commit Strangler Fig approach (new package, rewire, delete) kept the codebase compiling at every commit.

- **Delete backward compatibility immediately.** Keeping aliases "for safety" during renames created confusion about which type was canonical. The "no transition periods" policy eliminated this class of bug entirely.

### Naming

- **Domain vocabulary must be established early and enforced absolutely.** The 60-rename wave was painful because it touched every file. If the vocabulary had been set before building features, 40% of the commits would have been unnecessary.

- **File names must match type names.** Renaming a type without renaming its file created ongoing confusion. The rule "rename file when type is renamed" was established after 3 incidents of editing the wrong file.

### Type Safety

- **"Parse, don't validate" eliminates entire bug categories.** Before: runtime panics when a control ID was empty. After: empty control IDs are rejected at YAML/JSON parse time. Zero runtime panics from invalid IDs since adoption.

- **Unify types aggressively.** Three `Status` types and three `Severity` types caused silent bugs where the wrong type was compared. Unifying to one canonical type (`outcome.Status`, `controldef.Severity`) fixed all of them.

### Process

- **One linter per commit.** Enabling multiple linters simultaneously creates overwhelming fix volumes. One linter + all its fixes in a single commit is reviewable and revertable.

- **Dead code analysis after every structural change.** The `deadcode` tool found 207 unreachable functions after the hexagonal migration. Without this pass, the dead code would have accumulated indefinitely.

- **Refactoring strategies must be named and documented.** Commit messages like "refactor(validate): add domain types and use case (strangler fig)" made the history navigable. Unnamed refactors were impossible to understand a week later.

- **Regenerate derived files after adding controls.** The README template and control reference docs are generated from the control directory. Adding IAM/GCS/DNS controls without running `make readme` and `make docs-controls` breaks CI checks (`readme-check`, `docs-controls-check`). The genreadme tool was also hardcoded to `controls/s3` and had to be updated to walk `controls/` root. Always run `make readme && make docs-controls` after adding a new domain.

## Key Interfaces (Quick Reference)

| Interface | Package | Purpose |
|---|---|---|
| `ObservationRepository` | `app/contracts` | Load observation snapshots |
| `ControlRepository` | `app/contracts` | Load control definitions |
| `FindingMarshaler` | `app/contracts` | Render output (JSON/text/SARIF) |
| `Clock` | `core/ports` | Time injection for deterministic tests |
| `Tracer` | `core/ports` | Audit trace recording |
| `Digester` | `core/ports` | Content hashing for integrity |
| `PredicateEval` | `core/controldef` | CEL predicate evaluation |

## Evaluation Engine Quick Reference

**Strategies** (in `core/evaluation/engine/strategy.go`):
- `unsafeStateStrategy` — is the asset currently unsafe?
- `unsafeDurationStrategy` — has the asset been unsafe beyond the SLA threshold?
- `unsafeRecurrenceStrategy` — is the asset oscillating between safe and unsafe?
- `prefixExposureStrategy` — is an S3 prefix exposed?

**Control types** (in ctrl.v1 YAML):
- `unsafe_state` — fires when predicate matches at evaluation time
- `unsafe_duration` — fires when predicate has matched for longer than `max_unsafe_duration`

## Phase 2 Roadmap: Foundation to Product

### 1. Policy Forge (DONE)
~~Skill SDK Generator~~ → Corrected to **Policy Forge** (`make forge` / `internal/tools/gencontrol`).
Controls are declarative YAML+CEL, not imperative Go. The forge scaffolds ctrl.v1 YAML + pass/fail E2E fixtures with validation. Generates new controls in <30 seconds.

### 2. Air-Gap Trust (DONE — binary inspection)
- `stave version --verify`: prints sha256 of binary, sha256 of all embedded controls (deterministic), Go version, module deps
- No Cosign/GoReleaser needed — `--verify` is self-inspection, not signing
- Signing infrastructure belongs in CI pipeline, not in the binary
- Remaining: SBOM generation in CI, binary signing with Cosign for release artifacts

### 3. Explainability Loop (DONE)
- `stave prompt from-finding --trace-file audit_trace.json`
- Extends existing `prompt from-finding` with trace reasoning chain
- Template renders step-by-step evaluation logic (exemption check, predicate evaluation, threshold check)
- Works offline: copy-paste prompt for any AI assistant

### 4. Performance Guardrails (DONE)
- `perfsprint` linter enabled, all violations fixed
- `BenchmarkEvaluate10kAssets`: 10,000 mixed S3/IAM assets, 5 controls, ~121ms
- `BenchmarkEvaluateMultiControlScaling`: 1,000 assets × 1/5/10/25/50 controls (linear scaling verified)
- `make bench` target
- `hugeParam` at 512B, `rangeValCopy` at 128B (existing, already tight)

### 5. Multi-Cloud Expansion (DONE — exceeded target)
Original target: one Azure or GCP check with zero engine changes.
Actual result: **4 domains, 74 controls, 3+ vendors, zero engine changes.**

| Domain | Controls | Vendors | Engine Changes |
|---|---|---|---|
| S3 (storage) | 53 | aws | 0 |
| IAM (identity) | 11 | aws | 0 |
| GCS (storage) | 7 | gcp | 0 |
| DNS (takeover) | 3 | any (vendor-agnostic) | 0 |

## Phase 3 Roadmap: Infrastructure Domain Expansion

All phases require zero engine changes — YAML controls + observation contract only.

### Phase 3a: VPC + EC2 (highest HIPAA gap coverage)

| Domain | Controls Needed | Property Namespace | Source |
|---|---|---|---|
| VPC flow logging | Flow logs enabled, flow logs encrypted | `properties.network.flow_log.*` | kops #1776, Cloudticity #3 |
| VPC security groups | Default deny, restricted ports, no 0.0.0.0/0 | `properties.network.security_group.*` | kops #1776, Cloudticity #1 |
| EC2 encryption | EBS volume encryption, snapshot encryption | `properties.compute.encryption.*` | kops #1776, Cloudticity #6 |
| EC2 network | No public IP, IMDSv2 enforced | `properties.compute.network.*` | kops #1776, Cloudticity #1 |
| EC2 monitoring | Detailed monitoring enabled | `properties.compute.monitoring.*` | AWS blog 2016 |

### Phase 3b: RDS + ELB

| Domain | Controls Needed | Property Namespace | Source |
|---|---|---|---|
| RDS encryption | Storage encryption, snapshot encryption | `properties.database.encryption.*` | kops #1776, Cloudticity #6 |
| RDS access | No public access, multi-AZ | `properties.database.access.*` | Cloudticity #9 |
| RDS backup | Backup enabled, retention period | `properties.database.backup.*` | Cloudticity #8 |
| RDS logging | Audit logging, slow query log | `properties.database.logging.*` | Cloudticity #3 |
| ELB encryption | TLS 1.2+, HTTPS redirect | `properties.loadbalancer.encryption.*` | Cloudticity #7 |
| ELB logging | Access logging enabled | `properties.loadbalancer.logging.*` | kops #1776 |
| ELB availability | Cross-zone enabled, multi-AZ | `properties.loadbalancer.availability.*` | Cloudticity #9 |

### Phase 3c: Kubernetes

| Domain | Controls Needed | Property Namespace | Source |
|---|---|---|---|
| K8s RBAC | No wildcard ClusterRoles, service account restrictions | `properties.rbac.*` | kops #1776 |
| K8s network | Network policies exist, default deny | `properties.network_policy.*` | kops #1776 |
| K8s audit | Audit logging enabled, audit policy configured | `properties.audit.*` | kops #1776 |
| K8s secrets | etcd encryption, no plaintext secrets in pods | `properties.secrets.*` | kops #1776 |

### Phase 3d: Backup + Availability (cross-service)

| Domain | Controls Needed | Property Namespace | Source |
|---|---|---|---|
| Backup verification | Backup exists, backup is recent, backup encrypted | `properties.backup.*` | Cloudticity #8 |
| Availability | Multi-AZ configured, redundancy present | `properties.availability.*` | Cloudticity #9 |
| Disaster recovery | Cross-region replication configured | `properties.replication.*` | HIPAA §164.308(a)(7) |

### Gap sources consolidated

| Source | Issues Mapped | Gaps Found |
|---|---|---|
| kops #1776 | 42 requirements | VPC, EC2, K8s, RDS |
| Cloudticity top 10 | 10 issues | Availability, backup frequency, transport |
| AWS Config Conformance Pack | ~100 rules | 20+ services breadth |
| Prowler HIPAA | Checklist | Same as kops + Cloudticity |
| AWS blog 2016 | 9 snippets | EC2 monitoring, security groups |

## Architectural Insight: Stave Is a Formal Proof System

The 2-month refactoring and Phase 2 implementation revealed Stave's true identity. It is NOT a cloud security tool. It is a **policy evaluation engine for JSON-represented infrastructure**.

### Key realizations

- **Multi-cloud is a schema specification, not code.** Stave doesn't need adapters for each cloud. It defines the observation contract (property namespaces), and clients build extractors that populate those properties. Adding a new cloud provider = extending `docs/observation-contract.md` + writing YAML controls.

- **Extractors are external — Stave owns the contract.** Stave never imports cloud SDKs. It reads obs.v0.1 JSON. The extractor is the client's responsibility. Stave's responsibility is to detect when extractor data is incomplete (INCOMPLETE controls).

- **Asset types and vendors are open strings.** No enums, no validation, no hardcoded lists. The engine accepts `type: "kubernetes_pod"` and `vendor: "onprem"` today without any code change.

- **Each real-world resource = one asset type.** DNS records are `dns_record` assets with `dns.*` properties. S3 buckets are `aws_s3_bucket` assets with `storage.*` properties. Never mix different resources in one asset.

- **Vendor goes in the `vendor` field, not in property paths.** `storage.access.public_read` works for both S3 and GCS because the semantics align. Vendor-specific fields (like `storage.controls.uniform_access_enabled` for GCS) are just additional properties, not a separate namespace.

- **DNS controls are vendor-agnostic.** A `dns_record` asset can have `vendor: "cloudflare"`, `vendor: "route53"`, `vendor: "namecheap"`, or `vendor: "bind"`. The controls evaluate `dns.target_exists` and `dns.target_owned` — the DNS provider is irrelevant.

### Liability shift via INCOMPLETE controls

Every domain must have an INCOMPLETE control that fires when the extractor provides insufficient data. This prevents false compliant verdicts:
- `CTL.S3.INCOMPLETE.001` — bucket safety unprovable
- `CTL.IAM.INCOMPLETE.001` — root MFA status missing
- `CTL.GCS.INCOMPLETE.001` — access control data missing

If you add a new domain, add its INCOMPLETE control first.
