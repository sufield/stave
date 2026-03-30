# Go Idioms in the Stave Codebase

| # | File | Location | Concept |
|---|---|---|---|
| 1 | `internal/core/hipaa/control.go` | 59-100 | Functional options pattern |
| 2 | `internal/core/diag/translator.go` | 22-37 | Functional options for translator |
| 3 | `internal/sanitize/policy.go` | 23-56 | Functional options for sanitizer |
| 4 | `internal/adapters/observations/loader_core.go` | 26-55 | Functional options for loader |
| 5 | `internal/core/controldef/severity.go` | 9-20 | Typed enum with iota ordering |
| 6 | `internal/core/hipaa/severity.go` | 5-14 | Typed severity with Less() and Rank() |
| 7 | `internal/core/securityaudit/types.go` | 14-18 | Typed status enum (PASS/WARN/FAIL) |
| 8 | `internal/cli/ui/error.go` | 51-75 | Custom error type with hints and actions |
| 9 | `internal/cli/ui/error.go` | 77-81 | UserError with Unwrap() |
| 10 | `internal/core/evaluation/remediation/detail.go` | 11-12 | Sentinel error with errors.New |
| 11 | `internal/app/eval/intent_evaluation.go` | 13-14 | Sentinel errors for domain events |
| 12 | `internal/core/evaluation/remediation/mapper.go` | 16-17 | Compile-time interface check (`var _ I = (*T)(nil)`) |
| 13 | `internal/adapters/observations/loader_core.go` | 36 | Compile-time interface check |
| 14 | `internal/core/ports/clock.go` | 7-9 | Single-method interface (Clock) |
| 15 | `internal/core/ports/crypto.go` | 7-23 | Small interfaces (Verifier, Digester, IdentityGenerator) |
| 16 | `internal/app/contracts/ports.go` | 15-30 | Consumer-side interface definitions |
| 17 | `internal/core/diag/translator.go` | 54 | Return concrete type, accept options |
| 18 | `internal/app/eval/evaluation_run.go` | 52-64 | Factory with nil-dep panics (fail-fast) |
| 19 | `internal/core/diag/issue.go` | 24-95 | Builder pattern with method chaining |
| 20 | `internal/cli/ui/error.go` | 121-156 | Builder with WithTitle/WithAction/WithURL |
| 21 | `internal/core/ports/clock.go` | 12-18 | Zero-value usable struct (RealClock) |
| 22 | `internal/core/kernel/airgap.go` | 69-103 | Defensive copy via slices.Clone |
| 23 | `internal/core/kernel/sanitizable_map.go` | 86-91 | Deep clone via maps.Clone |
| 24 | `internal/builtin/pack/registry.go` | 111-117 | Clone on return for immutability |
| 25 | `internal/core/evaluation/remediation/detail.go` | 19 | Error wrapping with %w |
| 26 | `internal/app/eval/plan.go` | 65-84 | Contextual error wrapping with %q paths |
| 27 | `internal/cli/ui/error.go` | 84-109 | errors.Is / errors.As dispatch |
| 28 | `internal/cli/ui/error.go` | 56-64 | Structured error with Code/Title/Action/URL |
| 29 | `internal/core/controldef/controldef_test.go` | 18-35 | Table-driven tests |
| 30 | `internal/core/hipaa/access_block_public_test.go` | 10-50 | Table-driven tests with subtests |
| 31 | `internal/profile/reporter/reporter_test.go` | 15-40 | Golden file test with -update flag |
| 32 | `internal/core/evaluation/metadata_golden_test.go` | 11-46 | Golden file comparison |
| 33 | `cmd/stave/main_test.go` | 12-33 | Testscript integration harness |
| 34 | `cmd/stave/testdata/scripts/` | 21 .txtar files | Testscript behavioral CLI tests |
| 35 | `internal/app/architecture_dependency_test.go` | full file | Architecture boundary enforcement test |
| 36 | `internal/app/eval/evaluation_run.go` | 68 | Context as first parameter |
| 37 | `internal/app/eval/build.go` | 74 | Context passed through, not stored in struct |
| 38 | `internal/builtin/pack/registry.go` | 22 | //go:embed for compiled-in assets |
| 39 | `internal/controldata/embed.go` | 3-4 | //go:embed for control YAML files |
| 40 | `internal/contracts/schema/load.go` | embedded | //go:embed for JSON schemas |
| 41 | `internal/core/hipaa/access_block_public.go` | 16-26 | init() for one-time registry registration |
| 42 | `internal/core/` directory | package structure | Core domain layer (no adapter imports) |
| 43 | `internal/app/` directory | package structure | Application use-case layer |
| 44 | `internal/adapters/` directory | package structure | Infrastructure adapter layer |
| 45 | `internal/app/contracts/ports.go` | full file | Port interfaces at app boundary |
| 46 | `internal/core/evaluation/doc.go` | 1-15 | Package-level doc.go |
| 47 | `internal/app/doc.go` | 1-21 | App-layer design documentation |
| 48 | `cmd/doc.go` | 1-33 | CLI exit code contract in doc |
| 49 | `internal/` directory | import restriction | Go internal/ encapsulation |
| 50 | `internal/app/{eval,diagnose,fix}/` | package layout | Feature-based package organization |
| 51 | `cmd/apply/cmd.go` | 84-120 | Cobra command with Long/Example/ExitCodes |
| 52 | `cmd/enforce/gate/cmd.go` | 61-63 | PreRunE for flag validation |
| 53 | `internal/cli/ui/error.go` | 14-22 | Semantic exit code constants |
| 54 | `internal/cli/ui/runtime.go` | 52-77 | NO_COLOR and TTY detection |
| 55 | `internal/core/controldef/severity.go` | 73-88 | MarshalText/UnmarshalText for custom type |
| 56 | `internal/core/controldef/severity.go` | 92-104 | MarshalJSON/UnmarshalJSON for string enums |
| 57 | `internal/core/controldef/severity.go` | 106-117 | MarshalYAML/UnmarshalYAML for config files |
| 58 | `internal/core/hipaa/control.go` | 36-48 | JSON tags with omitempty |
| 59 | `internal/app/securityaudit/security_audit_request.go` | 29-45 | RequestOption functional options for defaults |
| 60 | `internal/core/evaluation/exposure/control_ids.go` | 8-50 | Struct-based SSoT registry with all() enumeration |
| 61 | `internal/app/capabilities/registry.go` | 73-85 | Runtime discovery from embedded registry |
| 62 | `cmd/cmdutil/cliflags/flags.go` | 16-22 | Shared format completion constants from contracts |
| 63 | `internal/app/config/evaluator.go` | 17-18 | Injectable Getenv for testable env lookups |
| 64 | `internal/app/config/configops.go` | 220-230 | Map-based registry replacing reflection |
| 65 | `internal/app/eval/evaluation_output.go` | 16-22 | Pipeline struct separating deps from data |
| 66 | `internal/profile/profile.go` | 146-163 | Auto-discovery from registry metadata |
| 67 | `internal/compliance/crosswalk.go` | 50-52 | SupportedFrameworks() as SSoT enumeration |
| 68 | `internal/app/diagnose/filter.go` | 22-46 | Method on value type (Filter.Apply) |
| | | | |
| | **Encapsulation** | | |
| 69 | `internal/core/kernel/sanitizable_map.go` | 21-24 | Private fields, public accessors (Get, Sanitized, Set) |
| 70 | `internal/core/hipaa/registry.go` | 11-14 | Private controls map, public Lookup/All/ByProfile |
| 71 | `internal/builtin/pack/registry.go` | 51-58 | Private packs/hash, public ListPacks with clone-on-return |
| 72 | `internal/core/asset/episode.go` | 15-19 | Private start/end/open, Close() enforces endAt >= startAt |
| 73 | `internal/core/asset/tag_set.go` | 32-35 | Private normalized map, public Matches/Conflicts |
| 74 | `internal/core/evaluation/exposure/control_ids.go` | 8-20 | Private ID fields, all() as single enumeration point |
| | | | |
| | **Methods vs Functions** | | |
| 75 | `internal/core/hipaa/registry.go` | 43-45 | Method: Lookup reads receiver's internal map |
| 76 | `internal/app/diagnose/filter.go` | 22-46 | Method: Apply uses receiver's filter criteria |
| 77 | `internal/core/controldef/severity.go` | 45-48 | Method: Gte compares receiver's ordinal value |
| 78 | `internal/core/asset/timeline.go` | 66-81 | Method: RecordObservation mutates receiver state |
| 79 | `internal/core/evaluation/exposure/classify.go` | 26-45 | Function: ClassifyExposure is pure transformation, no state |
| 80 | `internal/app/eval/build.go` | 74-116 | Function: BuildDependencies assembles from params, no receiver |
| 81 | `internal/app/eval/filters.go` | 24-45 | Function: FilterControls transforms input, filter is parameter |
| 82 | `internal/core/evaluation/exposure/classify.go` | 15-22 | Function: ValidateControlIDs validates package singleton |
| | | | |
| | **Accept Interfaces, Return Structs** | | |
| 83 | `internal/app/eval/evaluation_run.go` | 52-76 | Accepts 4 interface params, returns *EvaluateRun |
| 84 | `internal/app/diagnose/run.go` | 40-55 | Accepts ObservationRepository + ControlRepository, returns *Run |
| 85 | `internal/adapters/controls/yaml/loader.go` | 28, 41-49 | Returns *ControlLoader; compile-time check satisfies interface |
| 86 | `internal/adapters/observations/loader_core.go` | 36, 41-55 | Returns *ObservationLoader; satisfies ObservationRepository |
| 87 | `internal/app/catalog/provider.go` | 25-27 | Exception: returns ControlProvider interface (multiple impls) |
| 88 | `internal/cel/factory.go` | 10-22 | Exception: returns PredicateEval function type (closure) |
| | | | |
| | **Domain-Driven Design** | | |
| | | | |
| | *Entities (identity-based, mutable)* | | |
| 89 | `internal/core/asset/models.go` | 18-24 | Entity: Asset with ID, mutable properties across snapshots |
| 90 | `internal/core/asset/timeline.go` | 17-26 | Entity: Timeline tracks safety state, mutates via RecordObservation |
| 91 | `internal/core/asset/episode.go` | 15-19 | Entity: Episode transitions from open to closed |
| 92 | `internal/core/asset/models.go` | 50-56 | Entity: CloudIdentity with ID, mutable attributes |
| | | | |
| | *Value Objects (immutable, compared by content)* | | |
| 93 | `internal/core/controldef/severity.go` | 9-20 | Value object: Severity enum with iota ordering |
| 94 | `internal/core/kernel/control_id.go` | 12-16 | Value object: ControlID typed string with format validation |
| 95 | `internal/core/kernel/crypto.go` | 6-8 | Value object: Digest (SHA-256 hex hash) |
| 96 | `internal/core/kernel/schema.go` | 6-36 | Value object: Schema version string with IsValid |
| 97 | `internal/core/kernel/principal_scope.go` | 10-19 | Value object: PrincipalScope enum (Public/Authenticated/Account) |
| 98 | `internal/core/kernel/trust_boundary.go` | 10-17 | Value object: TrustBoundary enum (External/CrossAccount/Internal) |
| 99 | `internal/core/kernel/network_scope.go` | 10-18 | Value object: NetworkScope with Rank() for restrictiveness |
| 100 | `internal/core/kernel/vendor.go` | 9-11 | Value object: Vendor typed string, normalized to lowercase |
| 101 | `internal/core/kernel/asset_type.go` | 12-13 | Value object: AssetType with Domain() extraction |
| 102 | `internal/core/asset/id.go` | 11-28 | Value object: asset.ID with validation |
| 103 | `internal/core/evaluation/result.go` | 51-57 | Value object: SafetyStatus (Safe/Borderline/Unsafe) |
| 104 | `internal/core/evaluation/result.go` | 15-22 | Value object: ConfidenceLevel (High/Medium/Low/Inconclusive) |
| 105 | `internal/core/evaluation/evidence.go` | 12-21 | Value object: RootCause (Identity/Resource/General) |
| 106 | `internal/core/evaluation/evidence.go` | 76-85 | Value object: DriftPattern (Persistent/Degraded/Intermittent) |
| 107 | `internal/core/evaluation/exposure/classify_types.go` | 23-31 | Value object: ExposureClassification (no identity) |
| | | | |
| | *Aggregates (consistency boundaries)* | | |
| 108 | `internal/core/asset/snapshot.go` | 13-19 | Aggregate root: Snapshot contains Assets + Identities |
| 109 | `internal/core/evaluation/result.go` | 119-130 | Aggregate root: Result contains Findings, Summary, Rows |
| 110 | `internal/core/asset/episode_history.go` | 12-14 | Aggregate: EpisodeHistory of closed Episodes |
| 111 | `internal/profile/profile.go` | 47-56 | Aggregate: ProfileReport with Results, CompoundFindings |
| 112 | `internal/core/evaluation/evidence.go` | 32-53 | Aggregate: Evidence with timing, recurrence, root causes |
| | | | |
| | *Domain Services (stateless operations)* | | |
| 113 | `internal/app/workflow/evaluation.go` | 32-52 | Domain service: Evaluate orchestrates full pipeline |
| 114 | `internal/core/evaluation/exposure/classify.go` | 26-45 | Domain service: ClassifyExposure pure transformation |
| 115 | `internal/core/hipaa/compound/compound.go` | 43-58 | Domain service: Detect compound risks from results |
| 116 | `internal/core/evaluation/result.go` | 59-68 | Domain service: ClassifySafetyStatus from violations |
| 117 | `internal/core/evaluation/evidence.go` | 93-127 | Domain service: ComputePostureDrift from timeline |
| 118 | `internal/core/evaluation/diagnosis/analysis.go` | 42+ | Domain service: Diagnose explains evaluation results |
| | | | |
| | *Repositories (collection-like access)* | | |
| 119 | `internal/app/contracts/ports.go` | 23-25 | Repository: ObservationRepository loads snapshots |
| 120 | `internal/app/contracts/ports.go` | 35-37 | Repository: ControlRepository loads controls |
| 121 | `internal/app/contracts/ports.go` | 72-74 | Repository: FindingMarshaler transforms findings |
| 122 | `internal/core/evaluation/finding.go` | 131-133 | Repository: ControlProvider resolves control by ID |
| | | | |
| | *Domain Events (things that happened)* | | |
| 123 | `internal/core/evaluation/finding.go` | 17-31 | Domain event: Finding (violation detected) |
| 124 | `internal/core/hipaa/compound/compound.go` | 10-23 | Domain event: CompoundFinding (combined risk detected) |
| 125 | `internal/core/evaluation/diagnosis/types.go` | 21-28 | Domain event: Issue (diagnostic finding occurred) |
| 126 | `internal/profile/profile.go` | 59-66 | Domain event: AcknowledgedEntry (exception acknowledged) |
| 127 | `internal/core/evaluation/finding.go` | 176-181 | Domain event: ExceptedFinding (finding excepted) |
| | | | |
| | *Bounded Contexts (package boundaries)* | | |
| 128 | `internal/core/evaluation/` | package | Context: Evaluation (findings, evidence, engine) |
| 129 | `internal/core/asset/` | package | Context: Asset/Observation (snapshots, timelines) |
| 130 | `internal/core/controldef/` | package | Context: Control Definition (rules, predicates) |
| 131 | `internal/core/hipaa/` | package | Context: HIPAA Compliance (controls, compound risks) |
| 132 | `internal/core/evaluation/exposure/` | package | Context: Exposure Classification (risk vectors) |
| 133 | `internal/core/evaluation/remediation/` | package | Context: Remediation (fix guidance, action plans) |
| 134 | `internal/core/evaluation/diagnosis/` | package | Context: Diagnostics (explain evaluation outcomes) |
| | | | |
| | *Ubiquitous Language* | | |
| 135 | `GLOSSARY.md` | repo root | Terminology: Control, Asset, Finding, Observation, Evidence, Sanitize |
| | | | |
| | **Dependency Injection & Construction** | | |
| 136 | `internal/app/eval/evaluation_run.go` | 52-76 | DI: constructor accepts 4 interface deps, panics on nil |
| 137 | `internal/app/securityaudit/security_audit.go` | 22-37 | DI: NewRunner accepts RunnerDeps struct |
| 138 | `internal/app/securityaudit/evidence/types.go` | 269 | DI: NewCollectors wires all providers from Deps |
| 139 | `internal/core/hipaa/access_block_public.go` | 16-26 | init() for write-once registry (acceptable pattern) |
| 140 | `internal/profile/hipaa.go` | 5-9 | init() for profile registration (write-once) |
| | | | |
| | **Error Discipline** | | |
| 141 | `internal/app/eval/plan.go` | 65-84 | Wrap errors with %w and %q context at every call site |
| 142 | `internal/cli/ui/error.go` | 84-109 | Handle errors once: classify via errors.Is/As, no log+return |
| 143 | `internal/core/evaluation/remediation/detail.go` | 11-12 | Sentinel errors for programmatic inspection |
| 144 | `cmd/securityaudit/output.go` | 12-15 | Derive error enum from domain constants, not hardcode |
| | | | |
| | **Naming Conventions** | | |
| 145 | `internal/core/hipaa/registry.go` | 43 | Receiver: `r` for Registry (1-letter abbreviation) |
| 146 | `internal/app/diagnose/filter.go` | 22 | Receiver: `f` for Filter |
| 147 | `internal/core/controldef/severity.go` | 45 | Receiver: `s` for Severity |
| 148 | `internal/core/asset/timeline.go` | 66 | Receiver: `tl` for Timeline (2-letter) |
| 149 | `internal/app/contracts/ports.go` | 23-74 | Interface "er" suffix: Repository, Marshaler, Reader |
| 150 | `internal/core/ports/crypto.go` | 7-23 | Interface "er" suffix: Verifier, Digester, Generator |
| 151 | `internal/core/evaluation/exposure/` | package name | Short package name, no util/common/shared |
| 152 | `internal/core/hipaa/` | snake_case files | Filenames: access_block_public.go, policy_helper.go |
| | | | |
| | **Slice & Memory Patterns** | | |
| 153 | `internal/core/hipaa/registry.go` | 48-53 | Pre-allocate: make([]Control, len(r.order)) |
| 154 | `internal/app/eval/filters.go` | 37 | Pre-allocate: make([]ControlDefinition, 0, len(controls)) |
| 155 | `internal/adapters/output/sarif/finding_writer.go` | (impl) | Pre-allocate SARIF rules/results slices |
| 156 | `internal/core/controldef/severity.go` | 45-48 | Value receiver on small type (Severity int) |
| 157 | `internal/app/diagnose/filter.go` | 16-21 | Value receiver on small struct (Filter, 2 fields) |
| 158 | `internal/core/kernel/control_id.go` | methods | Value receiver on typed string (ControlID) |
| | | | |
| | **Testing Discipline** | | |
| 159 | `internal/core/hipaa/access_block_public_test.go` | full file | Table-driven tests with subtests |
| 160 | `internal/profile/reporter/reporter_test.go` | full file | Golden file test with -update flag |
| 161 | `cmd/stave/main_test.go` | 12-33 | Testscript integration harness |
| 162 | `internal/app/architecture_dependency_test.go` | full file | Automated boundary enforcement |
| 163 | (codebase-wide) | all test files | No mocking frameworks (testify/gomock/mockery) |
| 164 | (codebase-wide) | all test files | Hand-written stubs satisfying interfaces |
| 165 | `internal/app/eval/evaluation_run_test.go` | 15-40 | 5-line stub structs implementing repository interfaces |
| | | | |
| | **Not Used (noted)** | | |
| 166 | (codebase-wide) | — | t.Parallel() not used (tests are lightweight) |
| | | | |
| | **No Global Mutable State** | | |
| 167 | `internal/app/` | all packages | Zero global mutable variables; all state via constructor injection |
| 168 | `internal/core/` | all packages | Only const, sentinel errors, and compile-time checks at package level |
| 169 | `internal/core/hipaa/registry.go` | 75 | ControlRegistry: write-once at init, immutable after startup |
| 170 | `internal/app/config/evaluator.go` | 22-31 | Getenv injected via constructor, not os.Getenv global call |
| | | | |
| | **Tell, Don't Ask** | | |
| 171 | `internal/core/asset/timeline.go` | 66-81 | Tell: RecordObservation(t, isUnsafe) — caller doesn't inspect state |
| 172 | `internal/core/asset/episode.go` | 47 | Tell: Close(t) — episode manages its own transition |
| 173 | `internal/core/hipaa/registry.go` | 33-39 | Tell: MustRegister(ctrl) — registry handles validation internally |
| 174 | `internal/app/diagnose/filter.go` | 22-46 | Tell: Apply(report) — filter applies itself to data |
| 175 | `internal/app/eval/evaluation_output.go` | 24-60 | Tell: Pipeline.Run(ctx, w, result) — caller doesn't manage steps |
| 176 | `internal/core/kernel/sanitizable_map.go` | 49-56 | Tell: SetSensitive(k, v) — map decides how to store it |
| | | | |
| | **Command-Query Separation** | | |
| 177 | `internal/core/hipaa/registry.go` | 25-33 | Command: Register() mutates map, returns error |
| 178 | `internal/core/hipaa/registry.go` | 43-45 | Query: Lookup() reads map, returns value |
| 179 | `internal/core/asset/timeline.go` | 66-81 | Command: RecordObservation() mutates state |
| 180 | `internal/core/asset/timeline.go` | 83+ | Query: UnsafeDuration(), IsOpen() return data without mutation |
| 181 | `internal/core/evaluation/result.go` | 59-68 | Query: ClassifySafetyStatus() pure function, no side effects |
| 182 | `internal/profile/profile.go` | 49 | Command: RecomputeSummary() mutates counts via pointer receiver |
| | | | |
| | **Composition over Inheritance** | | |
| 183 | `internal/profile/profile.go` | 40-44 | ProfileResult embeds hipaa.Result (adds ComplianceRef, Rationale) |
| 184 | `internal/app/eval/evaluation_run.go` | 27-39 | EvaluateConfig embeds LoadConfig (shares common fields) |
| 185 | `internal/core/hipaa/access_block_public.go` | 12-14 | accessBlockPublic embeds Definition (reuses ID, Severity, etc.) |
| 186 | `internal/app/securityaudit/evidence/types.go` | 259-266 | Collectors composes 6 provider interfaces (not inheritance) |
| | | | |
| | **Fail Fast** | | |
| 187 | `internal/app/eval/evaluation_run.go` | 62-76 | Constructor panics on nil deps (programmer error) |
| 188 | `internal/core/hipaa/registry.go` | 36-39 | MustRegister panics on duplicate (startup invariant) |
| 189 | `internal/app/eval/options.go` | 57-86 | Validate() returns early on first error |
| 190 | `cmd/enforce/gate/cmd.go` | 61-63 | PreRunE validates flags before RunE executes |
| 191 | `internal/app/securityaudit/security_audit.go` | 45-48 | Run() validates request before any work starts |
| | | | |
| | **Immutability** | | |
| 192 | `internal/core/controldef/severity.go` | 9-48 | No setters on Severity; Gte/Rank return new values |
| 193 | `internal/core/kernel/control_id.go` | 12-16 | ControlID typed string; Provider/Category return derived values |
| 194 | `internal/core/kernel/airgap.go` | 69-103 | Getters return slices.Clone, preventing external mutation |
| 195 | `internal/builtin/pack/registry.go` | 111-117 | ListPacks returns cloned Pack slice |
| 196 | `internal/core/evaluation/evidence.go` | 100-128 | Evidence snapshot types: no setters, immutable after creation |
| | | | |
| | **Law of Demeter** | | |
| 197 | `internal/app/eval/evaluation_run.go` | 79-92 | Passes resolved controls/snapshots directly, no deep chaining |
| 198 | `internal/app/eval/evaluation_output.go` | 30-57 | Pipeline steps call one method each, results passed forward |
| 199 | `internal/core/hipaa/access_block_public.go` | 29-55 | Extracts properties into local vars before logic, no a.B().C() |
| | | | |
| | **Single Responsibility** | | |
| 200 | `internal/core/controldef/severity.go` | full file | One type, one concern: severity ordering and parsing |
| 201 | `internal/core/hipaa/registry.go` | full file | One concern: control storage and lookup |
| 202 | `internal/core/hipaa/policy_helper.go` | full file | One concern: S3 bucket policy statement parsing |
| 203 | `internal/core/evaluation/exposure/classify.go` | full file | One concern: exposure classification logic |
| 204 | `internal/adapters/output/sarif/finding_writer.go` | full file | One concern: SARIF format output |
