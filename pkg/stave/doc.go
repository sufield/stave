// Package stave is the programmatic entry point for running Stave's
// control evaluation. It exposes the canonical use cases — Apply,
// Score, Gate — as typed Go APIs that the ./stave CLI is itself a
// thin wrapper over.
//
// # When to use
//
// Use this package when a Go program needs the output of `stave apply`,
// `stave score`, or `stave ci gate` without shelling out and parsing
// JSON. Consumers get typed [Finding], [Issue], [Assessment],
// [ControlID], [AssetID], [Classification], [Severity], [ScoreResult],
// and [GateResult] values; they do not marshal or unmarshal anything.
//
// # When not to use
//
// Shell users want the `./stave ...` CLI. Non-Go consumers (scripts,
// other languages) want the CLI's JSON output over stdout. This
// package is Go-only.
//
// # Basic usage
//
//	cfg := stave.Config{
//		SnapshotsDir: "./observations",
//		// ControlsDir empty → use the embedded builtin catalog.
//		// MaxUnsafe zero → project default.
//		// Now zero → real current time.
//	}
//	a, err := stave.Apply(context.Background(), cfg)
//	if err != nil {
//		return err
//	}
//	for _, f := range a.Findings {
//		if f.Classification == stave.StateAssertion {
//			fmt.Println(f.ControlID, f.AssetID, f.Severity)
//		}
//	}
//
//	// Score the assessment.
//	sr, _ := stave.Score(ctx, stave.ScoreConfig{Assessment: a})
//	fmt.Printf("posture %.0f/100 (%s)\n", sr.Score, sr.RubricBand)
//
//	// Gate a CI pipeline against the artifact.
//	g, _ := stave.Gate(ctx, stave.GateConfig{
//		Policy:         stave.GateFailOnAnyViolation,
//		EvaluationPath: "out/evaluation.json",
//	})
//	if !g.Passed {
//		os.Exit(3)
//	}
//
// # Library is the source of truth
//
// The ./stave CLI is a thin wrapper over this package. New use cases
// land here first; the CLI invokes them with flag-derived Config
// structs and renders the typed Result back to stdout. This means a
// behavior change ships in one place — anything the CLI does that
// the library can't is a gap that should be closed, not a feature.
//
// # Public API surface (today)
//
// Every function below corresponds to one user intent. Adding a
// function that does not is a smell; it probably belongs in
// internal/.
//
//	Apply              — run an evaluation over a snapshot directory.
//	Score              — compute the posture score for an Assessment.
//	Gate               — apply a CI failure policy to an evaluation.
//	Compliance         — per-framework compliance posture (one).
//	ComplianceMulti    — per-framework compliance posture (many; single-pass).
//	ResolveCrosswalk   — resolve a control-crosswalk doc against frameworks.
//	ListEmbeddedProfiles — list the built-in compliance profiles (id + name).
//	LoadProfile        — load and validate a compliance-profile YAML file.
//	SanitizeSnapshot   — tokenize a snapshot bundle for safe sharing.
//	ObservationSchemaVersion — the obs.v0.1 schema_version string (const).
//	ListEnvVars        — the supported STAVE_* environment variables.
//	ListPredicateAliases — semantic predicate alias metadata.
//	SupportedOperators — the predicate operators Stave supports.
//	InspectACL         — assess a JSON array of S3 ACL grants.
//	InspectPolicy      — analyse a raw S3 bucket-policy document.
//	InspectRisk        — score a policy statement context.
//	InspectExposure    — classify resource exposure + bucket access.
//	MapTelemetry       — assessment -> NDJSON telemetry events.
//	SignSnapshot       — Ed25519-sign a snapshot's assets.
//	VerifySnapshot     — verify an attested snapshot.
//	GenerateAttestKeyPair — make an Ed25519 attestation key pair.
//	EvalCEL            — evaluate a raw CEL expression over a snapshot.
//	DiffCatalogs       — render the delta between two control catalogs.
//	DiffSnapshotBundles — render the diff of two observation bundle files.
//	RenderMetrics      — Prometheus scrape body from an assessment history.
//	RenderScorecard    — multi-framework compliance scorecard from findings.
//	CompareFrameworks  — baseline-vs-target framework gap analysis.
//	CompareRemediationImpact — before/after remediation-impact analysis.
//	ExpandList         — archetype catalog summary with control counts.
//	ExpandArchetype    — expand one archetype/finding into its control family.
//	ContractShowType   — agent-facing input contract for one asset type.
//	ContractList       — asset types with controls (schema/mapping presence).
//	BuildReport        — executive posture report (json/markdown).
//	MapAttackCoverage  — MITRE ATT&CK tactic coverage map from the catalog.
//	VetMapping         — pre-flight check a Steampipe->Stave mapping file.
//	AvailableFrameworks — list every embedded framework profile ID.
//	SearchCatalog      — rank the catalog against a free-form intent.
//	RenderCatalogSearch — load (dir) + rank + render the catalog search.
//	AnalyzeFieldCoverage — control evaluability vs a snapshot's fields.
//	RenderCatalog      — grouped capability catalog view (text/wide/json).
//	BuildAttackPath    — chain attack-path graph (json/dot/csv-edges).
//	CIDiff             — new/resolved findings vs a baseline evaluation.
//	BaselineSave       — capture evaluation findings as a baseline file.
//	BaselineCheck      — new/resolved findings vs a saved baseline.
//	GenerateEnforcement — write a PAB/SCP enforcement template from findings.
//	RunDoctor          — local environment readiness checks (text/json).
//	ExportOCSF         — findings as OCSF 1.1 Compliance Finding NDJSON.
//	ExportOSCAL        — findings as OSCAL assessment-results / POA&M JSON.
//	ExportChanges      — remediation property changes as JSON.
//	ExportTickets      — findings as ticket records (json/csv).
//	RenderFeatures     — in-scope (discovered) + out-of-scope capability report.
//	BisectControl      — find when a control was first violated (text/json).
//	ExplainControl     — catalog-only explanation of one control.
//	SuggestControlIDs  — fuzzy-suggest control IDs for a partial query.
//	AssetTypeExamples  — example control ID per asset type.
//	Gaps               — field-level observation coverage gaps.
//	Readiness          — control fire/blocked forecast + action plan.
//	NewReadinessEvaluator — readiness validation closure shared by
//	                     `apply --dry-run` and `validate`.
//	ValidatePackConfiguration — flag unknown enabled control-pack names.
//	DiffSnapshots      — structured diff of two snapshot directories.
//	GetCapabilities    — version + capability counts (controls, packs, frameworks).
//	ExportInvariants   — catalog projected as solver-ready invariants
//	                     (the data shape an external SMT compiler consumes).
//	ExportPolicies     — parsed resource/trust policies for solver export.
//	BuildEvidenceBundle — sealed evidence bundle (+ optional ASFF) from an assessment.
//	AssembleAuditBundle — compliance-period evidence package from assessment history.
//	ExportCompliance   — per-requirement evidence package (json/table/markdown/oscal).
//	DiffObservationDrift — drift between the latest two snapshots (text/json).
//	CoverageGraph      — control→asset coverage graph (dot/json).
//	ExportAssessmentGraph — assessment graph export (json/stix/jsonld/graphml).
//	VerifyRemediation  — before/after attestation report (json) + violation signal.
//	AddAcknowledgment / AddException / AddAssetExemption / RemoveAcceptance
//	                   — mutate the risk-acceptance file (audit-trailed).
//	ListAcceptances / UpcomingAcceptances / AcceptanceHistory
//	                   — render acceptance views (table/json).
//	ValidateAcceptances — validate the acceptance file (returns errors list).
//	ExportRiskRegister — acceptances + open findings as OSCAL POA&M JSON.
//	SuggestExemptions  — chronic/oscillating finding exemption candidates.
//	RunGate            — CI gate verdict (policy + optional team scope; text/json).
//	EnforcementGatePolicies — the supported CI failure policy names.
//	FixFinding         — remediation guidance JSON for a single finding.
//	RunFixLoop         — apply/apply/verify remediation lifecycle + artifacts.
//	ResolvePrincipal   — net effective permissions for one IAM principal (table/json).
//	ResolveResourceAccess — who can reach a resource (table/json/dot) + exit-1 signal.
//	NepSummary         — aggregate net-effective-permission metrics (table/json).
//	TrendReport        — posture-trend report across assessment history (table/json/openmetrics).
//	PredictReadiness   — compliance-readiness achievement-date projection (text/json).
//	ForecastPosture    — posture-score trajectory + SLA status (table/json).
//	ClassifyOscillation — violation oscillation patterns (table/json).
//	ForgePreview / ForgeLivePreview — CEL-evaluate a synthetic predicate
//	                   against a snapshot (control-authoring preview).
//	ForgePaths         — enumerate property paths for an asset type.
//	ForgeSnapshotAssetCount / ForgeSnapshotAssetTypes — snapshot inspection
//	                   for the authoring wizard.
//	ForgeScaffold      — write pass/fail fixtures for a control.
//	ForgeLintWithFormat — lint a control (or directory) for schema/semantics.
//	ForgeChainLint     — lint a chain file against a controls directory.
//	ForgeTest          — fixture-based pass/fail assertions for a control.
//	ForgeValidateGenerated — validate a freshly generated control YAML.
//
// See docs/architecture/pkg-stave-facade.md for the facade pattern,
// the rule cmd/ should obey ("imports only pkg/stave"), and the
// current migration state.
//
// # The standard pattern
//
// Every use case in this package follows the same shape:
//
//  1. A Config struct (Apply: [Config]; Score: [ScoreConfig]; Gate:
//     [GateConfig]) carries the inputs. Required fields are
//     documented; zero values default sensibly. CLI flags map 1:1
//     to Config fields where possible.
//
//  2. A Result struct (Apply: [Assessment]; Score: [ScoreResult];
//     Gate: [GateResult]) carries the outputs. Domain types are
//     re-aliased from internal packages where the wire format is
//     stable; otherwise the result is mirrored to keep the public
//     API independent of engine refactors.
//
//  3. The function is `Verb(ctx, cfg) (*Result, error)`. Adapters
//     are wired internally — the library is responsible for
//     instantiating loaders, evaluators, and any other ports
//     usecase.Verb requires.
//
//  4. Pure operations (no I/O) take only a Config and return the
//     Result; orchestration operations (with I/O) accept a context
//     for cancellation. Score is pure; Apply and Gate orchestrate.
//
// Every use case follows the same `Verb(ctx, cfg) (*Result, error)`
// shape — consumer code that knows one knows them all.
package stave
