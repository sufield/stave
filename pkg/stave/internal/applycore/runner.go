// Package applycore is the shared evaluation orchestration used by
// pkg/stave.Apply (public API) and pkg/stave/cliapi.Apply (CLI escape
// hatch). It is internal to pkg/stave/ — Go's internal-package rule
// prevents external consumers from importing it.
//
// Both stave.Apply and cliapi.Apply build the same Inputs from their
// respective configs, call Run, and then convert the *evaluation.ComplianceReport
// into the shape their callers expect (a trimmed *stave.Assessment for
// stave.Apply; both views for cliapi.Apply).
package applycore

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	stavecel "github.com/sufield/stave/internal/adapters/cel"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/adapters/sirbridge"
	appcapabilities "github.com/sufield/stave/internal/app/capabilities"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/reachability"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/capabilities"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/core/sirfacts"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/providers/aws"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
	"github.com/sufield/stave/internal/version"
)

// libraryOnce guards the library-mode init that wires the AWS
// provider and the policy library. cmd/root.NewApp does this for
// CLI users; pkg/stave callers route through Run, so we replicate
// the same wiring here on first call.
var libraryOnce sync.Once

// errLibraryInit captures any panic recovered during library-mode
// init (typically a misconfigured embedded policy library that
// pack.MustNewLibrary refuses to construct). Permanent for the
// process lifetime — sync.Once makes the init body unreachable on
// every call after the first, so a recovered panic on the first
// call permanently disables this runner. Callers receive the
// original panic message wrapped as an error; retries are not
// attempted.
var errLibraryInit error

// isLibraryReady reports whether the embedded policy library and
// cloud adapters initialised successfully. Returns nil on success
// or the captured init error if the one-time bootstrap panicked.
// Names the system-health check so Run reads as "is the library
// ready?" instead of a raw global-error probe — and a future
// change to the bootstrap status (multiple components, partial
// init) lands here.
func isLibraryReady() error {
	return errLibraryInit
}

// DefaultMaxUnsafe is the fallback when Inputs.MaxUnsafe is zero.
// Matches the conventional Stave project default (one week).
const DefaultMaxUnsafe = 168 * time.Hour

// Inputs is the engine-relevant subset of the library config.
// Both stave.Config and cliapi.Apply's config are mapped into this
// shape before calling [Run].
//
// SLAConfig is the already-internal form (evaluation.SLAConfig)
// because the conversion from the public mirror happens at the
// pkg/stave boundary, not here.
//
// GitMetadata, ProjectConfig, and Tracer are optional CLI affordances —
// applycore stamps them onto the output when supplied so the CLI's
// JSON wire format (run.git_metadata, control filtering from
// stave.yaml, --trace logic-trace export) stays identical between
// the library and direct cmd/apply paths.
type Inputs struct {
	SnapshotsDir        string
	ControlsDir         string
	ChainsDir           string
	IntegrityManifest   string
	IntegrityPublicKey  string
	MaxUnsafe           time.Duration
	Now                 time.Time
	ExemptionRules      *policy.ExemptionConfig
	AcknowledgmentRules *policy.AcknowledgmentConfig
	SLAConfig           *evaluation.SLAConfig
	ProjectConfig       *appeval.ProjectConfigInput
	Tracer              ports.Tracer

	// ContextName is the project context label (e.g. "stave") that
	// lands on Metadata.ContextName / output.run.context_name. CLI
	// callers populate from the resolved EvaluationPlan; library
	// callers usually leave empty.
	ContextName string
}

// Result is the engine's output: the full ComplianceReport plus the
// active controls (which may differ from what the caller passed if
// the workflow loaded controls from disk). When SIR projection
// succeeded post-evaluation, each Report.Findings[i] is annotated
// with ContributingFactIDs by applycore before returning — callers
// don't need to run the projection themselves. SIR build failures
// are best-effort: findings ship un-annotated rather than blocking
// the report.
//
// SIRDocument is the raw projection the same applycore pass already
// built for fact-id correlation. Surfacing it on Result lets
// downstream consumers — pkg/stave.ExportGraph in particular — read
// transitive role chains and per-asset lifecycle without rebuilding
// the document. nil when SIR construction failed (the report is
// still returned).
type Result struct {
	Report      *evaluation.ComplianceReport
	Controls    []policy.ControlDefinition
	SIRDocument *sir.Document
}

// Run executes the evaluation pipeline: resolve controls, build the
// AuditWorkflow, run PerformAssessment, then annotate reachability
// using the workflow's retained snapshots.
//
// Errors from individual steps are wrapped with the step name so
// callers can distinguish setup failures (CEL init, control load)
// from evaluation failures.
func Run(ctx context.Context, in Inputs) (*Result, error) {
	if in.SnapshotsDir == "" {
		return nil, errors.New("applycore.Run: SnapshotsDir is required")
	}
	libraryOnce.Do(func() {
		// pack.MustNewLibrary panics on an invalid embedded
		// library — recover so a misconfigured release builds a
		// runnable error path instead of taking down every
		// pkg/stave caller. The error is sticky (see errLibraryInit
		// doc) — sync.Once won't re-enter this body.
		defer func() {
			if r := recover(); r != nil {
				errLibraryInit = fmt.Errorf("applycore: library init panicked: %v", r)
			}
		}()
		aws.Register()
		appcapabilities.Configure(pack.MustNewLibrary())
	})
	if err := isLibraryReady(); err != nil {
		return nil, err
	}

	controls, ctlRepo, err := resolveControls(in.ControlsDir)
	if err != nil {
		return nil, err
	}

	// Project config: when supplied, resolve exception rules and any
	// preloaded controls. nil project config keeps the prior behavior
	// (no exceptions, controls from the standard ControlsDir path).
	var exceptionCfg *policy.ExceptionConfig
	if in.ProjectConfig != nil {
		resolved, resolveErr := appeval.ResolveProjectConfig(*in.ProjectConfig)
		if resolveErr != nil {
			return nil, fmt.Errorf("resolve project config: %w", resolveErr)
		}
		exceptionCfg = resolved.ExceptionConfig
		if len(resolved.PreloadedControls) > 0 {
			controls = resolved.PreloadedControls
			ctlRepo = nil
		}
	}

	maxUnsafe := in.MaxUnsafe
	if maxUnsafe == 0 {
		maxUnsafe = DefaultMaxUnsafe
	}
	clock := buildClock(in.Now)

	// Stave-apply is the only hot path that runs the full control
	// catalog repeatedly; wire it through the persistent on-disk
	// compile cache so warm runs skip parse + type-check.
	// DefaultCacheDir falls back to "" on platforms without an
	// XDG cache dir, which makes the compiler an in-memory-only
	// no-op — identical to the pre-cache behaviour.
	cacheDir, _ := stavecel.DefaultCacheDir()
	var celCompiler *stavecel.Compiler
	celEval, celCompiler, err := stavecel.NewPredicateEvalWithCompiler(stavecel.WithCacheDir(cacheDir))
	if err != nil {
		return nil, fmt.Errorf("initialize CEL evaluator: %w", err)
	}
	defer func() {
		// Best-effort persist on exit. A failed persist is a
		// missed optimisation, not a correctness problem, so we
		// log and move on rather than poisoning the apply result.
		if persistErr := celCompiler.PersistCache(); persistErr != nil {
			slog.Warn("cel: persist cache failed", "err", persistErr)
		}
	}()

	obsOpts := []observations.LoaderOption{}
	if in.IntegrityManifest != "" {
		obsOpts = append(obsOpts, observations.WithIntegrityCheck(in.IntegrityManifest, in.IntegrityPublicKey))
	}
	wf := &appeval.AuditWorkflow{
		ObservationRepo:  observations.NewObservationLoader(obsOpts...),
		PolicyRepo:       ctlRepo,
		SnapshotEnricher: iam.NewChainPropertyEnricher(),
	}

	chainDefs, err := loadChainDefs(in.ChainsDir)
	if err != nil {
		return nil, fmt.Errorf("load chains: %w", err)
	}

	// Build via appeval.NewConfig so Metadata.ContextName /
	// ResolvedPaths / ControlSource defaults match the cmd/apply
	// path that goes through BuildDependencies. Direct struct
	// initialization would skip the NewConfig setup and cause the
	// output JSON to lose the extensions block (context_name,
	// control_source, resolved_paths) that consumers parse.
	plan := appeval.EvaluationPlan{
		ControlsPath:     in.ControlsDir,
		ObservationsPath: in.SnapshotsDir,
		ContextName:      in.ContextName,
	}
	opts := []appeval.Option{
		appeval.WithMaxUnsafeDuration(maxUnsafe),
		appeval.WithHasher(crypto.NewHasher()),
		appeval.WithExemptionConfig(in.ExemptionRules),
		appeval.WithExceptionConfig(exceptionCfg),
		appeval.WithAcknowledgmentConfig(in.AcknowledgmentRules),
		appeval.WithPreloadedControls(controls),
		appeval.WithPredicateParser(ctlyaml.ParsePredicate),
		appeval.WithCELEvaluator(celEval),
		appeval.WithTracer(in.Tracer),
		appeval.WithChainDefs(chainDefs),
		appeval.WithSLAConfig(in.SLAConfig),
	}
	assessmentCfg := appeval.NewConfig(plan, opts...)
	assessmentCfg.Clock = clock
	assessmentCfg.BuildVersion = version.String
	assessmentCfg.ActivePolicies = controls

	report, _, err := wf.PerformAssessment(ctx, assessmentCfg)
	if err != nil {
		return nil, fmt.Errorf("perform assessment: %w", err)
	}
	if loaded := wf.Controls(); len(loaded) > 0 {
		controls = loaded
	}

	annotateReachability(report.Findings, wf.Snapshots())

	sirDoc := annotateContributingFactIDs(report.Findings, controls, wf.Snapshots(), clock.Now(), celEval)

	return &Result{
		Report:      &report,
		Controls:    controls,
		SIRDocument: sirDoc,
	}, nil
}

// annotateContributingFactIDs builds the SIR document for the same
// (controls, snapshots, now) the evaluation just consumed and
// stamps each finding's ContributingFactIDs from the resulting
// fact_ids whose Subject equals the finding's AssetID. The
// annotation closes the trace from a CEL finding to the
// `stave export-sir` outputs that describe the same asset.
//
// Best-effort: a SIR builder failure is silent — findings ship
// un-annotated rather than blocking the report. The omitempty
// json tag on ContributingFactIDs preserves the prior wire shape
// for consumers that don't read the new field.
//
// Determinism: [sirfacts.ExtractFacts] sorts its inner walks;
// per-subject grouping here preserves projection emission order.
// Subjects with zero facts (control IDs that never produced a
// fact, or principals not represented as assets) leave the
// finding's slice nil — callers must treat absence as "no facts"
// rather than an error.
func annotateContributingFactIDs(
	findings []evaluation.Finding,
	controls []policy.ControlDefinition,
	snapshots []asset.Snapshot,
	now time.Time,
	celEval policy.PredicateEval,
) *sir.Document {
	// The SIR is built unconditionally — even with zero findings
	// there are consumers (Result.SIRDocument → cmd/exportsir,
	// pkg/stave.ExportGraph) that need the document. Skipping when
	// findings is empty would silently break `stave export-sir`
	// on a fixture that has nothing to flag (a remediated-config
	// snapshot, for example).
	//
	// The CoverageSource matches cmd/exportsir's expectations
	// (same DefaultContinuityLimit thresholds) so applycore's
	// Result.SIRDocument and `stave export-sir --format json`
	// are byte-identical for the same (controls, snapshots, now)
	// triple. Coverage source has no effect on fact extraction —
	// facts don't include the coverage report — but having both
	// callers see identical SIR documents matters for the
	// "library and CLI route through one builder" invariant.
	//
	// A coverage-source construction failure is non-fatal:
	// fact-id annotation is best-effort already (a SIR build
	// failure leaves findings un-annotated rather than blocking
	// the report). Falling back to a nil source preserves the
	// prior behaviour rather than degrading findings.
	opts := []sir.Option{
		sir.WithRoleChainSource(sirbridge.NewAWSRoleChainSource()),
		sir.WithLifecycleSource(sirbridge.NewEngineLifecycleSource(celEval)),
		sir.WithResourceFactGrouper(sirbridge.NewAWSS3FactGrouper()),
	}
	if coverageSrc, covErr := sirbridge.NewEngineCoverageSource(engine.DefaultContinuityLimit, engine.DefaultContinuityLimit); covErr == nil {
		opts = append(opts, sir.WithCoverageSource(coverageSrc))
	}
	builder := sir.NewBuilder(opts...)
	doc, err := builder.Build(controls, snapshots, now)
	if err != nil || doc == nil {
		return nil
	}
	facts := sirfacts.ExtractFacts(doc)
	bySubject := make(map[string][]string, len(facts))
	for _, f := range facts {
		if f.Subject == "" || f.FactID == "" {
			continue
		}
		bySubject[f.Subject] = append(bySubject[f.Subject], f.FactID)
	}
	for i := range findings {
		if ids, ok := bySubject[string(findings[i].AssetID)]; ok && len(ids) > 0 {
			findings[i].ContributingFactIDs = ids
		}
	}
	return doc
}

// LoadControls loads the control catalog for read-only inspection
// (e.g. fingerprint explain). Empty dir uses the embedded catalog.
func LoadControls(dir string) ([]policy.ControlDefinition, error) {
	libraryOnce.Do(func() {
		defer func() {
			if r := recover(); r != nil {
				errLibraryInit = fmt.Errorf("applycore: library init panicked: %v", r)
			}
		}()
		aws.Register()
		appcapabilities.Configure(pack.MustNewLibrary())
	})
	if err := isLibraryReady(); err != nil {
		return nil, err
	}
	controls, repo, err := resolveControls(dir)
	if err != nil {
		return nil, err
	}
	if repo != nil {
		controls, err = appcontracts.LoadControls(context.Background(), repo, dir)
		if err != nil {
			return nil, fmt.Errorf("load controls from dir: %w", err)
		}
	}
	return controls, nil
}

// resolveControls loads the control set used by the evaluation.
// Empty dir uses the embedded builtin catalog. Non-empty dir defers
// loading to the workflow's PolicyRepo.
func resolveControls(dir string) ([]policy.ControlDefinition, appcontracts.ControlRepository, error) {
	if dir != "" {
		loader := ctlyaml.NewControlLoader(ctlyaml.WithAliasResolver(builtinpredicate.ResolverFunc()))
		return nil, loader, nil
	}
	store := ctlbuiltin.NewControlStore(
		ctlbuiltin.EmbeddedFS(),
		"embedded",
		ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc()),
	)
	controls, err := store.All()
	if err != nil {
		return nil, nil, fmt.Errorf("load builtin controls: %w", err)
	}
	return controls, nil, nil
}

// loadChainDefs reads chain definitions from dir. Empty dir or
// missing dir returns nil with no error — chain detection silently
// disables when no chains are configured.
func loadChainDefs(dir string) ([]policy.ChainDefinition, error) {
	if dir == "" {
		return nil, nil
	}
	chains, err := ctlyaml.LoadChains(dir, capabilities.Builtin())
	if err != nil {
		return nil, fmt.Errorf("load chains: %w", err)
	}
	return chains, nil
}

// buildClock returns a FixedClock when now is non-zero, otherwise a
// RealClock. Mirrors the cmd/apply behavior so library and CLI runs
// observe time the same way given the same Now value.
func buildClock(now time.Time) ports.Clock {
	if !now.IsZero() {
		return ports.FixedClock(now)
	}
	return ports.RealClock{}
}

// annotateReachability adds IAM-reachability context to findings
// using the in-memory snapshots. Silently no-ops when the snapshots
// have no IAM data — adopters without identity collection should
// see findings unchanged.
//
// Builds a merged index across every snapshot in the history rather
// than only snapshots[0]: a policy that landed in a later capture
// must still influence the reachability annotation for any finding
// that names the same asset.
func annotateReachability(findings []evaluation.Finding, snapshots []asset.Snapshot) {
	if len(findings) == 0 || len(snapshots) == 0 {
		return
	}
	idx := iam.BuildResourceAccessIndexFromSnapshots(snapshots)
	if idx == nil {
		return
	}
	for i := range findings {
		entries := idx.EntriesFor(string(findings[i].AssetID))
		if len(entries) == 0 {
			continue
		}
		findings[i].Reachability = reachability.BuildContext(entries)
	}
}
