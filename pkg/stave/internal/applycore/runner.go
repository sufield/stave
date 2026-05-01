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
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/reachability"
	"github.com/sufield/stave/internal/builtin/capabilities"
	builtinpredicate "github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

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
	AllowUnknownInput   bool
	ExemptionRules      *policy.ExemptionConfig
	AcknowledgmentRules *policy.AcknowledgmentConfig
	SLAConfig           *evaluation.SLAConfig
	GitMetadata         *evaluation.GitInfo
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
// the workflow loaded controls from disk).
type Result struct {
	Report   *evaluation.ComplianceReport
	Controls []policy.ControlDefinition
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

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return nil, fmt.Errorf("initialize CEL evaluator: %w", err)
	}

	obsOpts := []observations.LoaderOption{}
	if in.IntegrityManifest != "" {
		obsOpts = append(obsOpts, observations.WithIntegrityCheck(in.IntegrityManifest, in.IntegrityPublicKey))
	}
	wf := &appeval.AuditWorkflow{
		ObservationRepo: observations.NewObservationLoader(obsOpts...),
		PolicyRepo:      ctlRepo,
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
		appeval.WithAllowUnknownInput(in.AllowUnknownInput),
		appeval.WithExemptionConfig(in.ExemptionRules),
		appeval.WithExceptionConfig(exceptionCfg),
		appeval.WithAcknowledgmentConfig(in.AcknowledgmentRules),
		appeval.WithPreloadedControls(controls),
		appeval.WithGitMetadata(in.GitMetadata),
		appeval.WithPredicateParser(ctlyaml.ParsePredicate),
		appeval.WithCELEvaluator(celEval),
		appeval.WithTracer(in.Tracer),
		appeval.WithChainDefs(chainDefs),
		appeval.WithSLAConfig(in.SLAConfig),
	}
	assessmentCfg := appeval.NewConfig(plan, opts...)
	assessmentCfg.Clock = clock
	assessmentCfg.BuildVersion = version.String
	assessmentCfg.AcceptUnknownData = in.AllowUnknownInput
	assessmentCfg.ActivePolicies = controls

	report, _, err := wf.PerformAssessment(ctx, assessmentCfg)
	if err != nil {
		return nil, err
	}
	if len(wf.LoadedControls) > 0 {
		controls = wf.LoadedControls
	}

	annotateReachability(report.Findings, wf.LoadedSnapshots)

	return &Result{Report: &report, Controls: controls}, nil
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
	return ctlyaml.LoadChains(dir, capabilities.Builtin())
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
func annotateReachability(findings []evaluation.Finding, snapshots []asset.Snapshot) {
	if len(findings) == 0 || len(snapshots) == 0 {
		return
	}
	idx := reachability.BuildIndexFromSnapshot(&snapshots[0])
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
