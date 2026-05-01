package stave

import (
	"context"
	"errors"
	"fmt"
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	covadapter "github.com/sufield/stave/internal/adapters/coverage"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/builtin/capabilities"
	builtinpredicate "github.com/sufield/stave/internal/builtin/predicate"
	stavecel "github.com/sufield/stave/internal/cel"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/usecase"
	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/version"
)

// defaultMaxUnsafe is the library's fallback when Config.MaxUnsafe
// is zero. Matches the conventional Stave project default (one week).
const defaultMaxUnsafe = 168 * time.Hour

// Apply runs Stave's control evaluation against the snapshots in
// cfg.SnapshotsDir and returns the typed assessment. Equivalent to
// `./stave apply` on the command line, minus CLI concerns
// (formatting, team manifests, SLA overlays, output paths).
//
// Apply routes through [usecase.Apply] — the canonical application-
// layer entry point — with a library-provided evaluation-runner
// adapter. The CLI path remains untouched.
func Apply(ctx context.Context, cfg Config) (*Assessment, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("stave.Apply: Config.SnapshotsDir is required")
	}

	req := usecase.ApplyRequest{
		ControlsDir:       cfg.ControlsDir,
		ObservationsDir:   cfg.SnapshotsDir,
		MaxUnsafeDuration: formatDuration(cfg.MaxUnsafe),
		NowTime:           formatTime(cfg.Now),
		AllowUnknownInput: cfg.AllowUnknownInput,
	}
	deps := usecase.ApplyDeps{Runner: &workflowRunner{chainsDir: cfg.ChainsDir}}

	resp, err := usecase.Apply(ctx, req, deps)
	if err != nil {
		return nil, err
	}

	result, ok := resp.EvaluationData.(*evaluationResult)
	if !ok {
		return nil, fmt.Errorf("stave.Apply: unexpected evaluation data type %T", resp.EvaluationData)
	}
	return buildAssessment(result.Report, result.Controls), nil
}

// evaluationResult is the typed payload the library's runner puts
// into ApplyResponse.EvaluationData. Using a concrete type instead
// of `any` lets the conversion back to Assessment be a single type
// assertion rather than reflection.
type evaluationResult struct {
	Report   *evaluation.ComplianceReport
	Controls []policy.ControlDefinition
}

// workflowRunner implements [usecase.EvaluationRunnerPort] against
// the production [appeval.AuditWorkflow]. It is the first (and
// currently only) production implementation of the port; the CLI
// bypasses usecase.Apply and calls the workflow directly.
//
// chainsDir is a library-path-specific field not present on
// ApplyRequest — the CLI path loads chains from a hardcoded "chains"
// directory relative to the project root; the library requires an
// explicit Config.ChainsDir so calls from any working directory work
// correctly.
type workflowRunner struct {
	chainsDir string
}

func (r *workflowRunner) RunEvaluation(ctx context.Context, req usecase.ApplyRequest) (usecase.ApplyResponse, error) {
	controls, ctlRepo, err := resolveControls(req.ControlsDir)
	if err != nil {
		return usecase.ApplyResponse{}, err
	}

	sla, err := parseDurationOrDefault(req.MaxUnsafeDuration, defaultMaxUnsafe)
	if err != nil {
		return usecase.ApplyResponse{}, fmt.Errorf("parse max-unsafe: %w", err)
	}
	clock, err := parseClock(req.NowTime)
	if err != nil {
		return usecase.ApplyResponse{}, fmt.Errorf("parse now: %w", err)
	}

	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		return usecase.ApplyResponse{}, fmt.Errorf("initialize CEL evaluator: %w", err)
	}

	wf := &appeval.AuditWorkflow{
		ObservationRepo: observations.NewObservationLoader(),
		PolicyRepo:      ctlRepo,
	}

	chainDefs, err := loadChainDefs(r.chainsDir)
	if err != nil {
		return usecase.ApplyResponse{}, fmt.Errorf("load chains: %w", err)
	}

	cfg := appeval.AssessmentConfig{
		ObservationConfig: appeval.ObservationConfig{
			PolicySource:      req.ControlsDir,
			ObservationSource: req.ObservationsDir,
			AcceptUnknownData: req.AllowUnknownInput,
			ActivePolicies:    controls,
		},
		ChainDefs:       chainDefs,
		SLAThreshold:    sla,
		Clock:           clock,
		Hasher:          crypto.NewHasher(),
		PredicateParser: ctlyaml.ParsePredicate,
		PredicateEval:   celEval,
		BuildVersion:    version.String,
	}

	report, _, err := wf.PerformAssessment(ctx, cfg)
	if err != nil {
		return usecase.ApplyResponse{}, err
	}
	if len(wf.LoadedControls) > 0 {
		controls = wf.LoadedControls
	}

	return usecase.ApplyResponse{
		EvaluationData: &evaluationResult{Report: &report, Controls: controls},
		HasViolations:  len(report.Findings) > 0,
	}, nil
}

// loadChainDefs loads chain definitions from dir. Empty dir returns
// nil (chain detection silently disabled). Missing dir returns nil
// with no error — adopters who haven't opted into chain detection
// shouldn't be blocked by the absence of a chains/ directory.
func loadChainDefs(dir string) ([]policy.ChainDefinition, error) {
	if dir == "" {
		return nil, nil
	}
	return ctlyaml.LoadChains(dir, capabilities.Builtin())
}

// resolveControls loads the control set used by the evaluation.
// When dir is empty the embedded builtin catalog is preloaded and
// returned via ActivePolicies; no ControlRepository is needed. When
// dir is set, the YAML loader is returned and the workflow loads
// from disk.
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

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	return d.String()
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func parseDurationOrDefault(s string, def time.Duration) (time.Duration, error) {
	if s == "" {
		return def, nil
	}
	return time.ParseDuration(s)
}

func parseClock(nowRFC3339 string) (ports.Clock, error) {
	if nowRFC3339 == "" {
		return ports.RealClock{}, nil
	}
	t, err := time.Parse(time.RFC3339, nowRFC3339)
	if err != nil {
		return nil, err
	}
	return ports.FixedClock(t), nil
}

// buildAssessment converts the internal evaluation report into the
// library's public [Assessment] shape. This is the single
// conversion point that translates internal types into the
// library's curated subset.
func buildAssessment(report *evaluation.ComplianceReport, controls []policy.ControlDefinition) *Assessment {
	return &Assessment{
		SchemaVersion: string(kernel.SchemaOutput),
		Status:        Status(report.SecurityState),
		Run: RunInfo{
			StaveVersion: report.Run.StaveVersion,
			Now:          report.Run.Now,
			MaxUnsafe:    time.Duration(report.Run.MaxUnsafeDuration),
			Snapshots:    report.Run.Snapshots,
		},
		Summary: Summary{
			TotalAssets:      report.Summary.TotalAssets,
			ExposedResources: report.Summary.ExposedResources,
			Violations:       report.Summary.Violations,
		},
		Findings:      convertFindings(report.Findings),
		Issues:        report.Issues,
		Coverage:      buildCoverage(controls),
		ChainFindings: convertChainFindings(report.ChainFindings),
	}
}

// convertChainFindings copies compound-finding records from the
// internal report into the library's typed ChainFinding slice,
// applying ChainID typing at the boundary.
func convertChainFindings(cfs []risk.CompoundFinding) []ChainFinding {
	if len(cfs) == 0 {
		return nil
	}
	out := make([]ChainFinding, len(cfs))
	for i := range cfs {
		out[i] = convertCompoundFinding(&cfs[i])
	}
	return out
}

func convertFindings(fs []evaluation.Finding) []Finding {
	out := make([]Finding, len(fs))
	for i := range fs {
		out[i] = convertFinding(&fs[i])
	}
	return out
}

func convertFinding(f *evaluation.Finding) Finding {
	return Finding{
		FindingID:         f.FindingID,
		ControlID:         f.ControlID,
		ControlName:       f.ControlName,
		AssetID:           f.AssetID,
		AssetType:         f.AssetType,
		Severity:          Severity(f.ControlSeverity.String()),
		Classification:    f.Classification,
		ScopeTags:         f.ScopeTags,
		ControlCompliance: convertCompliance(f.ControlCompliance),
		Remediation:       convertRemediation(f),
		ReasoningTrace:    f.ReasoningTrace,
		ChainMembership:   convertChainMembership(f.ChainMembership),
		ChainBonus:        chainBonusFromBreakdown(f),
		ExposureScore:     f.ExposureScore,
		Defect:            f.Defect,
		Infection:         f.Infection,
		Failure:           f.Failure,
		Delta:             convertDelta(f.Delta),
	}
}

// chainBonusFromBreakdown reads the chain-bonus multiplier off the
// internal finding's ScoreBreakdown. Default 1.0 when the breakdown
// hasn't been populated (pre-enrichment findings) or when the finding
// doesn't belong to any chain.
func chainBonusFromBreakdown(f *evaluation.Finding) float64 {
	if f.ScoreBreakdown == nil {
		return 1.0
	}
	if f.ScoreBreakdown.ChainBonus == 0 {
		return 1.0
	}
	return f.ScoreBreakdown.ChainBonus
}

func convertDelta(ds []policy.DeltaPath) []DeltaPath {
	if len(ds) == 0 {
		return nil
	}
	out := make([]DeltaPath, len(ds))
	for i, d := range ds {
		out[i] = DeltaPath{
			PropertyLabel: d.PropertyLabel,
			PropertyPath:  d.PropertyPath,
			CurrentValue:  d.CurrentValue,
			FixAction:     d.FixAction,
		}
	}
	return out
}

func convertCompliance(m policy.ComplianceMapping) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[string(k)] = v
	}
	return out
}

// convertRemediation resolves the finding's remediation guidance
// the same way the enrichment pipeline does: catalog-authored spec
// first, class-based default as fallback. Consumers get a
// non-empty Remediation whenever the engine can produce one.
func convertRemediation(f *evaluation.Finding) Remediation {
	spec := remediationSpecFor(f)
	return Remediation{
		Description: spec.Description,
		Action:      spec.Action,
		Example:     spec.Example,
	}
}

func remediationSpecFor(f *evaluation.Finding) policy.RemediationSpec {
	if f.ControlRemediation != nil {
		return *f.ControlRemediation
	}
	return policy.DefaultRemediationForClass(f.ControlID.Classify())
}

// buildCoverage builds the per-tool, per-domain coverage posture
// using the same path the CLI uses: load the embedded alternative-
// tool inventories and aggregate them against the active controls.
// Inventory load errors are treated as absence — coverage posture
// is decorative, not load-bearing.
func buildCoverage(controls []policy.ControlDefinition) CoveragePosture {
	if len(controls) == 0 {
		return CoveragePosture{}
	}
	inventories, err := covadapter.LoadEmbedded()
	if err != nil {
		return CoveragePosture{}
	}
	return coverage.BuildCoverageIndex(controls, inventories)
}
