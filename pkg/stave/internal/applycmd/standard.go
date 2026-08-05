package applycmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sufield/stave/internal/adapters/acknowledgment"
	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
	"github.com/sufield/stave/internal/adapters/exemption"
	"github.com/sufield/stave/internal/adapters/observations"
	builtinpredicate "github.com/sufield/stave/internal/adapters/predicate"
	"github.com/sufield/stave/internal/adapters/sla"
	"github.com/sufield/stave/internal/adapters/telemetry"
	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/app/exemptlapse"
	"github.com/sufield/stave/internal/app/reachability"
	"github.com/sufield/stave/internal/app/staleness"
	"github.com/sufield/stave/internal/app/teams"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/providers/aws/iam"
	"github.com/sufield/stave/internal/sanitize"
	"github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
	"gopkg.in/yaml.v3"
)

// ErrInvalidInput marks input errors in the standard pipeline (bad
// --new-since, missing --history-dir) so the pkg/stave facade maps them to
// ErrInvalidInput (exit 2).
var ErrInvalidInput = errors.New("invalid input")

// StandardRequest is the parsed input for the default `apply` (standard
// evaluation) path. Most fields are primitives; ProjectConfig is the
// already-loaded stave.yaml policy (the command-side cleanliness of passing
// it is resolved when the dispatch is wired — increment 3c-ii).
type StandardRequest struct {
	ControlsDir        string
	ObservationsDir    string
	MaxUnsafe          string // raw --max-unsafe (e.g. "168h", "7d"); parsed by the engine
	EvalTime           string // raw --eval-time (RFC3339) or ""; parsed by the engine
	SanitizeIDs        bool
	PathMode           string
	Format             string
	Verbose            bool
	ExemptionFile      string
	AckFile            string
	IntegrityManifest  string
	IntegrityPublicKey string
	SLAProfile         string
	SLAProfileFile     string
	TeamManifest       string
	OwnerFilter        []string
	TracePath          string
	UseBuiltin         bool
	ContextName        string
	ControlsFlagSet    bool
	AssertRecent       string    // --assert-recent: fail fast if newest snapshot older than this
	FreshnessThreshold string    // --freshness-threshold: downgrade confidence when stale (default "24h")
	SkipFreshness      bool      // --skip-freshness: disable confidence downgrade
	Stdin              io.Reader // used only when ObservationsDir == "-" (stdin observations)
	// ProjectConfigPath is the resolved stave.yaml path (from command-side
	// projconfig discovery), or "" when no project config applies. The engine
	// loads it — the command holds only the path string, never the policy type.
	ProjectConfigPath string

	// New-only mode (--new-only / --new-since): the output becomes the
	// new/returned/resolved diff against HistoryDir. Gating is unchanged.
	NewOnly    bool
	NewSince   string
	HistoryDir string

	// ControlIDAllowlist scopes evaluation to only these control IDs
	// (`apply --pack`). Empty = whole catalog.
	ControlIDAllowlist []string

	// GraphFindingsDir points to pre-computed Soufflé .csv output.
	// When set, graph-based chain findings are appended to the report.
	GraphFindingsDir string

	// IncludeAtomic includes per-control (atomic) findings in output.
	// When false (default), only compound chain findings are rendered;
	// atomic findings still evaluate but are suppressed from output.
	IncludeAtomic bool

	FindingsOnly      bool // --findings-only: suppress indeterminate from output
	IndeterminateOnly bool // --indeterminate-only: suppress confirmed findings from output
}

// StandardResult is the rendered outcome of a standard evaluation. Everything
// the command needs for exit routing + summary rendering crosses as a
// primitive so the command holds no internal evaluation types.
type StandardResult struct {
	Output                     []byte   // the report (stdout)
	Warnings                   []string // stderr-bound (new-only history warnings)
	SecurityState              string   // COMPLIANT | AT_RISK | NON_COMPLIANT
	Gate                       string   // ALLOW | ADVISORY | BLOCK
	SummaryMessage             string   // outcome.SummaryMessage()
	HasSLABreach               bool
	HasCriticalSLABreach       bool
	LapsedExemptionCount       int
	CompoundFindingCount       int  // number of compound chain findings
	CompoundOnlyMode           bool // true when atomic findings suppressed
	UnchainedHighSeverityCount int  // critical/high findings not in any chain
	IndeterminateCount         int  // controls that could not be evaluated (data gaps)
}

// EvaluateStandard runs the default `apply` pipeline: load exemption/
// acknowledgment/SLA/project config, evaluate via the applycore engine,
// annotate owner + reachability context, render the report to bytes, and
// compute the gating decision. NOTE: --new-only / --new-since filtering is
// not yet handled here (added in a follow-up); callers must not pass it until
// then.
func EvaluateStandard(ctx context.Context, req StandardRequest) (StandardResult, error) {
	exemptionCfg, err := loadExemptionConfig(req.ExemptionFile)
	if err != nil {
		return StandardResult{}, err
	}
	ackCfg, err := loadAcknowledgmentConfig(req.AckFile)
	if err != nil {
		return StandardResult{}, err
	}
	projCfg, err := loadWorkspacePolicy(req.ProjectConfigPath)
	if err != nil {
		return StandardResult{}, err
	}
	projCfgInput, err := buildProjectConfigInput(projCfg, req.ControlsFlagSet)
	if err != nil {
		return StandardResult{}, err
	}

	slaCfg, err := sla.NewProvider().LoadSLAConfig(ctx, req.SLAProfile, req.SLAProfileFile)
	if err != nil {
		return StandardResult{}, fmt.Errorf("load SLA policy: %w", err)
	}

	maxUnsafe, now, err := parseStandardTimes(req.MaxUnsafe, req.EvalTime)
	if err != nil {
		return StandardResult{}, err
	}

	// Staleness gate (--assert-recent): run before evaluation so a stale
	// snapshot fails fast. A breach maps to exit 2 via ErrInvalidInput.
	if req.AssertRecent != "" && req.ObservationsDir != "-" {
		if msg, stale, serr := checkStaleness(ctx, req.ObservationsDir, req.AssertRecent, now); serr != nil {
			return StandardResult{}, serr
		} else if stale {
			return StandardResult{}, fmt.Errorf("%s: %w", msg, ErrInvalidInput)
		}
	}

	var tracer ports.Tracer
	var fileTracer *telemetry.LocalFileTracer
	if req.TracePath != "" {
		fileTracer = telemetry.NewLocalFileTracer()
		tracer = fileTracer
	}

	// Built-in catalog fallback: an empty ControlsDir tells the engine to
	// select the embedded catalog rather than load a non-existent directory.
	controlsDir := req.ControlsDir
	if req.UseBuiltin {
		controlsDir = ""
	}

	// Stdin observations (`apply -o -`): override the dir loader with a
	// stdin-reading repository so applycore reads the bundle from req.Stdin.
	var obsRepo appcontracts.ObservationRepository
	if req.ObservationsDir == "-" {
		stdinRepo, serr := observations.NewStdinObservationLoader(observations.NewObservationLoader(), req.Stdin)
		if serr != nil {
			return StandardResult{}, fmt.Errorf("init stdin observation loader: %w", serr)
		}
		obsRepo = stdinRepo
	}

	result, err := applycore.Run(ctx, applycore.Inputs{
		SnapshotsDir:        req.ObservationsDir,
		ControlsDir:         controlsDir,
		ChainsDir:           "chains",
		IntegrityManifest:   req.IntegrityManifest,
		IntegrityPublicKey:  req.IntegrityPublicKey,
		MaxUnsafe:           maxUnsafe,
		EvalTime:            now,
		ExemptionRules:      exemptionCfg,
		AcknowledgmentRules: ackCfg,
		SLAConfig:           slaCfg,
		ProjectConfig:       &projCfgInput,
		Tracer:              tracer,
		ContextName:         req.ContextName,
		ObservationRepo:     obsRepo,
		ControlIDAllowlist:  req.ControlIDAllowlist,
		GraphFindingsDir:    req.GraphFindingsDir,
	})
	if err != nil {
		return StandardResult{}, fmt.Errorf("evaluate: %w", err)
	}
	report := result.Report

	if err = annotateOwners(report, req.TeamManifest, req.OwnerFilter); err != nil {
		return StandardResult{}, err
	}
	if err = annotateReachability(report, req.ObservationsDir); err != nil {
		return StandardResult{}, err
	}
	if err = annotateFreshness(report, req.ObservationsDir, req.FreshnessThreshold, req.SkipFreshness, now); err != nil {
		return StandardResult{}, err
	}

	var out []byte
	var warnings []string
	if req.NewOnly {
		// Signal-filtered output replaces the standard report; gating below
		// is computed from the same report regardless.
		out, warnings, err = evaluateNewOnly(ctx, req, report, now)
	} else {
		sanitizer := sanitize.Policy{SanitizeIDs: req.SanitizeIDs, PathMode: sanitize.PathMode(req.PathMode)}.NewSanitizer()
		out, err = renderReport(ctx, req.Format, req.Verbose, req.IncludeAtomic, req.FindingsOnly, req.IndeterminateOnly, sanitizer, report, result.Controls)
	}
	if err != nil {
		return StandardResult{}, err
	}

	if fileTracer != nil {
		lt := fileTracer.Finalize(ports.FinalizeArgs{StaveVersion: version.String})
		if writeErr := telemetry.WriteTraceFile(lt, req.TracePath); writeErr != nil {
			slog.Warn("failed to write logic trace", "path", req.TracePath, "error", writeErr)
		}
	}

	lapsed := exemptlapse.Detect(exemptlapse.Input{
		Findings: report.Findings,
		EvalTime: now,
	})

	outcome := evaluation.EnforcementPolicy{}.Evaluate(report.SecurityState)

	compoundOnly := !req.IncludeAtomic && len(report.ChainFindings) > 0

	var unchainedCount int
	if compoundOnly {
		atomicIDs := make([]kernel.ControlID, len(report.Findings))
		atomicSevs := make(map[kernel.ControlID]policy.Severity, len(report.Findings))
		for i := range report.Findings {
			atomicIDs[i] = report.Findings[i].ControlID
			atomicSevs[report.Findings[i].ControlID] = report.Findings[i].ControlSeverity
		}
		unchainedCount = len(risk.LintUnchainedHighSeverity(atomicIDs, atomicSevs, report.ChainFindings))
	}

	return StandardResult{
		Output:                     out,
		Warnings:                   warnings,
		SecurityState:              string(report.SecurityState),
		Gate:                       string(outcome.Signal),
		SummaryMessage:             outcome.SummaryMessage(),
		HasSLABreach:               report.HasAnySLABreach(),
		HasCriticalSLABreach:       report.HasCriticalSLABreach(),
		LapsedExemptionCount:       len(lapsed),
		CompoundFindingCount:       len(report.ChainFindings),
		CompoundOnlyMode:           compoundOnly,
		UnchainedHighSeverityCount: unchainedCount,
		IndeterminateCount:         report.Summary.Indeterminate,
	}, nil
}

// parseStandardTimes parses the raw --max-unsafe and --eval-time flag strings into
// the engine's reference duration and time. Bad values wrap ErrInvalidInput
// (exit 2).
//
// When --eval-time is empty it materializes the wall clock as time.Now().UTC(),
// matching the pre-facade command which passed params.clock.Now()
// (ports.RealClock{}.Now() == time.Now().UTC()) as a concrete time. The engine
// then builds a FixedClock (IsUserProvided=true) and uses that wall clock as
// the audit reference. Returning the zero time instead would make the engine
// fall back to the latest snapshot's CapturedAt (RealClock, IsUserProvided=
// false), silently changing durations, security_state, gating, and the exit
// code on every no---eval-time run. --eval-time is normalized to UTC to match the
// pre-facade parseEvalTime, so non-UTC offsets render byte-identically.
func parseStandardTimes(maxUnsafeStr, nowStr string) (time.Duration, time.Time, error) {
	// Parse unconditionally: the pre-facade appeval.parseMaxUnsafeDuration
	// rejected an empty value (kernel.ParseDuration → ErrEmptyDuration → exit
	// 2). Guarding on != "" would silently treat an explicit --max-unsafe ""
	// as 0 and evaluate (exit 3), a behavior change.
	maxUnsafe, err := kernel.ParseDuration(maxUnsafeStr)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("parse --max-unsafe %q: %w: %w", maxUnsafeStr, err, ErrInvalidInput)
	}
	if nowStr == "" {
		return maxUnsafe, time.Now().UTC(), nil
	}
	t, err := time.Parse(time.RFC3339, nowStr)
	if err != nil {
		return 0, time.Time{}, fmt.Errorf("parse --eval-time %q: %w: %w", nowStr, err, ErrInvalidInput)
	}
	return maxUnsafe, t.UTC(), nil
}

// checkStaleness loads snapshots and applies the --assert-recent threshold.
// Returns (message, stale, error); a malformed duration is surfaced as a
// stale message so the command maps it to exit 2.
func checkStaleness(ctx context.Context, obsDir, assertRecent string, now time.Time) (string, bool, error) {
	threshold, err := time.ParseDuration(assertRecent)
	if err != nil {
		return fmt.Sprintf("parse --assert-recent %q: %v", assertRecent, err), true, nil
	}
	loaded, err := observations.NewObservationLoader().LoadSnapshots(ctx, obsDir)
	if err != nil {
		return "", false, fmt.Errorf("load snapshots for staleness check: %w", err)
	}
	sr := staleness.Check(loaded.Snapshots, threshold, now)
	if sr.Stale {
		return sr.Message, true, nil
	}
	return "", false, nil
}

// renderReport runs the output pipeline (marshaler + enricher + coverage)
// into a byte buffer. When includeAtomic is false, per-control findings are
// suppressed from the output (compound-only default mode).
func renderReport(ctx context.Context, format string, verbose bool, includeAtomic bool, findingsOnly bool, indeterminateOnly bool, sanitizer kernel.Sanitizer, report *evaluation.ComplianceReport, controls []policy.ControlDefinition) ([]byte, error) {
	marshaler, err := buildFindingWriter(format, verbose)
	if err != nil {
		return nil, err
	}
	enricher := remediation.NewPlanner()

	atomicCount := len(report.Findings)
	severityCounts := evaluation.CountBySeverity(report.Findings)

	atomicControlIDs := make([]kernel.ControlID, 0, len(report.Findings))
	atomicSeverities := make(map[kernel.ControlID]policy.Severity, len(report.Findings))
	atomicFailures := make([]risk.FailingControl, 0, len(report.Findings))
	for i := range report.Findings {
		cid := report.Findings[i].ControlID
		atomicControlIDs = append(atomicControlIDs, cid)
		atomicSeverities[cid] = report.Findings[i].ControlSeverity
		atomicFailures = append(atomicFailures, report.Findings[i].ToFailingControl())
	}
	controlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		controlLookup[controls[i].ID] = &controls[i]
	}

	enrichFn := func(rep *evaluation.ComplianceReport) (appcontracts.EnrichedResult, error) {
		enriched, enrichErr := appeval.Enrich(enricher, sanitizer, rep)
		if enrichErr != nil {
			return enriched, fmt.Errorf("enrich findings: %w", enrichErr)
		}
		if !includeAtomic && len(rep.ChainFindings) > 0 {
			enriched.Result.CompoundOnlyMode = true
			enriched.Result.SuppressedAtomicCount = atomicCount
			enriched.Result.SuppressedBySeverity = &severityCounts
			enriched.Result.UnchainedHighSeverity = risk.LintUnchainedHighSeverity(
				atomicControlIDs, atomicSeverities, rep.ChainFindings)
			enriched.Result.ChainSuggestions = risk.SuggestChains(
				atomicFailures, rep.ChainFindings, controlLookup)
			enriched.Findings = nil
			enriched.MarkerFindings = nil
		}
		if findingsOnly {
			enriched.IndeterminateFindings = nil
		}
		if indeterminateOnly {
			enriched.Findings = nil
			enriched.MarkerFindings = nil
		}
		return enriched, nil
	}
	pipeline := &appeval.OutputPipeline{
		Marshaler:       marshaler,
		Enricher:        enrichFn,
		CoveragePosture: buildCoveragePosture(controls, nil),
	}
	var buf bytes.Buffer
	if err := pipeline.Run(ctx, &buf, report); err != nil {
		return nil, fmt.Errorf("run output pipeline: %w", err)
	}
	data := buf.Bytes()
	if len(data) == 0 {
		return nil, errors.New("output pipeline produced empty output")
	}
	if format == "json" && !json.Valid(data) {
		return nil, fmt.Errorf("output pipeline produced invalid JSON (%d bytes)", len(data))
	}
	return data, nil
}

// --- enrichment (moved verbatim from cmd/apply/run_owners.go + run_reachability.go) ---

func annotateOwners(report *evaluation.ComplianceReport, teamManifest string, ownerFilter []string) error {
	manifestPath := resolveTeamManifest(teamManifest)
	if manifestPath == "" {
		if len(ownerFilter) > 0 {
			return errors.New("--owner-filter requires a team manifest (set --team-manifest or place stave-teams.yaml in cwd)")
		}
		return nil
	}

	manifest, err := teams.LoadManifest(manifestPath)
	if err != nil {
		if len(ownerFilter) > 0 {
			return fmt.Errorf("load team manifest %q: %w", manifestPath, err)
		}
		slog.Warn("skipping owner annotation", "manifest", manifestPath, "error", err)
		return nil
	}

	for i := range report.Findings {
		f := &report.Findings[i]
		owner := manifest.ResolveOwner(nil, string(f.AssetID), string(f.ControlID))
		f.OwnerTeamID = kernel.TeamID(owner.TeamID)
		f.OwnerTeamName = owner.TeamName
		f.OwnerContact = owner.Contact
		f.OwnerResolution = owner.ResolutionPath
	}

	if len(ownerFilter) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(ownerFilter))
	for _, id := range ownerFilter {
		allowed[strings.TrimSpace(id)] = struct{}{}
	}
	filtered := make([]evaluation.Finding, 0, len(report.Findings))
	for i := range report.Findings {
		if report.Findings[i].MatchesOwner(allowed) {
			filtered = append(filtered, report.Findings[i])
		}
	}
	report.Findings = filtered
	return nil
}

func resolveTeamManifest(flagPath string) string {
	if flagPath != "" {
		return flagPath
	}
	const defaultPath = "stave-teams.yaml"
	if _, err := os.Stat(defaultPath); err == nil {
		return defaultPath
	}
	return ""
}

const reachabilityBundleName = "observations.json"

func annotateReachability(report *evaluation.ComplianceReport, obsDir string) error {
	if obsDir == "" || len(report.Findings) == 0 {
		return nil
	}
	if obsDir == "-" {
		slog.Debug("annotate reachability: stdin observation mode; skipping bundle lookup", "obs_dir", obsDir)
		return nil
	}

	bundlePath := filepath.Join(obsDir, reachabilityBundleName)
	snapshots, err := observations.LoadBundle(bundlePath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			slog.Debug("annotate reachability: no bundle file in observations dir; skipping", "obs_dir", obsDir)
			return nil
		}
		return fmt.Errorf("annotate reachability: malformed bundle at %q: %w", bundlePath, err)
	}
	if len(snapshots) == 0 {
		return nil
	}
	snap := &snapshots[len(snapshots)-1]
	idx := iam.BuildResourceAccessIndex(snap)
	if idx == nil {
		return nil
	}

	remFindings := make([]remediation.Finding, len(report.Findings))
	for i := range report.Findings {
		remFindings[i] = remediation.Finding{Finding: report.Findings[i]}
	}
	reachability.AnnotateFindings(remFindings, idx)
	for i := range remFindings {
		report.Findings[i].Reachability = remFindings[i].Reachability
	}
	return nil
}

// annotateFreshness runs the FM-034 post-eval freshness pass: if the
// most recent snapshot is older than the threshold, downgrade every
// finding's Confidence to LOW and record the reason. Verdicts, exit
// codes, and SecurityState are unaffected.
func annotateFreshness(report *evaluation.ComplianceReport, obsDir string, thresholdStr string, skip bool, now time.Time) error {
	if skip || obsDir == "" || obsDir == "-" {
		return nil
	}
	threshold, err := time.ParseDuration(thresholdStr)
	if err != nil {
		return fmt.Errorf("parse --freshness-threshold %q: %w: %w", thresholdStr, err, ErrInvalidInput)
	}

	loaded, err := observations.NewObservationLoader().LoadSnapshots(context.Background(), obsDir)
	if err != nil {
		slog.Warn("freshness check: could not load snapshots", "error", err)
		return nil
	}
	if len(loaded.Snapshots) == 0 {
		return nil
	}

	sr := staleness.Check(loaded.Snapshots, threshold, now)

	staleCount := 0
	if sr.Stale {
		for i := range report.Findings {
			report.Findings[i].Confidence = evaluation.ConfidenceLow
			report.Findings[i].FreshnessReason = sr.Message
		}
		staleCount = len(report.Findings)
		for i := range report.ChainFindings {
			report.ChainFindings[i].Confidence = string(evaluation.ConfidenceLow)
			report.ChainFindings[i].FreshnessReason = sr.Message
		}
	} else {
		for i := range report.Findings {
			if report.Findings[i].Confidence == "" {
				report.Findings[i].Confidence = evaluation.ConfidenceHigh
			}
		}
		for i := range report.ChainFindings {
			if report.ChainFindings[i].Confidence == "" {
				report.ChainFindings[i].Confidence = string(evaluation.ConfidenceHigh)
			}
		}
	}

	report.InputFreshness = &evaluation.InputFreshness{
		MostRecent:     sr.MostRecent.Format(time.RFC3339),
		AgeHours:       sr.StalenessHrs,
		ThresholdHours: sr.ThresholdHrs,
		Stale:          sr.Stale,
		StaleFindings:  staleCount,
	}
	return nil
}

// --- config loading (moved verbatim from cmd/apply/deps_project.go) ---

// loadWorkspacePolicy reads + parses the stave.yaml at path. Empty path means
// no project config. Mirrors projconfig's loadProjectConfig (which stays
// command-side); the engine loads here so the command passes only the path.
func loadWorkspacePolicy(path string) (*appconfig.WorkspacePolicy, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil //nolint:nilnil // no project config: nil-cfg + nil-err means "none".
	}
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read project config: %w", err)
	}
	var cfg appconfig.WorkspacePolicy
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse project config at %q: %w", path, err)
	}
	return &cfg, nil
}

func buildProjectConfigInput(projCfg *appconfig.WorkspacePolicy, controlsSet bool) (appeval.ProjectConfigInput, error) {
	if projCfg == nil {
		return appeval.ProjectConfigInput{}, nil
	}
	input := appeval.ProjectConfigInput{
		Exceptions:          mapExceptions(projCfg.Exceptions),
		EnabledControlPacks: projCfg.EnabledControlPacks,
		ExcludeControls:     projCfg.ExcludeControls,
		ControlsFlagSet:     controlsSet,
		BuiltinLoader:       ctlbuiltin.NewControlStore(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(builtinpredicate.ResolverFunc())).All,
	}
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return input, fmt.Errorf("initialize embedded pack registry: %w", err)
	}
	input.PackRegistry = reg
	return input, nil
}

func mapExceptions(in []appconfig.PolicyException) []appeval.ExceptionInput {
	if len(in) == 0 {
		return nil
	}
	out := make([]appeval.ExceptionInput, len(in))
	for i, s := range in {
		out[i] = appeval.ExceptionInput{
			ControlID: s.ControlID,
			AssetID:   s.AssetID,
			Reason:    s.Reason,
			Expires:   s.Expires,
		}
	}
	return out
}

func loadAcknowledgmentConfig(path string) (*policy.AcknowledgmentConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil //nolint:nilnil // optional config: nil-cfg + nil-err means "none configured".
	}
	cfg, err := acknowledgment.Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading acknowledgments from %q: %w", path, err)
	}
	return cfg, nil
}

func loadExemptionConfig(path string) (*policy.ExemptionConfig, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil //nolint:nilnil // optional config: nil-cfg + nil-err means "none configured".
	}
	cfg, err := (&exemption.Loader{}).Load(path)
	if err != nil {
		return nil, fmt.Errorf("loading exemptions from %q: %w", path, err)
	}
	return cfg, nil
}
