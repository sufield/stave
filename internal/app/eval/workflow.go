package eval

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/app/eval/cache"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/util/sets"
)

// ObservationConfig holds the sources for security policies and cloud resource states.
type ObservationConfig struct {
	PolicySource      string
	ObservationSource string
	Stderr            io.Writer
	ActivePolicies    []policy.ControlDefinition
}

// AssessmentConfig defines the parameters and environment for a security audit.
type AssessmentConfig struct {
	ObservationConfig
	SLAThreshold        time.Duration
	Clock               ports.Clock
	Hasher              ports.Digester
	Output              io.Writer
	ExemptionRules      *policy.ExemptionConfig
	ExceptionRules      *policy.ExceptionConfig
	AcknowledgmentRules *policy.AcknowledgmentConfig
	BuildVersion        string
	Metadata            evaluation.Metadata
	PredicateParser     func(any) (*policy.UnsafePredicate, error)
	PredicateEval       policy.PredicateEval
	Tracer              ports.Tracer
	ChainDefs           []policy.ChainDefinition // Optional chain definitions for risk reasoning
	SLAConfig           *evaluation.SLAConfig    // Optional SLA policy for deadline enforcement
}

// AuditWorkflow orchestrates the end-to-end security assessment process.
type AuditWorkflow struct {
	ObservationRepo  appcontracts.ObservationRepository
	PolicyRepo       appcontracts.ControlRepository
	ReportPublisher  appcontracts.FindingMarshaler
	ContextEnricher  appcontracts.EnrichFunc
	SnapshotEnricher appcontracts.SnapshotEnricher
	Logger           *slog.Logger

	// cacheMu guards loadedControls / loadedSnapshots. The cache is
	// written once per PerformAssessment call and read by accessor
	// callers (post-assessment posture aggregation, reachability
	// annotation) — concurrent test harnesses or future "watch"
	// orchestrators that read the cache while a fresh assessment
	// is writing it must not race.
	cacheMu sync.RWMutex
	// loadedControls and loadedSnapshots cache the inputs used by the
	// most recent PerformAssessment call. Populated as a side effect
	// of running an assessment so callers can do post-assessment work
	// (coverage posture aggregation, reachability annotation that
	// needs the full snapshot graph) without re-loading from the
	// repos. Private now — the read-only Controls() / Snapshots()
	// accessors prevent external mutation between assessment runs.
	loadedControls  []policy.ControlDefinition
	loadedSnapshots []asset.Snapshot
}

// Controls returns the control definitions loaded by the most
// recent PerformAssessment call. Returns a copy so callers cannot
// mutate the workflow's cached slice in place.
func (w *AuditWorkflow) Controls() []policy.ControlDefinition {
	w.cacheMu.RLock()
	defer w.cacheMu.RUnlock()
	if len(w.loadedControls) == 0 {
		return nil
	}
	out := make([]policy.ControlDefinition, len(w.loadedControls))
	copy(out, w.loadedControls)
	return out
}

// Snapshots returns the asset snapshots loaded by the most recent
// PerformAssessment call. Returns a copy so callers cannot mutate
// the workflow's cached slice in place.
func (w *AuditWorkflow) Snapshots() []asset.Snapshot {
	w.cacheMu.RLock()
	defer w.cacheMu.RUnlock()
	if len(w.loadedSnapshots) == 0 {
		return nil
	}
	out := make([]asset.Snapshot, len(w.loadedSnapshots))
	copy(out, w.loadedSnapshots)
	return out
}

// NewAuditWorkflow initializes the workflow with required
// security connectors. Returns an error rather than panicking on
// missing dependencies — panics on configuration errors are
// recoverable mistakes (the calling layer typically has its own
// retry / fallback path) and should not crash the process.
func NewAuditWorkflow(
	invRepo appcontracts.ObservationRepository,
	polRepo appcontracts.ControlRepository,
	publisher appcontracts.FindingMarshaler,
	enricher appcontracts.EnrichFunc,
) (*AuditWorkflow, error) {
	if invRepo == nil {
		return nil, errors.New("NewAuditWorkflow: ObservationRepo is required")
	}
	if polRepo == nil {
		return nil, errors.New("NewAuditWorkflow: PolicyRepo is required")
	}
	if publisher == nil {
		return nil, errors.New("NewAuditWorkflow: ReportPublisher is required")
	}
	if enricher == nil {
		return nil, errors.New("NewAuditWorkflow: ContextEnricher is required")
	}
	return &AuditWorkflow{
		ObservationRepo: invRepo,
		PolicyRepo:      polRepo,
		ReportPublisher: publisher,
		ContextEnricher: enricher,
	}, nil
}

// PerformAssessment executes the security audit and returns the compliance report.
func (w *AuditWorkflow) PerformAssessment(ctx context.Context, cfg AssessmentConfig) (evaluation.ComplianceReport, evaluation.SecurityState, error) {
	auditData := w.prepareAuditData(ctx, cfg.ObservationConfig)
	if auditData.HasErrors() {
		return evaluation.ComplianceReport{}, evaluation.StateUnknown, auditData.FirstError()
	}
	// Hold the cache lock across BOTH enrichment and
	// publication. The enricher mutates
	// Snapshot.Identities[i].Properties in place; if the
	// publication happened first (the previous shape) a
	// concurrent w.Snapshots() reader could observe a snapshot
	// while CloudIdentity.Properties was being written to. By
	// performing enrichment under the same lock that guards the
	// cache write, every Snapshots() observer sees either
	// pre-enrichment cached data from a prior cycle or fully
	// enriched new data — never a half-mutated mid-state.
	//
	// Iter 5/6 wiring rationale: the enricher folds chain output
	// (RoleChainFact.HopType lambda_invoke_existing /
	// cfn_update_existing, RoleChainFact.ScheduledDeletionAt)
	// into the per-identity booleans the ctrl.v1 controls read
	// (`identity.escalation.confused_*.present`,
	// `identity.chain.ghost_deletion.present`). The composition
	// root supplies the concrete enricher (typically the
	// iam-package projector); this layer only sees the port to
	// keep the hexagonal app/platform boundary intact.
	w.cacheMu.Lock()
	if w.SnapshotEnricher != nil {
		for i := range auditData.Snapshots {
			w.SnapshotEnricher.EnrichSnapshot(&auditData.Snapshots[i])
		}
	}
	w.loadedControls = auditData.Controls
	w.loadedSnapshots = auditData.Snapshots
	w.cacheMu.Unlock()

	// Content-addressed cache: skip the entire engine + risk-
	// reasoning pass when (controls, observations, chains, config)
	// hash to a key we have already evaluated. The cache pays off
	// hard on the CI/CD case where a typical push doesn't touch
	// the catalog or the observation snapshot at all.
	//
	// SLA annotation is intentionally outside the cache scope —
	// clock-dependent and cheap to re-run, so cached reports stay
	// fresh on deadlines.
	cacheKey := cache.Key{
		StaveVersion:    cfg.BuildVersion,
		ControlsDigest:  cache.ComputeControlsDigest(auditData.Controls),
		InputHashesHash: cache.ComputeInputHashesKey(auditData.Hashes),
		ChainsDigest:    cache.ComputeChainsDigest(cfg.ChainDefs),
		ConfigDigest: cache.ComputeConfigDigest(cache.ConfigForDigest{
			SLAThreshold:        cfg.SLAThreshold.String(),
			ExemptionRules:      cfg.ExemptionRules,
			ExceptionRules:      cfg.ExceptionRules,
			AcknowledgmentRules: cfg.AcknowledgmentRules,
			BuildVersion:        cfg.BuildVersion,
		}),
		// PolicySource + ObservationSource are the directories the
		// user passed via --controls / --observations. These flow
		// into Run.ResolvedPaths on the report; two runs with
		// identical CONTENT at different PATHS must NOT share a
		// cache key, otherwise the second run serves a report with
		// the wrong embedded paths. Discovered when two e2e fixtures
		// with byte-identical controls/observations at different
		// testdata/e2e/<name>/ dirs cross-polluted each other's
		// outputs.
		SourcePaths: cache.ComputeSourcePathsKey(
			cfg.PolicySource,
			cfg.ObservationSource,
		),
	}
	cacheDir, _ := cache.DefaultCacheDir()
	cache := cache.New(cacheDir)

	var report evaluation.ComplianceReport
	cacheHit := false
	if cached, ok := cache.Load(cacheKey); ok {
		report = cached
		cacheHit = true
		// ControlRemediation is json:"-", so the cache's JSON
		// round-trip drops it. Re-attach it from the live control
		// set, otherwise cache hits fall back to generic
		// class-default remediation instead of the control's
		// authored guidance (cache-miss runs keep it in memory).
		rehydrateControlRemediation(&report, auditData.Controls)
		if w.Logger != nil {
			w.Logger.Info("assessment cache hit", "key", cacheKey.Hex())
		}
	}

	if !cacheHit {
		var err error
		report, err = Evaluate(ctx, EvaluateInput{
			Controls:             auditData.Controls,
			Snapshots:            auditData.Snapshots,
			MaxUnsafeDuration:    cfg.SLAThreshold,
			Clock:                cfg.Clock,
			Hasher:               cfg.Hasher,
			ExemptionConfig:      cfg.ExemptionRules,
			ExceptionConfig:      cfg.ExceptionRules,
			AcknowledgmentConfig: cfg.AcknowledgmentRules,
			StaveVersion:         cfg.BuildVersion,
			InputHashes:          auditData.Hashes,
			PredicateParser:      cfg.PredicateParser,
			CELEvaluator:         cfg.PredicateEval,
			Metadata:             cfg.Metadata,
			Tracer:               cfg.Tracer,
		})
		if err != nil {
			return evaluation.ComplianceReport{}, evaluation.StateUnknown, fmt.Errorf("security assessment failed: %w", err)
		}

		// Run the risk reasoning engine: detect chain-based compound findings
		// and build an attack stage summary from the evaluation results.
		w.enrichWithRiskReasoning(&report, auditData.Controls, cfg.ChainDefs, auditData.Snapshots)

		// Persist BEFORE the SLA pass so the cached report stays
		// clock-independent. Best-effort: a persist failure is a
		// missed optimisation, not a correctness problem, so log
		// and continue rather than poisoning the assessment.
		if persistErr := cache.Persist(cacheKey, report); persistErr != nil {
			if w.Logger != nil {
				w.Logger.Warn("assessment cache persist failed", "err", persistErr)
			}
		}
	}

	// Annotate findings with SLA deadline data.
	if cfg.SLAConfig != nil {
		ctlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(auditData.Controls))
		for i := range auditData.Controls {
			ctlLookup[auditData.Controls[i].ID] = &auditData.Controls[i]
		}
		for i := range report.Findings {
			ctl := ctlLookup[report.Findings[i].ControlID]
			if ctl == nil {
				// Orphan finding: the control ID emitted by the engine
				// is not in the loaded control catalog. Skip SLA
				// annotation rather than dereferencing nil — the
				// finding still surfaces, but without a deadline. Log
				// so operators can investigate the catalog drift
				// (typically a finding emitted by a chain definition
				// referencing a removed control).
				if w.Logger != nil {
					w.Logger.Warn("sla annotation skipped: control not in catalog",
						"control_id", report.Findings[i].ControlID,
						"asset_id", report.Findings[i].AssetID)
				}
				continue
			}
			report.Findings[i].AnnotateSLA(ctl, cfg.SLAConfig)
		}
	}

	return report, report.SecurityState, nil
}

// rehydrateControlRemediation re-attaches each finding's
// ControlRemediation from the live control set. That field is
// json:"-" and so does not survive the assessment cache's JSON
// round-trip; without this, cache hits would resolve remediation to
// the generic class-default instead of the control's authored
// guidance. Findings whose control is absent from the catalog (e.g.
// chain-emitted) are left untouched and fall back as before.
func rehydrateControlRemediation(report *evaluation.ComplianceReport, controls []policy.ControlDefinition) {
	if report == nil {
		return
	}
	remediationByID := make(map[kernel.ControlID]*policy.RemediationSpec, len(controls))
	for i := range controls {
		remediationByID[controls[i].ID] = controls[i].Remediation
	}
	attach := func(fs []evaluation.Finding) {
		for i := range fs {
			if fs[i].ControlRemediation == nil {
				if rem, ok := remediationByID[fs[i].ControlID]; ok {
					fs[i].ControlRemediation = rem
				}
			}
		}
	}
	attach(report.Findings)
	attach(report.MarkerFindings)
}

func (w *AuditWorkflow) prepareAuditData(ctx context.Context, cfg ObservationConfig) IntentEvaluationResult {
	intent := NewIntentEvaluation(w.ObservationRepo, w.PolicyRepo)

	// caller-supplied means: any non-nil slice (including empty)
	// — the caller is explicitly providing the control set, even
	// if that set is "no controls at all". An empty slice is a
	// legitimate input (e.g. profile-driven runs that filter to
	// zero matching controls); it must NOT fall back to loading
	// from disk, because doing so would silently re-introduce
	// controls the caller deliberately excluded.
	callerSupplied := cfg.ActivePolicies != nil

	data := intent.LoadArtifacts(ctx, IntentEvaluationConfig{
		ControlsDir:      cfg.PolicySource,
		ObservationsDir:  cfg.ObservationSource,
		RequireControls:  !callerSupplied,
		SkipControlsLoad: callerSupplied,
	})
	if callerSupplied {
		data.Controls = cfg.ActivePolicies
	}
	return data
}

// enrichWithRiskReasoning runs the chain detection engine and builds
// an attack stage summary from the evaluation results. This is the
// inference layer — it transforms individual findings into compound
// risk assessments.
//
// snapshots feeds the [risk.ScopeResolver] used when a chain
// declares scope_field. Without snapshots, scope_field-bearing
// chains silently fall back to asset.ID grouping.
func (w *AuditWorkflow) enrichWithRiskReasoning(
	report *evaluation.ComplianceReport,
	controls []policy.ControlDefinition,
	chainDefs []policy.ChainDefinition,
	snapshots []asset.Snapshot,
) {
	if len(report.Findings) == 0 && len(report.MarkerFindings) == 0 {
		return
	}

	// Build per-asset failure list for asset-aware chain and
	// attack-stage analysis. Marker findings join the failure list
	// for chain detection — chains can compose marker findings
	// (e.g. "bucket is tagged phi") with violation findings (e.g.
	// "Cognito unauth role grants S3 access") into cross-resource
	// compounds. Markers stay out of the attack-stage summary so
	// they don't invent kill-chain stages from informational
	// signal.
	failures := make([]risk.FailingControl, 0, len(report.Findings)+len(report.MarkerFindings))
	for i := range report.Findings {
		failures = append(failures, report.Findings[i].ToFailingControl())
	}
	violationCount := len(failures)
	for i := range report.MarkerFindings {
		failures = append(failures, report.MarkerFindings[i].ToFailingControl())
	}

	controlLookup := make(map[kernel.ControlID]*policy.ControlDefinition, len(controls))
	for i := range controls {
		controlLookup[controls[i].ID] = &controls[i]
	}

	// Detect chain-based compound findings.
	if len(chainDefs) > 0 {
		scopeResolver := risk.NewScopeResolverFromSnapshots(snapshots)
		report.ChainFindings = risk.DetectChains(failures, chainDefs, controlLookup, scopeResolver)
		annotateChainMembership(report)
	}

	// Build attack stage summary from violation failures only —
	// marker findings carry no attack-stage semantics on their own.
	report.AttackStageSummary = risk.BuildAttackStageSummary(failures[:violationCount], controlLookup)

	// Rank findings by exposure score (silent killer detection).
	// ChainMembership must be annotated before this loop runs so the
	// chain-bonus factor feeds into per-finding scores.
	rankInputs := make([]risk.RankInput, len(report.Findings))
	for i := range report.Findings {
		rankInputs[i] = report.Findings[i].ToRankInput()
	}
	report.TopExposures = risk.RankExposures(rankInputs, controlLookup, 0)

	// Propagate the per-finding score + breakdown back onto each
	// Finding so downstream sorts and output can read the score
	// without a parallel lookup. Matches metrics.md § Metric 1
	// improvement signal: "score and breakdown are emitted on every
	// finding, not only on the top-N slice".
	for i := range report.TopExposures {
		er := &report.TopExposures[i]
		if er.IsDanglingReference(len(report.Findings)) {
			// A dangling reference means the rank pipeline is out
			// of sync with the finding set — stale ranker, upstream
			// filter that dropped findings without updating indices,
			// or a hand-built fixture with mismatched parallel
			// arrays. Warn so the data-integrity gap surfaces
			// instead of leaving a 0-score row with no trail.
			slog.Warn("workflow: dangling exposure reference; skipping",
				"control_id", er.ControlID, "asset_id", er.AssetID,
				"finding_index", er.FindingIndex, "findings_available", len(report.Findings))
			continue
		}
		f := &report.Findings[er.FindingIndex]
		f.ExposureScore = er.ExposureScore
		// Point directly at the slice element's field. The previous
		// shape (`breakdown := er.Breakdown; f.ScoreBreakdown = &breakdown`)
		// allocated a fresh per-iteration copy; pointing into the
		// existing TopExposures slice avoids the per-iteration alloc
		// and keeps the score breakdown a single source of truth.
		// TopExposures is not mutated after this loop (sortFindings
		// below reorders Findings, not TopExposures), so the shared
		// pointer is stable for the report's lifetime.
		f.ScoreBreakdown = &er.Breakdown
	}

	// Re-sort findings by the newly-populated score.
	evaluation.SortFindings(report.Findings)

	// Build consolidated Issues from the scored findings. Runs after
	// ranking so ConsolidatedScore uses the final per-finding score
	// including chain bonus. See docs/product/metrics.md § Metric 2.
	report.Issues = evaluation.BuildIssues(report.Findings)
}

// annotateChainMembership cross-references fired chains with individual
// findings and populates ChainMembership on each contributing finding.
func annotateChainMembership(report *evaluation.ComplianceReport) {
	if len(report.ChainFindings) == 0 {
		return
	}

	// Build a lookup: controlID → list of chain membership entries.
	type entry struct {
		controlIDs sets.Set[kernel.ControlID]
		membership evaluation.ChainMembershipEntry
	}
	chainEntries := make([]entry, 0, len(report.ChainFindings))
	for i := range report.ChainFindings {
		cf := &report.ChainFindings[i]
		cidSet := sets.New[kernel.ControlID](cf.ControlsFailing...)
		chainEntries = append(chainEntries, entry{
			controlIDs: cidSet,
			membership: evaluation.ChainMembershipEntry{
				ChainID:       cf.ChainID,
				ChainSeverity: cf.Severity,
				StageSpan:     risk.SortStagesByKillChain(cf.AttackStages),
				Narrative:     cf.Description,
			},
		})
	}

	for i := range report.Findings {
		f := &report.Findings[i]
		for _, ce := range chainEntries {
			if ce.controlIDs.Contains(f.ControlID) {
				f.AddChainMembership(ce.membership)
			}
		}
	}
	// Marker findings can be chain members too (cross-resource
	// compounds compose markers with violations). Annotate them so
	// downstream consumers see "this informational fact is one
	// link in chain X" — same shape as violations.
	for i := range report.MarkerFindings {
		f := &report.MarkerFindings[i]
		for _, ce := range chainEntries {
			if ce.controlIDs.Contains(f.ControlID) {
				f.AddChainMembership(ce.membership)
			}
		}
	}
}

// EnrichReport applies risk reasoning (chains, attack stages, exposure
// ranking) to an evaluation report. Exported for use by the profile
// runner which bypasses the standard assessment workflow.
//
// snapshots feeds the chain-engine [risk.ScopeResolver] used by chains
// that declare scope_field. Callers that do not retain snapshots can
// pass nil; chain detection then falls back to asset.ID grouping for
// every chain (the legacy semantics).
//
// Seeds the workflow with slog.Default() so enrichWithRiskReasoning's
// Logger.Warn calls (and any future logger reads) never fire on a
// nil receiver. The previous shape constructed an AuditWorkflow{}
// with Logger==nil; the current call sites guard with `if w.Logger
// != nil` but a future reader would silently drop diagnostic output.
func EnrichReport(report *evaluation.ComplianceReport, controls []policy.ControlDefinition, chainDefs []policy.ChainDefinition, snapshots []asset.Snapshot) {
	w := &AuditWorkflow{Logger: slog.Default()}
	w.enrichWithRiskReasoning(report, controls, chainDefs, snapshots)
}
