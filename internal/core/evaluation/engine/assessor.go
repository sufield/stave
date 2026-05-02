package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	stavecel "github.com/sufield/stave/internal/cel"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Assessor orchestrates the evaluation of security controls against cloud resource states.
// It is the central engine that transforms raw snapshots into a verified ComplianceReport.
//
// Fields are unexported so callers must construct via NewAssessor and
// configure via the WithX options. The functional-options pattern
// keeps the construction site explicit (each dep is named at the
// call) and prevents drift toward partially-initialised instances
// produced by struct-literal assignment.
type Assessor struct {
	// Infrastructure — stateless services injected at construction.
	logger          *slog.Logger
	clock           ports.Clock
	hasher          ports.Digester
	predicateEval   policy.PredicateEval
	predicateParser func(any) (*policy.UnsafePredicate, error)
	confidence      evaluation.ConfidenceCalculator

	// Observability — optional logic trace for audit transparency.
	tracer ports.Tracer

	// Governance — the policy-set and override configurations.
	controls        []policy.ControlDefinition
	exemptions      *policy.ExemptionConfig
	exceptions      *policy.ExceptionConfig
	acknowledgments *policy.AcknowledgmentConfig

	// Risk Thresholds — global parameters for SLA and data continuity.
	slaThreshold    time.Duration
	continuityLimit time.Duration
}

// AssessorOption configures an Assessor at construction time.
type AssessorOption func(*Assessor)

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) AssessorOption { return func(a *Assessor) { a.logger = l } }

// WithClock sets the wall-clock source.
func WithClock(c ports.Clock) AssessorOption { return func(a *Assessor) { a.clock = c } }

// WithHasher sets the policy-fingerprint hasher. Domain code cannot
// import platform/crypto under the hexagonal architecture; the
// composition root injects crypto.NewHasher() here.
func WithHasher(h ports.Digester) AssessorOption { return func(a *Assessor) { a.hasher = h } }

// WithPredicateEval sets the CEL predicate evaluator.
func WithPredicateEval(e policy.PredicateEval) AssessorOption {
	return func(a *Assessor) { a.predicateEval = e }
}

// WithPredicateParser sets the predicate parser used for raw rule decoding.
func WithPredicateParser(p func(any) (*policy.UnsafePredicate, error)) AssessorOption {
	return func(a *Assessor) { a.predicateParser = p }
}

// WithConfidence overrides the default confidence calculator.
func WithConfidence(c evaluation.ConfidenceCalculator) AssessorOption {
	return func(a *Assessor) { a.confidence = c }
}

// WithTracer attaches an optional logic tracer for audit transparency.
func WithTracer(t ports.Tracer) AssessorOption { return func(a *Assessor) { a.tracer = t } }

// WithControls installs the control catalog.
func WithControls(ctls []policy.ControlDefinition) AssessorOption {
	return func(a *Assessor) { a.controls = ctls }
}

// WithExemptions installs the exemption configuration. nil is
// permitted — the assessor treats a nil ExemptionConfig as "no
// exemptions configured".
func WithExemptions(e *policy.ExemptionConfig) AssessorOption {
	return func(a *Assessor) { a.exemptions = e }
}

// WithExceptions installs the exception configuration; nil is permitted.
func WithExceptions(e *policy.ExceptionConfig) AssessorOption {
	return func(a *Assessor) { a.exceptions = e }
}

// WithAcknowledgments installs the acknowledgment configuration; nil is permitted.
func WithAcknowledgments(ack *policy.AcknowledgmentConfig) AssessorOption {
	return func(a *Assessor) { a.acknowledgments = ack }
}

// WithSLAThreshold sets the global max-unsafe-duration default.
func WithSLAThreshold(d time.Duration) AssessorOption {
	return func(a *Assessor) { a.slaThreshold = d }
}

// WithContinuityLimit overrides the default continuity limit.
func WithContinuityLimit(d time.Duration) AssessorOption {
	return func(a *Assessor) { a.continuityLimit = d }
}

// NewAssessor creates an engine with sensible defaults for security
// evaluation. The hasher is intentionally left nil — the domain
// layer cannot import platform/crypto, so callers that need a non-empty
// PolicyFingerprint must inject a hasher explicitly via WithHasher.
//
// Nil-receiver contract: Exemptions, Exceptions, and Acknowledgments
// may be left nil. Their *ShouldExempt / *ShouldExcept / *FindRule
// methods are nil-safe and treat a nil receiver as "no rules
// configured" — so the assessor never panics on a partially-wired
// configuration.
func NewAssessor(opts ...AssessorOption) *Assessor {
	a := &Assessor{
		logger:          slog.Default(),
		continuityLimit: DefaultContinuityLimit,
		confidence:      evaluation.DefaultConfidenceCalculator(),
	}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// Controls returns the control catalog the assessor is configured
// to evaluate. Returned slice is the live backing slice — callers
// must not mutate it.
func (a *Assessor) Controls() []policy.ControlDefinition { return a.controls }

// sessionDeps wraps the Assessor to satisfy strategyDeps, adding the
// active trace span from the current assessmentSession.
type sessionDeps struct {
	*Assessor
	span ports.AssessmentSpan
}

func (d *sessionDeps) currentSpan() ports.AssessmentSpan { return d.span }

// Compile-time checks.
var (
	_ strategyDeps = (*sessionDeps)(nil)
	_ strategyDeps = (*Assessor)(nil)
)

// ErrClockMissing is returned by referenceTime when the clock is nil.
// Mirrors the precondition error returned by Assess at its boundary.
var ErrClockMissing = errors.New("Assessor: clock is nil; supply WithClock to NewAssessor")

func (a *Assessor) currentSpan() ports.AssessmentSpan { return nopSpan{} }

// Logger returns the structured logger configured at construction.
func (a *Assessor) Logger() *slog.Logger { return a.logger }

// PredicateParser returns the configured predicate parser.
func (a *Assessor) PredicateParser() policy.PredicateParser { return a.predicateParser }

// ContinuityLimit returns the configured continuity limit (max
// allowed gap between observation snapshots).
func (a *Assessor) ContinuityLimit() time.Duration { return a.continuityLimit }

// slaThresholdFor returns the effective SLA (Max Unsafe Duration) for a control.
func (a *Assessor) slaThresholdFor(ctl *policy.ControlDefinition) time.Duration {
	return ctl.EffectiveMaxUnsafeDuration(a.slaThreshold)
}

func (a *Assessor) confidenceCalculator() evaluation.ConfidenceCalculator { return a.confidence }

// sortSnapshots returns a chronological copy of the snapshots.
// Uses stable sort with source as secondary key for determinism
// when timestamps are identical.
func (a *Assessor) sortSnapshots(snapshots []asset.Snapshot) []asset.Snapshot {
	sorted := slices.Clone(snapshots)
	slices.SortStableFunc(sorted, func(i, j asset.Snapshot) int {
		if cmp := i.CapturedAt.Compare(j.CapturedAt); cmp != 0 {
			return cmp
		}
		return strings.Compare(string(i.Source), string(j.Source))
	})
	return sorted
}

// referenceTime establishes the "audit now" timestamp.
// If --now was set (FixedClock), the user's explicit time takes precedence.
// Otherwise, the latest snapshot's CapturedAt is used for reproducibility.
//
// Contract: a.clock MUST be non-nil. Returns ErrClockMissing instead
// of panicking so callers can surface the misuse via a normal error
// path. The earlier defensive fallback called wall-clock time
// directly, which snuck a side effect into the core runtime —
// caught by the TestCoreRuntimeNoHardwiredSideEffects architecture
// test. The brief panic-replacement was the right architecture fix
// but the wrong error mode for tests / programmatic callers; an
// error return matches how Assess already handles the same nil-Clock
// condition at its boundary.
func (a *Assessor) referenceTime(snapshots []asset.Snapshot) (time.Time, error) {
	if a.clock == nil {
		return time.Time{}, ErrClockMissing
	}
	if a.clock.IsUserProvided() {
		return a.clock.Now(), nil
	}
	if len(snapshots) > 0 {
		// Find the latest CapturedAt rather than trusting slice
		// order. The earlier shape returned snapshots[last], which
		// silently produced the wrong reference time when the
		// caller passed snapshots in any order other than ascending
		// CapturedAt — a precondition the type signature did not
		// advertise. slices.MaxFunc makes the intent explicit.
		latest := slices.MaxFunc(snapshots, func(a, b asset.Snapshot) int {
			return a.CapturedAt.Compare(b.CapturedAt)
		})
		return latest.CapturedAt, nil
	}
	return a.clock.Now(), nil
}

// AssessmentOptions holds ephemeral parameters for a specific evaluation run.
type AssessmentOptions struct {
	StaveVersion     string
	InputHashes      *evaluation.InputHashes
	GenerateEvidence bool
}

// assessmentSession maintains the state of a single execution of the engine.
//
// Concurrency: applyControl is invoked sequentially from Assess, and the
// activeSpan field is mutated without synchronization. If a future
// change parallelizes per-control evaluation, activeSpan must be moved
// into per-call state (or guarded by a mutex) before doing so —
// otherwise concurrent writers will race and the strategy will see the
// wrong span. The collector's own RecordCheck path is mutex-protected
// independently, so it is safe to call from a future concurrent caller.
//
// applyControlInUse is the runtime assertion guard. It is set
// non-zero while applyControl is executing; a second concurrent
// caller would see it already non-zero and panic with a clear
// message identifying the contract violation. The cost is one
// atomic load/store per applyControl call, negligible against the
// per-asset CEL evaluation that dominates the runtime.
type assessmentSession struct {
	assessor          *Assessor
	snapshots         []asset.Snapshot
	auditTime         time.Time
	collector         *AssessmentCollector
	idIndex           IdentityIndex
	opts              AssessmentOptions
	activeSpan        ports.AssessmentSpan // current control×asset span for strategy access; sequential-only, see type doc
	applyControlInUse atomic.Bool
}

// beginTrace starts a trace span for a control×asset evaluation.
// Returns a nopSpan if no tracer is configured — avoids nil checks at call sites.
func (s *assessmentSession) beginTrace(resourceID, policyID string) ports.AssessmentSpan {
	if s.assessor.tracer == nil {
		return nopSpan{}
	}
	return s.assessor.tracer.BeginAssessment(resourceID, policyID)
}

// Assess processes the observation snapshots and returns a comprehensive ComplianceReport.
//
// ctx is consulted between control iterations in applyControl so a
// cancelled or deadline-expired context aborts long-running evaluations
// (Ctrl-C, server timeouts) at the next control boundary instead of
// running the catalog to completion.
func (a *Assessor) Assess(ctx context.Context, snapshots []asset.Snapshot, opts ...AssessmentOptions) (evaluation.ComplianceReport, error) {
	if ctx == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor.Assess requires a non-nil context")
	}
	if err := ctx.Err(); err != nil {
		return evaluation.ComplianceReport{}, err
	}
	if a.clock == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a Clock")
	}
	if a.predicateEval == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a PredicateEval")
	}
	if a.predicateParser == nil {
		return evaluation.ComplianceReport{}, errors.New("precondition failed: Assessor requires a PredicateParser")
	}
	var opt AssessmentOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	sequenced := a.sortSnapshots(snapshots)

	// Pre-pass: derive cross-resource properties (e.g., KMS key isolation).
	// This enriches asset properties with derived fields before control
	// evaluation, enabling cross-resource reasoning via standard predicates.
	sequenced = EnrichKeyIsolation(sequenced)

	lifecycles, err := BuildLifecyclesPerControl(a.controls, sequenced, a.predicateEval)
	if err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("lifecycle analysis failed: %w", err)
	}

	// Use the maximum asset count across snapshots as the
	// pre-allocation hint. The earlier shape used sequenced[0]
	// (the EARLIEST snapshot), which under-allocated whenever the
	// asset count grew over the observation window — every
	// subsequent append then forced a re-grow. Picking the max
	// produces a one-shot allocation that fits any snapshot the
	// session will see.
	assetHint := 0
	for i := range sequenced {
		if n := len(sequenced[i].Assets); n > assetHint {
			assetHint = n
		}
	}

	auditTime, refErr := a.referenceTime(sequenced)
	if refErr != nil {
		return evaluation.ComplianceReport{}, refErr
	}
	sess := &assessmentSession{
		assessor:  a,
		snapshots: sequenced,
		auditTime: auditTime,
		collector: NewCollector(assetHint),
		idIndex:   BuildIdentityIndex(sequenced),
		opts:      opt,
	}

	for i := range a.controls {
		if err := ctx.Err(); err != nil {
			return evaluation.ComplianceReport{}, err
		}
		ctl := &a.controls[i]
		if !ctl.IsEvaluatable() {
			sess.collector.RecordSkippedControl(
				ctl.ID,
				ctl.Name,
				"control type cannot be evaluated: "+ctl.Type.String(),
			)
			continue
		}
		if err := sess.applyControl(ctx, ctl, lifecycles[ctl.ID]); err != nil {
			return evaluation.ComplianceReport{}, err
		}
	}

	return sess.compileReport(), nil
}

// applyControl evaluates a single control across the asset set.
//
// Concurrency contract: this method MUST remain sequential. It writes
// `s.activeSpan` mid-loop without synchronization, so any future
// parallelization (e.g., one goroutine per control) would race the
// per-asset span assignment with the strategy's read of activeSpan.
// If parallelization becomes necessary, move activeSpan into a per-
// call local that the strategy receives as a parameter — do NOT add a
// mutex around the field assignment, because that only serializes the
// write and the strategy still reads the wrong span.
func (s *assessmentSession) applyControl(
	ctx context.Context,
	ctl *policy.ControlDefinition,
	lifecycles map[asset.ID]*asset.ExposureLifecycle,
) error {
	// Detect any future caller that violates the sequential
	// contract. CompareAndSwap returns false when the flag is
	// already set, which means another goroutine is in
	// applyControl right now — bug, not a recoverable runtime
	// condition, so panic with a message that points at the
	// type-doc explanation.
	if !s.applyControlInUse.CompareAndSwap(false, true) {
		panic("engine: applyControl invoked concurrently — see assessmentSession concurrency contract; activeSpan is not goroutine-safe")
	}
	defer s.applyControlInUse.Store(false)

	// Ensure deterministic output by processing assets in ID order.
	assetIDs := make([]asset.ID, 0, len(lifecycles))
	for id := range lifecycles {
		assetIDs = append(assetIDs, id)
	}
	slices.Sort(assetIDs)

	for _, id := range assetIDs {
		// Per-asset cancellation check: bail out at the next iteration
		// boundary so a long catalog × asset matrix does not run to
		// completion after the user hit Ctrl-C. Checked here rather
		// than only in Assess() because a single control with a large
		// asset set can dominate runtime.
		if err := ctx.Err(); err != nil {
			return err
		}
		lifecycle := lifecycles[id]
		span := s.beginTrace(string(id), ctl.ID.String())

		// 1. Check for organizational exemptions (Policy Overrides)
		if rule := s.assessor.exemptions.ShouldExempt(id); rule != nil {
			span.RecordStep("exemption_check", map[string]any{
				"pattern": rule.Pattern,
			}, map[string]any{
				"exempted": true,
				"reason":   rule.Reason,
			})
			span.SetVerdict(string(evaluation.VerdictSkipped), string(evaluation.ConfidenceHigh))
			span.End()

			if s.collector.RecordExemption(id) {
				s.collector.RecordExemptedAsset(id, rule.Pattern, rule.Reason)
			}
			// A nil lifecycle here is unexpected — the lifecycle map is
			// produced by BuildLifecyclesPerControl and the caller
			// iterates its keys. Record the check with empty type
			// metadata rather than panicking, and emit a debug log so
			// the upstream invariant violation is traceable.
			check := evaluation.ResourceCheck{
				ControlID:  ctl.ID,
				AssetID:    id,
				Verdict:    evaluation.VerdictSkipped,
				Confidence: evaluation.ConfidenceHigh,
				Reason:     rule.Reason,
			}
			if lifecycle != nil {
				check.AssetType = lifecycle.Asset().Type
				check.AssetDomain = lifecycle.Asset().Type.Domain()
			} else {
				s.assessor.Logger().Debug("exemption check: nil lifecycle",
					"control", ctl.ID, "asset", id)
			}
			s.collector.RecordCheck(check)
			continue
		}
		span.RecordStep("exemption_check", nil, map[string]any{"exempted": false})

		// 2. Track evaluated snapshots through the collector's
		//    mutex-protected entry points. The collector itself is
		//    concurrent-safe; applyControl is currently called
		//    sequentially from Assess (see assessmentSession type doc).
		// RecordNonCompliantAsset moves below the strategy.Evaluate
		// call so the counter reflects findings, not raw lifecycle
		// state. IsExposed() is true any time a snapshot caught the
		// asset in an unsafe configuration, regardless of whether
		// any control actually fires (e.g. an asset is "publicly
		// readable" but the control catalog doesn't include the
		// matching predicate). Counting on IsExposed inflated the
		// "exposed resources" summary above the violation count,
		// confusing operators reading the report's totals.
		s.collector.RecordSeenAsset(id)

		// 3. Evaluate the security strategy against the asset lifecycle.
		//    Set the active span so strategies can record their decision steps,
		//    then create the strategy (which captures the span via sessionDeps).
		s.activeSpan = span
		// Defensive nil-check: strategy.Evaluate dereferences lifecycle.
		// A nil here would panic the assessor; record an inconclusive
		// check + log instead.
		if lifecycle == nil {
			s.assessor.Logger().Warn("strategy evaluation: nil lifecycle",
				"control", ctl.ID, "asset", id)
			s.collector.RecordCheck(evaluation.ResourceCheck{
				ControlID:  ctl.ID,
				AssetID:    id,
				Verdict:    evaluation.VerdictInconclusive,
				Confidence: evaluation.ConfidenceInconclusive,
				Reason:     "lifecycle missing for asset",
			})
			span.End()
			continue
		}
		strat := s.strategyFor(ctl)
		check, findings := strat.Evaluate(lifecycle, s.auditTime, s.idIndex)

		// 4. Record verdict and finding linkage in the trace span
		span.SetVerdict(string(check.Verdict), string(check.Confidence))
		if len(findings) > 0 {
			span.SetFindingID(findings[0].ControlID.String() + "@" + string(findings[0].AssetID))
		}
		span.End()

		s.collector.RecordCheck(check)
		s.collector.RecordFindings(findings)
		// Increment exposed-resource count only when a violation
		// verdict actually came back from the strategy. Recording
		// pre-evaluation on lifecycle.IsExposed inflated the
		// counter past the violation total because it included
		// snapshots that no control matched.
		if check.IsViolation() {
			s.collector.RecordNonCompliantAsset(id)
		}
	}
	return nil
}

func (s *assessmentSession) compileReport() evaluation.ComplianceReport {
	// Snapshot the collector under its own mutex so the compile pass
	// sees a consistent view of findings / checks / skippedControls /
	// exemptedAssets. Direct reads were technically safe today (Assess
	// finishes all writers before compileReport runs), but the absence
	// of a happens-before relationship means a future async writer
	// would race silently.
	snap := s.collector.Snapshot()

	evaluation.SortFindings(snap.Findings)

	slices.SortFunc(snap.ExemptedAssets, func(a, b asset.ExemptedAsset) int {
		return cmp.Compare(a.ID, b.ID)
	})

	slices.SortFunc(snap.Checks, func(a, b evaluation.ResourceCheck) int {
		if c := cmp.Compare(a.ControlID, b.ControlID); c != 0 {
			return c
		}
		return cmp.Compare(a.AssetID, b.AssetID)
	})

	// Filter findings through active security exceptions.
	activeFindings, exceptedFindings := partitionFindings(
		snap.Findings,
		s.assessor.exceptions,
		s.auditTime,
	)

	// Apply acknowledgments. exceptedFindings is passed in so the
	// compensating-control validation can distinguish "this cc
	// genuinely passed" from "this cc was excepted from evaluation
	// and we don't actually know its state". Treating an excepted
	// control as passing would let an acknowledgment pretend its
	// safety net is in place while no signal exists.
	activeFindings, acknowledgedFindings := applyAcknowledgments(
		activeFindings,
		exceptedFindings,
		s.assessor.acknowledgments,
		s.auditTime,
	)

	// Calculate environmental risk based on pending violations.
	// Pass Exemptions so the risk pipeline filters exempted assets
	// the same way the main finding pipeline does — otherwise an
	// exempted asset can still flip overall posture to AT_RISK
	// through risk signals. Pass SuppressedFindings derived from
	// excepted/acknowledged findings for the same reason: a fully
	// acknowledged report must not surface AT_RISK posture via
	// upcoming threshold signals on findings the operator has
	// already accepted.
	suppressed := buildSuppressionSet(exceptedFindings, acknowledgedFindings)
	riskSignals := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                s.assessor.Controls(),
		Snapshots:               s.snapshots,
		GlobalMaxUnsafeDuration: s.assessor.slaThreshold,
		Now:                     s.auditTime,
		PredicateEval:           s.assessor.predicateEval,
		Exemptions:              s.assessor.exemptions,
		SuppressedFindings:      suppressed,
	})

	posture := evaluation.DeriveSecurityState(len(activeFindings), riskSignals)

	report := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			Now:               s.auditTime,
			MaxUnsafeDuration: kernel.Duration(s.assessor.slaThreshold),
			Snapshots:         len(s.snapshots),
			InputHashes:       s.opts.InputHashes,
			PolicyFingerprint: s.assessor.FingerprintPolicy(),
			EvaluatedState:    evaluatedState(s.snapshots),
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      s.collector.SeenAssetCount(),
			ExposedResources: s.collector.NonCompliantAssetCount(),
			Violations:       len(activeFindings),
		},
		SecurityState:        posture,
		RiskSignals:          riskSignals,
		Findings:             activeFindings,
		ExceptedFindings:     exceptedFindings,
		AcknowledgedFindings: acknowledgedFindings,
		SkippedControls:      snap.SkippedControls,
		ExemptedAssets:       snap.ExemptedAssets,
		Checks:               snap.Checks,
	}

	if s.opts.GenerateEvidence && len(s.snapshots) > 0 {
		latestSnap := &s.snapshots[len(s.snapshots)-1]
		report.EvidencePackage = buildEvidencePackage(
			activeFindings,
			snap.Checks,
			s.assessor.Controls(),
			latestSnap,
			s.auditTime,
		)
	}

	return report
}

// partitionFindings separates violations into active findings and accepted exceptions.
func partitionFindings(
	findings []evaluation.Finding,
	exceptions *policy.ExceptionConfig,
	now time.Time,
) ([]evaluation.Finding, []evaluation.ExceptedFinding) {
	var active []evaluation.Finding
	var excepted []evaluation.ExceptedFinding
	for i := range findings {
		f := &findings[i]
		if rule := exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			excepted = append(excepted, evaluation.ExceptedFinding{
				ControlID: f.ControlID,
				AssetID:   f.AssetID,
				Reason:    rule.Reason,
				Expires:   rule.Expires,
			})
		} else {
			active = append(active, *f)
		}
	}
	return active, excepted
}

// buildSuppressionSet collects the (controlID, assetID) tuples for
// every excepted or validly-acknowledged finding so risk signals
// computed from raw snapshots can skip the same items the active
// finding pipeline already filtered out. Invalid acknowledgments
// (expired, compensating-control failing) are NOT suppressed:
// their findings stay active and risk should still surface.
func buildSuppressionSet(
	excepted []evaluation.ExceptedFinding,
	acknowledged []policy.AcknowledgedFinding,
) map[risk.SuppressionKey]struct{} {
	if len(excepted) == 0 && len(acknowledged) == 0 {
		return nil
	}
	out := make(map[risk.SuppressionKey]struct{}, len(excepted)+len(acknowledged))
	for i := range excepted {
		out[risk.SuppressionKey{ControlID: excepted[i].ControlID, AssetID: excepted[i].AssetID}] = struct{}{}
	}
	for i := range acknowledged {
		if !acknowledged[i].Valid {
			continue
		}
		out[risk.SuppressionKey{ControlID: acknowledged[i].ControlID, AssetID: acknowledged[i].AssetID}] = struct{}{}
	}
	return out
}

// applyAcknowledgments separates acknowledged findings from active findings.
// Returns remaining active findings and a slice of acknowledged finding records.
//
// Compensating-control validation tracks failing AND excepted controls
// per asset. A compensating control is only counted "passing" when it
// genuinely passed evaluation; if it was filtered by an exception we
// have no positive signal that the safety net is in place, so it
// counts as failing for acknowledgment purposes. The earlier shape
// treated excepted controls as passing, which let an acknowledgment
// quietly stand on a control that was never verified.
func applyAcknowledgments(
	findings []evaluation.Finding,
	exceptedFindings []evaluation.ExceptedFinding,
	acks *policy.AcknowledgmentConfig,
	now time.Time,
) ([]evaluation.Finding, []policy.AcknowledgedFinding) {
	if acks == nil {
		return findings, nil
	}

	// Build per-asset failing-control sets from the active (non-excepted)
	// findings. The earlier shape used a single global set keyed by
	// ControlID, so a failure of CTL.X on asset B invalidated every
	// acknowledgment for CTL.X on asset A — even though A's compensating
	// control was passing on A. Per-asset partitioning preserves the
	// original intent: a compensating control is "passing" relative to
	// the asset whose acknowledgment we're validating.
	failingByAsset := make(map[asset.ID]map[kernel.ControlID]bool)
	for i := range findings {
		assetID := findings[i].AssetID
		if failingByAsset[assetID] == nil {
			failingByAsset[assetID] = make(map[kernel.ControlID]bool)
		}
		failingByAsset[assetID][findings[i].ControlID] = true
	}

	// Excepted controls are tracked separately so we can distinguish
	// "passed" from "filtered". A compensating control that was
	// excepted on this asset has no verification signal — treating
	// it as passing was the bug.
	exceptedByAsset := make(map[asset.ID]map[kernel.ControlID]bool)
	for i := range exceptedFindings {
		ef := &exceptedFindings[i]
		if exceptedByAsset[ef.AssetID] == nil {
			exceptedByAsset[ef.AssetID] = make(map[kernel.ControlID]bool)
		}
		exceptedByAsset[ef.AssetID][ef.ControlID] = true
	}

	var active []evaluation.Finding
	var acknowledged []policy.AcknowledgedFinding

	for i := range findings {
		f := &findings[i]
		rule := acks.FindRule(f.ControlID, f.AssetID)
		if rule == nil {
			active = append(active, *f)
			continue
		}

		af := policy.AcknowledgedFinding{
			FindingID:        string(f.FindingID),
			ControlID:        f.ControlID,
			AssetID:          f.AssetID,
			Severity:         f.ControlSeverity,
			Rationale:        rule.Rationale,
			AcknowledgedBy:   rule.AcknowledgedBy,
			AcknowledgedDate: rule.AcknowledgedDate,
			ExpiryDate:       rule.ExpiryDate,
		}

		// Check expiry.
		if rule.IsExpired(now) {
			af.Verdict = "fail"
			af.Valid = false
			af.InvalidReason = "expired"
			acknowledged = append(acknowledged, af)
			active = append(active, *f) // revert to active
			continue
		}

		// Check compensating controls scoped to *this* asset's failures.
		// A different asset's failure of the same control does not
		// invalidate this acknowledgment. A compensating control
		// that was excepted on this asset has no verification
		// signal, so it does not count as passing — we record its
		// status as "excepted" to surface the gap rather than
		// silently treating absence as success.
		assetFailing := failingByAsset[f.AssetID]
		assetExcepted := exceptedByAsset[f.AssetID]
		allCompPassing := true
		for _, cc := range rule.CompensatingControls {
			var status string
			switch {
			case assetFailing[cc]:
				status = "fail"
				allCompPassing = false
			case assetExcepted[cc]:
				status = "excepted"
				allCompPassing = false
			default:
				status = "pass"
			}
			af.CompensatingControls = append(af.CompensatingControls,
				policy.CompensatingControlStatus{ControlID: cc, Status: status})
		}

		if !allCompPassing {
			af.Verdict = "fail"
			af.Valid = false
			af.InvalidReason = "compensating_controls_failing"
			acknowledged = append(acknowledged, af)
			active = append(active, *f) // revert to active
			continue
		}

		// Valid acknowledgment.
		af.Verdict = "acknowledged"
		af.Valid = true
		acknowledged = append(acknowledged, af)
		// Finding is NOT added to active — it's acknowledged.
	}

	return active, acknowledged
}

// FingerprintPolicy returns a deterministic hash of the active control-set.
// This provides an integrity check for auditors to verify which rules were enforced.
func (a *Assessor) FingerprintPolicy() kernel.Digest {
	if len(a.controls) == 0 || a.hasher == nil {
		return ""
	}
	// Include evaluator identity — prevents silent evaluator swap.
	// Hash per-control fingerprints (which include predicate, severity,
	// type — not just IDs) sorted by ID for determinism.
	fingerprints := make([]string, 0, len(a.controls)+1)
	fingerprints = append(fingerprints, "eval_version:"+stavecel.EvalVersion)
	for i := range a.controls {
		ctl := &a.controls[i]
		fingerprints = append(fingerprints, string(ctl.ID)+":"+string(ctl.Fingerprint(a.hasher)))
	}
	slices.Sort(fingerprints)
	return a.hasher.Digest(fingerprints, '\n')
}

// DefaultContinuityLimit defines the maximum gap allowed between observations
// before results are considered INCONCLUSIVE.
const DefaultContinuityLimit = 12 * time.Hour

// evaluatedState extracts the source context from the latest snapshot.
func evaluatedState(snapshots []asset.Snapshot) string {
	if len(snapshots) == 0 {
		return ""
	}
	return string(snapshots[len(snapshots)-1].Source)
}
