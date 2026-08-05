package engine

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"slices"
	"time"

	"golang.org/x/sync/errgroup"

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
var ErrClockMissing = errors.New("assessor: clock is nil; supply WithClock to NewAssessor")

func (a *Assessor) currentSpan() ports.AssessmentSpan { return nopSpan{} }

// Logger returns the structured logger configured at construction.
// Falls back to slog.Default() when no logger was wired so callers
// never need to nil-check the result. The defensive accessor
// covers every code path that might leave a.logger nil — callers
// in the evaluation pipeline expect a valid sink unconditionally.
func (a *Assessor) Logger() *slog.Logger {
	if a == nil || a.logger == nil {
		return slog.Default()
	}
	return a.logger
}

// PredicateParser returns the configured predicate parser.
func (a *Assessor) PredicateParser() policy.PredicateParser { return a.predicateParser }

// ContinuityLimit returns the configured continuity limit (max
// allowed gap between observation snapshots).
func (a *Assessor) ContinuityLimit() time.Duration { return a.continuityLimit }

// slaThresholdFor returns the effective SLA (Max Unsafe Duration) for a control.
// A nil control falls back to the assessor's default SLA threshold rather than
// panicking — callers in the chain-finding path occasionally synthesize
// findings without a corresponding ControlDefinition lookup.
func (a *Assessor) slaThresholdFor(ctl *policy.ControlDefinition) time.Duration {
	if ctl == nil {
		return a.slaThreshold
	}
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
		return cmp.Compare(string(i.Source), string(j.Source))
	})
	return sorted
}

// referenceTime establishes the "audit now" timestamp.
// If --eval-time was set (FixedClock), the user's explicit time takes precedence.
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
// Concurrency: applyControl is safe to invoke from multiple goroutines
// concurrently. The trace span for each control×asset evaluation is
// carried as a per-call parameter (see strategyFor); no mutable span
// state lives on the session. The collector's own RecordCheck path is
// mutex-protected independently, so concurrent applyControl callers
// can write findings without contention beyond the collector's mu.
//
// Earlier revisions stored activeSpan on the session and used an
// atomic.Bool guard (applyControlInUse) to detect accidental
// concurrent callers; both were removed when per-control
// parallelisation landed. The contract is now structural: there is
// nothing to race because there is nothing shared-and-mutable.
type assessmentSession struct {
	assessor  *Assessor
	snapshots []asset.Snapshot
	auditTime time.Time
	collector *AssessmentCollector
	idIndex   IdentityIndex
	opts      AssessmentOptions
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
		return evaluation.ComplianceReport{}, fmt.Errorf("assess: %w", err)
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

	lifecycles, err := BuildLifecyclesPerControl(ctx, a.controls, sequenced, a.predicateEval)
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

	// Per-control evaluation runs concurrently up to runtime.NumCPU().
	// Each goroutine drives CEL evaluation for one control across the
	// asset set; writes that escape the goroutine all flow through
	// the AssessmentCollector's per-record mutex (see collector.go).
	// Determinism is preserved because compileReport sorts every
	// output slice — the order in which controls complete does not
	// reach the caller.
	//
	// Skipped (non-evaluatable) controls are recorded inline rather
	// than launching a goroutine per skip: the collector write is
	// trivial and a goroutine-per-skip would add scheduling overhead
	// for no benefit.
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.NumCPU())

	controlTimeout := 5 * time.Second
	if envTO := os.Getenv("STAVE_CONTROL_EVAL_TIMEOUT"); envTO != "" {
		if d, err := time.ParseDuration(envTO); err == nil && d > 0 {
			controlTimeout = d
		}
	}

	for i := range a.controls {
		ctl := &a.controls[i]
		if !ctl.IsEvaluatable() {
			sess.collector.RecordSkippedControl(
				ctl.ID,
				ctl.Name,
				"control type cannot be evaluated: "+ctl.Type.String(),
			)
			continue
		}
		pos := i // captured for the error message; gctx-derived cancellation does not preserve loop position
		g.Go(func() error {
			evalCtx, cancel := context.WithTimeout(gctx, controlTimeout)
			defer cancel()
			if err := evalCtx.Err(); err != nil {
				return fmt.Errorf("assess: cancelled before control %s (%d/%d): %w", ctl.ID, pos, len(a.controls), err)
			}
			if err := sess.applyControl(evalCtx, ctl, lifecycles[ctl.ID]); err != nil {
				if evalCtx.Err() != nil {
					return fmt.Errorf("control %s (%d/%d) timed out after %s: %w", ctl.ID, pos, len(a.controls), controlTimeout, err)
				}
				return fmt.Errorf("apply control %s (%d/%d): %w", ctl.ID, pos, len(a.controls), err)
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return evaluation.ComplianceReport{}, fmt.Errorf("assess: %w", err)
	}

	report := sess.compileReport()
	return report, nil
}

// applyControl evaluates a single control across the asset set.
//
// Concurrency: safe to invoke from multiple goroutines for different
// controls. The trace span for each control×asset pair is created
// inside this method and passed as a parameter into strategyFor —
// there is no shared mutable span state to race on. Writes into the
// collector go through its mutex-protected RecordX methods, which
// already serialise concurrent writers correctly.
func (s *assessmentSession) applyControl(
	ctx context.Context,
	ctl *policy.ControlDefinition,
	lifecycles map[asset.ID]*asset.ExposureLifecycle,
) error {
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
			return fmt.Errorf("apply control %s: cancelled mid-asset-loop: %w", ctl.ID, err)
		}
		lifecycle := lifecycles[id]
		span := s.beginTrace(string(id), ctl.ID.String())

		// Record the asset as seen before any exemption / exception
		// short-circuit so TotalAssets reflects every asset the control
		// considered. The previous shape only called RecordSeenAsset
		// after the exemption branch, so an exempted asset disappeared
		// from the denominator and inflated the compliance percentage.
		s.collector.RecordSeenAsset(id)

		// 1. Check for organizational exemptions (Policy Overrides).
		// ExemptionConfig.ShouldExempt is nil-safe on a nil receiver
		// (returns nil), so a partially-wired Assessor with no
		// exemptions configured does not panic here. See the
		// nil-receiver contract documented on NewAssessor.
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
		// RecordNonCompliantAsset is called below after strategy.Evaluate
		// so the counter reflects findings, not raw lifecycle state.
		// (RecordSeenAsset already fires at the top of the loop so
		// exempted assets are still counted in TotalAssets.)

		// 3. Evaluate the security strategy against the asset lifecycle.
		//    The strategy receives the span as a per-call parameter via
		//    strategyFor, so concurrent applyControl invocations for
		//    different controls do not contend on shared span state.
		//
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
		strat := s.strategyFor(ctl, span)
		check, findings := strat.Evaluate(lifecycle, s.auditTime, s.idIndex)

		// 4. Record verdict and finding linkage in the trace span
		span.SetVerdict(string(check.Verdict), string(check.Confidence))
		if len(findings) > 0 {
			span.SetFindingID(findings[0].SpanKey())
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

	// Split marker (fact-recording) findings off the violation
	// pipeline before exceptions / acknowledgments / risk signals
	// see them. Marker findings contribute to chain detection but
	// never to Summary.Violations / SecurityState / exit codes.
	violationCandidates, markerFindings := partitionMarkerFindings(snap.Findings, s.assessor.controls)

	// Filter findings through active security exceptions.
	activeFindings, exceptedFindings := partitionFindings(
		violationCandidates,
		s.assessor.exceptions,
		s.auditTime,
	)

	coverage := newEvaluationCoverage(snap.Checks)
	activeFindings = applyAcknowledgments(
		activeFindings,
		exceptedFindings,
		s.assessor.acknowledgments,
		s.auditTime,
		coverage,
	)

	// Merge all findings into one slice: active + excepted + acknowledged.
	allFindings := make([]evaluation.Finding, 0, len(activeFindings)+len(exceptedFindings))
	allFindings = append(allFindings, activeFindings...)
	allFindings = append(allFindings, exceptedFindings...)

	// Separate indeterminate findings (fired on absent fields only) from
	// confirmed violations before counting and deriving posture. Indeterminate
	// findings are coverage gaps, not confirmed misconfigurations.
	confirmedFindings, indeterminateFindings := partitionIndeterminateFindings(allFindings)

	suppressed := buildSuppressionSet(confirmedFindings)
	riskSignals := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                s.assessor.Controls(),
		Snapshots:               s.snapshots,
		GlobalMaxUnsafeDuration: s.assessor.slaThreshold,
		EvalTime:                s.auditTime,
		PredicateEval:           s.assessor.predicateEval,
		Exemptions:              s.assessor.exemptions,
		SuppressedFindings:      suppressed,
	})

	activeCount := 0
	for i := range confirmedFindings {
		if confirmedFindings[i].Status == evaluation.FindingActive {
			activeCount++
		}
	}
	posture := evaluation.DeriveSecurityState(activeCount, riskSignals)

	report := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:      s.opts.StaveVersion,
			Offline:           true,
			EvalTime:          s.auditTime,
			MaxUnsafeDuration: kernel.Duration(s.assessor.slaThreshold),
			Snapshots:         len(s.snapshots),
			InputHashes:       s.opts.InputHashes,
			PolicyFingerprint: s.assessor.FingerprintPolicy(),
			EvaluatedState:    evaluatedState(s.snapshots),
		},
		Summary: evaluation.ComplianceSummary{
			TotalAssets:      s.collector.SeenAssetCount(),
			ExposedResources: s.collector.NonCompliantAssetCount(),
			Violations:       activeCount,
			Indeterminate:    len(indeterminateFindings),
		},
		SecurityState:         posture,
		RiskSignals:           riskSignals,
		Findings:              confirmedFindings,
		IndeterminateFindings: indeterminateFindings,
		MarkerFindings:        markerFindings,
		SkippedControls:       snap.SkippedControls,
		ExemptedAssets:        snap.ExemptedAssets,
		Checks:                snap.Checks,
	}

	if s.opts.GenerateEvidence && len(s.snapshots) > 0 {
		// Pick the semantically latest snapshot rather than the
		// last slice element. sortSnapshots already orders the
		// session's snapshots ascending by CapturedAt, so today the
		// last index is correct — but the evidence pipeline reads
		// from a session field that any future caller (a
		// non-default ordering, an external source, a test that
		// hand-builds a session) might populate out of order.
		// Mirrors the explicit MaxFunc pattern referenceTime uses
		// for the same reason.
		latestSnap := slices.MaxFunc(s.snapshots, func(a, b asset.Snapshot) int {
			return a.CapturedAt.Compare(b.CapturedAt)
		})
		report.EvidencePackage = buildEvidencePackage(
			activeFindings,
			snap.Checks,
			s.assessor.Controls(),
			&latestSnap,
			s.auditTime,
		)
	}

	return report
}

// partitionIndeterminateFindings splits findings into confirmed violations
// and indeterminate results. A finding is indeterminate when every
// misconfiguration in its evidence was triggered by an absent field
// (FieldAbsent=true) — the predicate fired due to fail-closed semantics
// on missing data, not because the resource was confirmed insecure.
func partitionIndeterminateFindings(findings []evaluation.Finding) (confirmed, indeterminate []evaluation.Finding) {
	for i := range findings {
		if findings[i].IsIndeterminate() {
			indeterminate = append(indeterminate, findings[i])
		} else {
			confirmed = append(confirmed, findings[i])
		}
	}
	return confirmed, indeterminate
}

// partitionMarkerFindings splits raw findings into violation
// candidates (everything that should flow through the existing
// exception / acknowledgment / risk pipeline) and marker findings
// (fact-recording findings emitted by TypeMarker controls). The
// caller routes the two slices to different downstream stages so
// markers never count toward Summary.Violations or SecurityState.
//
// The split uses an O(n + m) pass over findings + controls: build
// a small set of marker control IDs once, then route each finding
// by lookup.
func partitionMarkerFindings(
	findings []evaluation.Finding,
	controls []policy.ControlDefinition,
) (violations, markers []evaluation.Finding) {
	markerIDs := make(map[kernel.ControlID]struct{})
	for i := range controls {
		if controls[i].IsMarker() {
			markerIDs[controls[i].ID] = struct{}{}
		}
	}
	if len(markerIDs) == 0 {
		// Common path — most catalogs have zero marker controls.
		// Skip the per-finding lookup and return the input as-is.
		return findings, nil
	}
	for i := range findings {
		f := &findings[i]
		if _, ok := markerIDs[f.ControlID]; ok {
			markers = append(markers, *f)
		} else {
			violations = append(violations, *f)
		}
	}
	return violations, markers
}

// partitionFindings separates violations into active findings and accepted exceptions.
func partitionFindings(
	findings []evaluation.Finding,
	exceptions *policy.ExceptionConfig,
	now time.Time,
) (active, excepted []evaluation.Finding) {
	for i := range findings {
		f := findings[i]
		if rule := exceptions.ShouldExcept(f.ControlID, f.AssetID, now); rule != nil {
			f.Status = evaluation.FindingSuppressed
			f.Suppression = &evaluation.Suppression{
				Kind:    "exemption",
				Reason:  rule.Reason,
				Expires: rule.Expires,
				Valid:   true,
			}
			excepted = append(excepted, f)
		} else {
			f.Status = evaluation.FindingActive
			active = append(active, f)
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
func buildSuppressionSet(findings []evaluation.Finding) map[risk.SuppressionKey]struct{} {
	out := make(map[risk.SuppressionKey]struct{})
	for i := range findings {
		f := &findings[i]
		if f.Status != evaluation.FindingSuppressed {
			continue
		}
		if f.Suppression != nil && !f.Suppression.Valid {
			continue
		}
		out[risk.SuppressionKey{ControlID: f.ControlID, AssetID: f.AssetID}] = struct{}{}
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
// EvaluationCoverage records the (asset, control) pairs that were
// actually evaluated during this assessment run. Acknowledgment
// validation consults it so a compensating control that was never
// evaluated reads as "unevaluated" instead of silently passing.
//
// The map-of-maps shape is hidden behind Contains so call sites
// read as a domain question ("was this control evaluated for this
// asset?") rather than a two-step nested lookup. Construct via
// newEvaluationCoverage; the zero value behaves like "nothing
// evaluated".
type EvaluationCoverage map[asset.ID]map[kernel.ControlID]struct{}

// Contains reports whether the (assetID, controlID) pair appears
// in this run's recorded check set.
func (c EvaluationCoverage) Contains(assetID asset.ID, controlID kernel.ControlID) bool {
	if c == nil {
		return false
	}
	controls, ok := c[assetID]
	if !ok {
		return false
	}
	_, present := controls[controlID]
	return present
}

// newEvaluationCoverage indexes the recorded ResourceChecks by
// (assetID, controlID) so the compensating-control loop can ask
// the coverage map a domain question instead of building the
// nested map at the call site.
func newEvaluationCoverage(checks []evaluation.ResourceCheck) EvaluationCoverage {
	out := make(EvaluationCoverage, len(checks))
	for i := range checks {
		c := &checks[i]
		if out[c.AssetID] == nil {
			out[c.AssetID] = make(map[kernel.ControlID]struct{})
		}
		out[c.AssetID][c.ControlID] = struct{}{}
	}
	return out
}

func applyAcknowledgments(
	activeFindings []evaluation.Finding,
	exceptedFindings []evaluation.Finding,
	acks *policy.AcknowledgmentConfig,
	now time.Time,
	coverage EvaluationCoverage,
) []evaluation.Finding {
	if acks == nil {
		return activeFindings
	}

	failingByAsset := make(map[asset.ID]map[kernel.ControlID]struct{})
	for i := range activeFindings {
		assetID := activeFindings[i].AssetID
		if failingByAsset[assetID] == nil {
			failingByAsset[assetID] = make(map[kernel.ControlID]struct{})
		}
		failingByAsset[assetID][activeFindings[i].ControlID] = struct{}{}
	}

	exceptedByAsset := make(map[asset.ID]map[kernel.ControlID]struct{})
	for i := range exceptedFindings {
		ef := &exceptedFindings[i]
		if exceptedByAsset[ef.AssetID] == nil {
			exceptedByAsset[ef.AssetID] = make(map[kernel.ControlID]struct{})
		}
		exceptedByAsset[ef.AssetID][ef.ControlID] = struct{}{}
	}

	var result []evaluation.Finding

	for i := range activeFindings {
		f := activeFindings[i]
		rule := acks.FindRule(f.ControlID, f.AssetID)
		if rule == nil {
			result = append(result, f)
			continue
		}

		if rule.IsExpired(now) {
			f.Status = evaluation.FindingSuppressed
			f.Suppression = &evaluation.Suppression{
				Kind:             "acknowledgment",
				Rationale:        rule.Rationale,
				AcknowledgedBy:   rule.AcknowledgedBy,
				AcknowledgedDate: rule.AcknowledgedDate,
				ExpiryDate:       rule.ExpiryDate,
				Valid:            false,
				InvalidReason:    "expired",
			}
			result = append(result, f)
			continue
		}

		assetFailing := failingByAsset[f.AssetID]
		assetExcepted := exceptedByAsset[f.AssetID]
		allCompPassing := true
		for _, cc := range rule.CompensatingControls {
			_, hasFailing := assetFailing[cc]
			_, hasExcepted := assetExcepted[cc]
			switch {
			case hasFailing:
				allCompPassing = false
			case hasExcepted:
				allCompPassing = false
			case !coverage.Contains(f.AssetID, cc):
				allCompPassing = false
			}
		}

		if !allCompPassing {
			f.Status = evaluation.FindingSuppressed
			f.Suppression = &evaluation.Suppression{
				Kind:             "acknowledgment",
				Rationale:        rule.Rationale,
				AcknowledgedBy:   rule.AcknowledgedBy,
				AcknowledgedDate: rule.AcknowledgedDate,
				ExpiryDate:       rule.ExpiryDate,
				Valid:            false,
				InvalidReason:    "compensating_controls_failing",
			}
			result = append(result, f)
			continue
		}

		f.Status = evaluation.FindingSuppressed
		f.Suppression = &evaluation.Suppression{
			Kind:             "acknowledgment",
			Rationale:        rule.Rationale,
			AcknowledgedBy:   rule.AcknowledgedBy,
			AcknowledgedDate: rule.AcknowledgedDate,
			ExpiryDate:       rule.ExpiryDate,
			Valid:            true,
		}
		result = append(result, f)
	}

	return result
}

// hasEmptyPolicy reports whether this assessor has no controls
// loaded — a legitimate "nothing to evaluate" state (e.g. no
// controls match the active vendor). Encapsulates the slice-length
// probe so the storage layout for controls can change without
// touching every fingerprint / count call site.
func (a *Assessor) hasEmptyPolicy() bool {
	return len(a.controls) == 0
}

// canComputeDigests reports whether this assessor was wired with a
// Digester (the dependency that turns a control fingerprint set into
// a deterministic hash). When false, fingerprinting / integrity
// signing is off the table — that's a configuration gap, not a
// transient state, and callers should warn rather than silently
// emit an empty digest.
func (a *Assessor) canComputeDigests() bool {
	return a.hasher != nil
}

// FingerprintPolicy returns a deterministic hash of the active control-set.
// This provides an integrity check for auditors to verify which rules were enforced.
//
// Returns "" with no error in two distinct cases:
//   - empty policy: the assessor has nothing to fingerprint (legitimate
//     empty-catalog state, e.g. when no controls match the active vendor).
//   - missing digester: the assessor was wired without one. This is an
//     audit gap — the audit-trail consumer expected a fingerprint and
//     gets nothing back. Surface a slog.Warn so the gap is visible
//     instead of a silent empty digest in compliance reports.
//
// PolicyPreimage returns the canonical sorted lines that feed the
// policy fingerprint hash. Format: eval_version:<version> as the
// first logical entry (sorts after CTL.* due to ASCII ordering),
// then one <control_id>:<per-control-hash> line per control,
// sorted ascending. PolicyFingerprint() is exactly
// sha256(join(PolicyPreimage(), '\n')).
func (a *Assessor) PolicyPreimage() []string {
	if a.hasEmptyPolicy() || !a.canComputeDigests() {
		return nil
	}
	lines := make([]string, 0, len(a.controls)+1)
	lines = append(lines, "eval_version:"+EvalVersion)
	for i := range a.controls {
		ctl := &a.controls[i]
		lines = append(lines, string(ctl.ID)+":"+string(ctl.Fingerprint(a.hasher)))
	}
	slices.Sort(lines)
	return lines
}

// FingerprintPolicy returns sha256(PolicyPreimage()). This is the
// single source — there is no second hash path.
func (a *Assessor) FingerprintPolicy() kernel.Digest {
	lines := a.PolicyPreimage()
	if lines == nil {
		if !a.hasEmptyPolicy() {
			slog.Warn("assessor: FingerprintPolicy called without a Digester; emitting empty digest",
				"controls", len(a.controls))
		}
		return ""
	}
	return a.hasher.Digest(lines, '\n')
}

// DefaultContinuityLimit defines the maximum gap allowed between observations
// before results are considered INCONCLUSIVE.
const DefaultContinuityLimit = 12 * time.Hour

// evaluatedState extracts the source context from the latest
// snapshot. Picks via slices.MaxFunc on CapturedAt rather than slice
// position so the answer is correct regardless of whether the
// caller pre-sorted; the standard apply pipeline runs sortSnapshots
// before calling, but a hand-built session or future caller might
// not. Mirrors the explicit-max pattern referenceTime and
// compileReport's evidence selection already use.
func evaluatedState(snapshots []asset.Snapshot) string {
	if len(snapshots) == 0 {
		return ""
	}
	latest := slices.MaxFunc(snapshots, func(a, b asset.Snapshot) int {
		return a.CapturedAt.Compare(b.CapturedAt)
	})
	return string(latest.Source)
}
