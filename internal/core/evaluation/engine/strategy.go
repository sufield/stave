package engine

import (
	"log/slog"
	"time"

	"github.com/sufield/stave/internal/core/ports"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// strategyDeps abstracts the Assessor capabilities that strategies need,
// decoupling them from the concrete Assessor type. Methods are
// capitalized so they don't collide with the unexported field names
// of the same concept on the Assessor itself (Go differentiates by
// case but the duplicate-name diagnostic fires at compile time).
type strategyDeps interface {
	slaThresholdFor(ctl *policy.ControlDefinition) time.Duration
	ContinuityLimit() time.Duration
	confidenceCalculator() evaluation.ConfidenceCalculator
	Logger() *slog.Logger
	PredicateParser() policy.PredicateParser
	currentSpan() ports.AssessmentSpan
}

// strategy defines how different control types analyze a lifecycle.
type strategy interface {
	Evaluate(t *asset.ExposureLifecycle, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding)
}

// Compile-time interface assertions.
var (
	_ strategy = (*unsafeStateStrategy)(nil)
	_ strategy = (*unsafeDurationStrategy)(nil)
	_ strategy = (*unsafeRecurrenceStrategy)(nil)
	_ strategy = (*prefixExposureStrategy)(nil)
	_ strategy = (*unsupportedStrategy)(nil)
)

// validateCoverage runs the standard coverage check used by every
// duration- or recurrence-style strategy: minimum coverage span equal
// to the threshold (or recurrence window), maximum gap equal to the
// strategy's continuity limit. Returns (reason, false) when coverage
// is insufficient and the caller should downgrade to INCONCLUSIVE.
//
// The validator was constructed inline by both unsafeDurationStrategy
// and unsafeRecurrenceStrategy with identical field assignments —
// centralizing the construction makes the "what does sufficient
// coverage mean" decision live in one place.
func validateCoverage(deps strategyDeps, t *asset.ExposureLifecycle, minSpan time.Duration) (string, bool) {
	v := CoverageValidator{
		minRequiredSpan: minSpan,
		maxAllowedGap:   deps.ContinuityLimit(),
	}
	return v.IsSufficient(t)
}

// emitViolationFinding builds the violation finding for a duration-style
// control and finalizes the observation row. Centralizes the
// CreateDurationFinding-call → nil-guard → durErr-warning →
// finalizeRow(VerdictViolation) sequence repeated by both
// unsafeStateStrategy and unsafeDurationStrategy. A change to the
// "what does a violation row look like" contract now lands in one place.
//
// On unrecoverable construction failure, returns the row marked
// INCONCLUSIVE and nil findings — the assessor counts violations from
// the findings slice, so emitting a Violation verdict without a finding
// would inflate report totals.
func emitViolationFinding(
	deps strategyDeps,
	ctl *policy.ControlDefinition,
	t *asset.ExposureLifecycle,
	maxUnsafe time.Duration,
	now time.Time,
	ids IdentityIndex,
	observation evaluation.ResourceCheck,
) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation.TemporalRisk = t.FormatExposureSummary(maxUnsafe, now)
	finding, durErr := CreateDurationFinding(DurationFindingInput{
		ExposureLifecycle: t,
		Control:           ctl,
		Threshold:         maxUnsafe,
		Now:               now,
		Identities:        ids.At(t.LastObservedAt()),
		PredicateParser:   deps.PredicateParser(),
	})
	// CreateDurationFinding's contract is "(*Finding, error)" with the
	// finding always non-nil. If a future refactor returns nil anyway,
	// we cannot describe the violation — downgrade to INCONCLUSIVE so
	// the assessor's violation count stays consistent with the findings
	// list. The alternative (emit VerdictViolation with empty findings)
	// inflates the violations summary above the visible finding count.
	if finding == nil {
		deps.Logger().Warn("CreateDurationFinding returned nil finding; downgrading verdict to INCONCLUSIVE to keep counts consistent",
			"control", ctl.ID, "asset", t.ID)
		observation.MarkInconclusive("violation finding could not be constructed")
		return observation, nil
	}
	findings := []*evaluation.Finding{finding}
	if durErr != nil {
		// Mark evidence invalid so report renderers avoid arithmetic
		// on the sentinel duration (-1.0). The verdict still stands —
		// CreateDurationFinding's contract is "the asset is in
		// violation, but I couldn't compute exact dwell" — but
		// evidence-derived numbers are unreliable.
		finding.Evidence.EvidenceInvalid = true
		deps.Logger().Warn("duration calculation failed; emitting violation with sentinel duration -1.0 and evidence_invalid=true",
			"control", ctl.ID, "asset", t.ID, "error", durErr,
			"finding_emitted", true)
	}
	confidence := deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
	return finalizeRow(observation, evaluation.VerdictViolation, confidence), findings
}

// strategyFor returns the appropriate evaluator based on the control type.
// The Assessor version is used by tests; the session version adds the trace span.
func (a *Assessor) strategyFor(ctl *policy.ControlDefinition) strategy {
	return buildStrategy(&sessionDeps{Assessor: a, span: nopSpan{}}, ctl)
}

// strategyFor returns the appropriate evaluator with the active trace span.
func (s *assessmentSession) strategyFor(ctl *policy.ControlDefinition) strategy {
	return buildStrategy(&sessionDeps{Assessor: s.assessor, span: s.activeSpan}, ctl)
}

// StrategyFactory constructs the appropriate strategy for a control of a
// given Type. Registered into strategyRegistry; buildStrategy looks the
// factory up by control type.
type StrategyFactory func(deps strategyDeps, ctl *policy.ControlDefinition) strategy

// strategyRegistry maps control type to its constructor. Adding a new
// control type means a new entry here — no switch case to keep in sync,
// no fallthrough to forget. Existing control types are listed in their
// declaration order; ordering is irrelevant for lookups.
var strategyRegistry = map[policy.ControlType]StrategyFactory{
	policy.TypeUnsafeState: func(deps strategyDeps, ctl *policy.ControlDefinition) strategy {
		return &unsafeStateStrategy{deps: deps, ctl: ctl}
	},
	policy.TypeUnsafeDuration: func(deps strategyDeps, ctl *policy.ControlDefinition) strategy {
		return &unsafeDurationStrategy{deps: deps, ctl: ctl}
	},
	policy.TypeUnsafeRecurrence: func(deps strategyDeps, ctl *policy.ControlDefinition) strategy {
		return &unsafeRecurrenceStrategy{deps: deps, ctl: ctl}
	},
	policy.TypePrefixExposure: func(_ strategyDeps, ctl *policy.ControlDefinition) strategy {
		return &prefixExposureStrategy{ctl: ctl}
	},
}

func buildStrategy(deps strategyDeps, ctl *policy.ControlDefinition) strategy {
	if factory, ok := strategyRegistry[ctl.Type]; ok {
		return factory(deps, ctl)
	}
	return &unsupportedStrategy{ctl: ctl}
}

// --- Duration & State Strategies ---

type unsafeStateStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeStateStrategy) Evaluate(t *asset.ExposureLifecycle, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	if s.ctl == nil {
		return evaluation.ResourceCheck{}, nil
	}
	observation := newControlRow(s.ctl, t)
	// unsafe_state is "this state must not be true" — not "this state
	// must not last longer than X." If the control author did NOT set
	// per-control max_unsafe_duration, fire immediately rather than
	// borrowing the global CLI fallback (default 168h). The fallback
	// is appropriate for unsafe_duration controls; applying it to
	// unsafe_state silently gave critical states (public buckets,
	// unrestricted ingress) up to a 7-day grace window where the
	// control author intended immediate detection. Per-control
	// max_unsafe_duration is still honored when explicitly declared.
	var maxUnsafe time.Duration
	if s.ctl.PreparedParams().HasMaxUnsafeDuration {
		maxUnsafe = s.deps.slaThresholdFor(s.ctl)
	}
	span := s.deps.currentSpan()

	span.RecordStep("predicate_evaluation", map[string]any{
		"currently_unsafe": !t.IsSecure(),
		"exposure_count":   t.History().Count(),
	}, map[string]any{
		"matched": !t.IsSecure(),
	})

	verdict, reason := t.VerdictWithReason(now, maxUnsafe)
	switch verdict {
	case asset.VerdictSecure:
		// VerdictWithReason returns ReasonSecurePredicateNotMatched
		// when the asset is not exposed and ReasonSecureWithinThreshold
		// when it is exposed but within the SLA window. Use the
		// reason to drive the trace step instead of re-querying
		// IsExposed.
		if reason == asset.ReasonSecurePredicateNotMatched {
			span.RecordStep("verdict_decision", nil, map[string]any{
				"verdict": "PASS",
				"reason":  reason,
			})
			return finalizeRow(observation, evaluation.VerdictPass, evaluation.ConfidenceHigh), nil
		}
		span.RecordStep("threshold_check", map[string]any{
			"threshold_hours":  maxUnsafe.Hours(),
			"last_seen_unsafe": t.LastObservedAt(),
		}, map[string]any{
			"exceeds_threshold": false,
		})
		span.RecordStep("verdict_decision", nil, map[string]any{
			"verdict": "PASS",
			"reason":  reason,
		})
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
		return finalizeRow(observation, evaluation.VerdictPass, confidence), nil

	case asset.VerdictInconclusive:
		// Reason carries the lifecycle sub-state directly — log the
		// threshold-check warning when the evaluator hit the
		// degraded-arithmetic path, then mark inconclusive with the
		// already-classified reason.
		if reason == asset.ReasonInconclusiveThresholdError {
			s.deps.Logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID)
		}
		observation.MarkInconclusive(reason)
		return observation, nil

	case asset.VerdictExposed:
		span.RecordStep("threshold_check", map[string]any{
			"threshold_hours":  maxUnsafe.Hours(),
			"last_seen_unsafe": t.LastObservedAt(),
		}, map[string]any{
			"exceeds_threshold": true,
		})
		return emitViolationFinding(s.deps, s.ctl, t, maxUnsafe, now, ids, observation)
	}

	// Unreachable: Verdict returns one of the three constants above.
	// A future enum addition without a matching case would fall through
	// here; mark inconclusive rather than silently returning a zero row.
	observation.MarkInconclusive("unhandled lifecycle verdict")
	return observation, nil
}

type unsafeDurationStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeDurationStrategy) Evaluate(t *asset.ExposureLifecycle, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	if s.ctl == nil {
		return evaluation.ResourceCheck{}, nil
	}
	observation := newControlRow(s.ctl, t)
	maxUnsafe := s.deps.slaThresholdFor(s.ctl)
	span := s.deps.currentSpan()

	// For unsafe_duration controls the predicate is "duration of an
	// unsafe window exceeded the threshold" — that result is the
	// threshold_check step's `exceeds_threshold` output, not the
	// instantaneous `IsExposed` reading. Record only the inputs here
	// so the trace does not claim the control matched (or did not
	// match) before the duration check has run.
	span.RecordStep("predicate_evaluation", map[string]any{
		"currently_unsafe": t.IsExposed(),
		"exposure_count":   t.History().Count(),
	}, nil)

	// 1. Violation Check (Always takes precedence)
	exceeds, threshErr := t.ExceedsSLA(now, maxUnsafe)
	if threshErr != nil {
		s.deps.Logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID, "error", threshErr)
		observation.MarkInconclusive("threshold check error")
		return observation, nil
	}

	span.RecordStep("threshold_check", map[string]any{
		"threshold_hours": maxUnsafe.Hours(),
		"max_gap_hours":   t.Stats().MaxGap().Hours(),
	}, map[string]any{
		"exceeds_threshold": exceeds,
	})

	if exceeds {
		return emitViolationFinding(s.deps, s.ctl, t, maxUnsafe, now, ids, observation)
	}

	// 2. Coverage Check (Is the data sufficient to say it's a PASS?)
	if reason, ok := validateCoverage(s.deps, t, maxUnsafe); !ok {
		span.RecordStep("coverage_check", map[string]any{
			"min_required_span_hours": maxUnsafe.Hours(),
			"observation_span_hours":  t.Stats().CoverageSpan().Hours(),
		}, map[string]any{
			"sufficient": false,
			"reason":     reason,
		})
		observation.MarkInconclusive(reason)
		return observation, nil
	}

	// 3. Adequate coverage and no violation => PASS
	span.RecordStep("verdict_decision", nil, map[string]any{
		"verdict": "PASS",
		"reason":  "threshold not exceeded and observation coverage is sufficient",
	})
	confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
	return finalizeRow(observation, evaluation.VerdictPass, confidence), nil
}

// --- Recurrence Strategy ---

type unsafeRecurrenceStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeRecurrenceStrategy) Evaluate(t *asset.ExposureLifecycle, now time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	if s.ctl == nil {
		return evaluation.ResourceCheck{}, nil
	}
	observation := newControlRow(s.ctl, t)
	p := s.ctl.RecurrencePolicy()
	span := s.deps.currentSpan()

	if !p.Enabled() {
		// "Disabled" here means the control's params don't carry the
		// recurrence_limit and window_days fields the policy needs to
		// run. The earlier shape returned VerdictPass, which read as
		// "we evaluated this and the asset is fine" — but in fact the
		// evaluator never executed any check. Downstream reporters
		// rolled the row up into the clean count, hiding the
		// configuration gap. VerdictSkipped is the documented "not
		// evaluated" verdict; downstream consumers (reporting, risk
		// scoring) treat it as a hole in coverage, not a clean state.
		observation.Reason = "missing recurrence parameters"
		return finalizeRow(observation, evaluation.VerdictSkipped, evaluation.ConfidenceHigh), nil
	}

	span.RecordStep("predicate_evaluation", map[string]any{
		"exposure_window_count": t.History().Count(),
		"recurrence_limit":      p.Limit,
		"window_days":           int(p.WindowDuration().Hours() / 24),
	}, map[string]any{
		"matched": t.IsExposed(),
	})

	// 1. Violation Check
	if findings := EvaluateRecurrenceForControl(t, s.ctl, now); len(findings) > 0 {
		span.RecordStep("recurrence_check", nil, map[string]any{
			"exceeds_limit": true,
			"finding_count": len(findings),
		})
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), p.WindowDuration())
		return finalizeRow(observation, evaluation.VerdictViolation, confidence), findings
	}

	// 2. Coverage Check
	//
	// Mirrors unsafeDurationStrategy: pass MaxAllowedGap so the
	// validator emits INCONCLUSIVE when snapshots have a hole big
	// enough to hide a recurrence. Without it, a recurrence
	// control would PASS on a sparse snapshot history that
	// could legitimately be missing several recurrence windows
	// inside the gap, producing a false-clean verdict.
	if reason, ok := validateCoverage(s.deps, t, p.WindowDuration()); !ok {
		span.RecordStep("coverage_check", nil, map[string]any{
			"sufficient": false,
			"reason":     reason,
		})
		observation.MarkInconclusive(reason)
		return observation, nil
	}

	span.RecordStep("verdict_decision", nil, map[string]any{
		"verdict": "PASS",
		"reason":  "recurrence count within limit and coverage is sufficient",
	})
	confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), p.WindowDuration())
	return finalizeRow(observation, evaluation.VerdictPass, confidence), nil
}

// --- Specialized Strategies ---

type prefixExposureStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *prefixExposureStrategy) Evaluate(t *asset.ExposureLifecycle, _ time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation, findings := EvaluatePrefixExposureForRow(t, s.ctl)
	return observation, wrapInPointers(findings)
}

type unsupportedStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *unsupportedStrategy) Evaluate(t *asset.ExposureLifecycle, _ time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	if s.ctl == nil {
		return evaluation.ResourceCheck{}, nil
	}
	observation := newControlRow(s.ctl, t)
	observation.Reason = "type not evaluatable: " + s.ctl.Type.String()
	return finalizeRow(observation, evaluation.VerdictSkipped, evaluation.ConfidenceHigh), nil
}

// --- Internal Helpers ---

func newControlRow(ctl *policy.ControlDefinition, t *asset.ExposureLifecycle) evaluation.ResourceCheck {
	// nil ctl: every Evaluate path passes a control owned by its
	// strategy struct, but a future caller (test scaffold, future
	// strategy refactor) could legitimately pass nil. Returning a
	// zero ResourceCheck is the safest no-information answer; the
	// downstream collector treats an empty ControlID as a skip.
	if ctl == nil {
		return evaluation.ResourceCheck{}
	}
	if t == nil {
		return evaluation.ResourceCheck{ControlID: ctl.ID}
	}
	resType := t.Asset().Type
	return evaluation.ResourceCheck{
		ControlID:   ctl.ID,
		AssetID:     t.ID,
		AssetType:   resType,
		AssetDomain: resType.Domain(),
	}
}

func finalizeRow(r evaluation.ResourceCheck, d evaluation.Verdict, c evaluation.ConfidenceLevel) evaluation.ResourceCheck {
	r.Verdict = d
	r.Confidence = c
	return r
}

func wrapInPointers(findings []evaluation.Finding) []*evaluation.Finding {
	if len(findings) == 0 {
		return nil
	}
	evaluatedFindings := make([]*evaluation.Finding, len(findings))
	for i := range findings {
		evaluatedFindings[i] = &findings[i]
	}
	return evaluatedFindings
}
