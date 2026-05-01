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
// decoupling them from the concrete Assessor type.
type strategyDeps interface {
	slaThresholdFor(ctl *policy.ControlDefinition) time.Duration
	continuityLimit() time.Duration
	confidenceCalculator() evaluation.ConfidenceCalculator
	logger() *slog.Logger
	predicateParser() policy.PredicateParser
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

// strategyFor returns the appropriate evaluator based on the control type.
// The Assessor version is used by tests; the session version adds the trace span.
func (a *Assessor) strategyFor(ctl *policy.ControlDefinition) strategy {
	return buildStrategy(&sessionDeps{Assessor: a, span: nopSpan{}}, ctl)
}

// strategyFor returns the appropriate evaluator with the active trace span.
func (s *assessmentSession) strategyFor(ctl *policy.ControlDefinition) strategy {
	return buildStrategy(&sessionDeps{Assessor: s.assessor, span: s.activeSpan}, ctl)
}

func buildStrategy(deps strategyDeps, ctl *policy.ControlDefinition) strategy {
	switch ctl.Type {
	case policy.TypeUnsafeState:
		return &unsafeStateStrategy{deps: deps, ctl: ctl}
	case policy.TypeUnsafeDuration:
		return &unsafeDurationStrategy{deps: deps, ctl: ctl}
	case policy.TypeUnsafeRecurrence:
		return &unsafeRecurrenceStrategy{deps: deps, ctl: ctl}
	case policy.TypePrefixExposure:
		return &prefixExposureStrategy{ctl: ctl}
	default:
		return &unsupportedStrategy{ctl: ctl}
	}
}

// --- Duration & State Strategies ---

type unsafeStateStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeStateStrategy) Evaluate(t *asset.ExposureLifecycle, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
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
	if s.ctl.Prepared.HasMaxUnsafeDuration {
		maxUnsafe = s.deps.slaThresholdFor(s.ctl)
	}
	span := s.deps.currentSpan()

	span.RecordStep("predicate_evaluation", map[string]any{
		"currently_unsafe": !t.IsSecure(),
		"exposure_count":   t.History().Count(),
	}, map[string]any{
		"matched": !t.IsSecure(),
	})

	if t.IsSecure() {
		span.RecordStep("verdict_decision", nil, map[string]any{
			"verdict": "PASS",
			"reason":  "predicate not matched — resource is compliant",
		})
		return finalizeRow(observation, evaluation.VerdictPass, evaluation.ConfidenceHigh), nil
	}

	if t.MissingExposureTimestamps() {
		observation.MarkInconclusive("missing timestamps")
		return observation, nil
	}

	exceeds, threshErr := t.ExceedsSLA(now, maxUnsafe)
	if threshErr != nil {
		s.deps.logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID, "error", threshErr)
		observation.MarkInconclusive("threshold check error")
		return observation, nil
	}

	span.RecordStep("threshold_check", map[string]any{
		"threshold_hours":  maxUnsafe.Hours(),
		"last_seen_unsafe": t.LastObservedAt(),
	}, map[string]any{
		"exceeds_threshold": exceeds,
	})

	if exceeds {
		observation.TemporalRisk = t.FormatExposureSummary(maxUnsafe, now)
		finding, durErr := CreateDurationFinding(DurationFindingInput{
			ExposureLifecycle: t,
			Control:           s.ctl,
			Threshold:         maxUnsafe,
			Now:               now,
			Identities:        ids.At(t.LastObservedAt()),
			PredicateParser:   s.deps.predicateParser(),
		})
		// CreateDurationFinding's contract is "(*Finding, error)"
		// with the finding always non-nil. If a future refactor
		// returns nil anyway, we cannot describe the violation —
		// downgrade to INCONCLUSIVE so the assessor's violation
		// count stays consistent with the findings list. The
		// alternative (emit VerdictViolation with empty findings)
		// inflates the violations summary above the visible
		// finding count and makes report totals diverge in a way
		// that's hard to debug from the user-facing output.
		if finding == nil {
			s.deps.logger().Warn("CreateDurationFinding returned nil finding; downgrading verdict to INCONCLUSIVE to keep counts consistent",
				"control", s.ctl.ID, "asset", t.ID)
			observation.MarkInconclusive("violation finding could not be constructed")
			return observation, nil
		}
		findings := []*evaluation.Finding{finding}
		if durErr != nil {
			// Mark the evidence invalid so downstream report
			// renderers can avoid arithmetic on the sentinel
			// duration (-1.0). The verdict still stands —
			// CreateDurationFinding's contract is "the asset is
			// in violation, but I couldn't compute exact dwell"
			// — but evidence-derived numbers are unreliable.
			finding.Evidence.EvidenceInvalid = true
			s.deps.logger().Warn("duration calculation failed; emitting violation with sentinel duration -1.0 and evidence_invalid=true",
				"control", s.ctl.ID, "asset", t.ID, "error", durErr,
				"finding_emitted", true)
		}
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
		return finalizeRow(observation, evaluation.VerdictViolation, confidence), findings
	}

	span.RecordStep("verdict_decision", nil, map[string]any{
		"verdict": "PASS",
		"reason":  "predicate matched but exposure within SLA threshold",
	})
	confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
	return finalizeRow(observation, evaluation.VerdictPass, confidence), nil
}

type unsafeDurationStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeDurationStrategy) Evaluate(t *asset.ExposureLifecycle, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
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
		s.deps.logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID, "error", threshErr)
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
		observation.TemporalRisk = t.FormatExposureSummary(maxUnsafe, now)
		finding, durErr := CreateDurationFinding(DurationFindingInput{
			ExposureLifecycle: t,
			Control:           s.ctl,
			Threshold:         maxUnsafe,
			Now:               now,
			Identities:        ids.At(t.LastObservedAt()),
			PredicateParser:   s.deps.predicateParser(),
		})
		// CreateDurationFinding's contract is "(*Finding, error)"
		// with the finding always non-nil. If a future refactor
		// returns nil anyway, we cannot describe the violation —
		// downgrade to INCONCLUSIVE so the assessor's violation
		// count stays consistent with the findings list. The
		// alternative (emit VerdictViolation with empty findings)
		// inflates the violations summary above the visible
		// finding count and makes report totals diverge in a way
		// that's hard to debug from the user-facing output.
		if finding == nil {
			s.deps.logger().Warn("CreateDurationFinding returned nil finding; downgrading verdict to INCONCLUSIVE to keep counts consistent",
				"control", s.ctl.ID, "asset", t.ID)
			observation.MarkInconclusive("violation finding could not be constructed")
			return observation, nil
		}
		findings := []*evaluation.Finding{finding}
		if durErr != nil {
			// Mark the evidence invalid so downstream report
			// renderers can avoid arithmetic on the sentinel
			// duration (-1.0). The verdict still stands —
			// CreateDurationFinding's contract is "the asset is
			// in violation, but I couldn't compute exact dwell"
			// — but evidence-derived numbers are unreliable.
			finding.Evidence.EvidenceInvalid = true
			s.deps.logger().Warn("duration calculation failed; emitting violation with sentinel duration -1.0 and evidence_invalid=true",
				"control", s.ctl.ID, "asset", t.ID, "error", durErr,
				"finding_emitted", true)
		}
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
		return finalizeRow(observation, evaluation.VerdictViolation, confidence), findings
	}

	// 2. Coverage Check (Is the data sufficient to say it's a PASS?)
	coverage := CoverageValidator{
		MinRequiredSpan: maxUnsafe,
		MaxAllowedGap:   s.deps.continuityLimit(),
	}
	if reason, ok := coverage.IsSufficient(t); !ok {
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
	coverage := CoverageValidator{
		MinRequiredSpan: p.WindowDuration(),
		MaxAllowedGap:   s.deps.continuityLimit(),
	}
	if reason, ok := coverage.IsSufficient(t); !ok {
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
	observation := newControlRow(s.ctl, t)
	observation.Reason = "type not evaluatable: " + s.ctl.Type.String()
	return finalizeRow(observation, evaluation.VerdictSkipped, evaluation.ConfidenceHigh), nil
}

// --- Internal Helpers ---

func newControlRow(ctl *policy.ControlDefinition, t *asset.ExposureLifecycle) evaluation.ResourceCheck {
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
