package engine

import (
	"log/slog"
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
)

// strategyDeps abstracts the Runner capabilities that strategies need,
// decoupling them from the concrete Runner type.
type strategyDeps interface {
	maxUnsafeDurationFor(ctl *policy.ControlDefinition) time.Duration
	maxGapThreshold() time.Duration
	confidenceCalculator() evaluation.ConfidenceCalculator
	logger() *slog.Logger
	predicateParser() policy.PredicateParser
}

// strategy defines how different control types analyze a timeline.
type strategy interface {
	Evaluate(t *asset.Timeline, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding)
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
func (r *Runner) strategyFor(ctl *policy.ControlDefinition) strategy {
	switch ctl.Type {
	case policy.TypeUnsafeState:
		return &unsafeStateStrategy{deps: r, ctl: ctl}
	case policy.TypeUnsafeDuration:
		return &unsafeDurationStrategy{deps: r, ctl: ctl}
	case policy.TypeUnsafeRecurrence:
		return &unsafeRecurrenceStrategy{deps: r, ctl: ctl}
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

func (s *unsafeStateStrategy) Evaluate(t *asset.Timeline, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation := newControlRow(s.ctl, t)
	maxUnsafe := s.deps.maxUnsafeDurationFor(s.ctl)

	if t.CurrentlySafe() {
		return finalizeRow(observation, evaluation.VerdictPass, evaluation.ConfidenceHigh), nil
	}

	if t.MissingUnsafeTimestamps() {
		observation.MarkInconclusive("missing timestamps")
		return observation, nil
	}

	exceeds, threshErr := t.ExceedsUnsafeThreshold(now, maxUnsafe)
	if threshErr != nil {
		s.deps.logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID, "error", threshErr)
		observation.MarkInconclusive("threshold check error")
		return observation, nil
	}
	if exceeds {
		observation.TemporalRisk = t.FormatUnsafeSummary(maxUnsafe, now)
		finding := CreateDurationFinding(DurationFindingInput{
			Timeline:        t,
			Control:         s.ctl,
			Threshold:       maxUnsafe,
			Now:             now,
			Identities:      ids.At(t.LastSeenUnsafeAt()),
			PredicateParser: s.deps.predicateParser(),
		})
		return finalizeRow(observation, evaluation.VerdictViolation, evaluation.ConfidenceHigh), []*evaluation.Finding{finding}
	}

	return finalizeRow(observation, evaluation.VerdictPass, evaluation.ConfidenceHigh), nil
}

type unsafeDurationStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeDurationStrategy) Evaluate(t *asset.Timeline, now time.Time, ids IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation := newControlRow(s.ctl, t)
	maxUnsafe := s.deps.maxUnsafeDurationFor(s.ctl)

	// 1. Violation Check (Always takes precedence)
	exceeds, threshErr := t.ExceedsUnsafeThreshold(now, maxUnsafe)
	if threshErr != nil {
		s.deps.logger().Warn("unsafe threshold check failed", "control", s.ctl.ID, "asset", t.ID, "error", threshErr)
		observation.MarkInconclusive("threshold check error")
		return observation, nil
	}
	if exceeds {
		observation.TemporalRisk = t.FormatUnsafeSummary(maxUnsafe, now)
		finding := CreateDurationFinding(DurationFindingInput{
			Timeline:        t,
			Control:         s.ctl,
			Threshold:       maxUnsafe,
			Now:             now,
			Identities:      ids.At(t.LastSeenUnsafeAt()),
			PredicateParser: s.deps.predicateParser(),
		})
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
		return finalizeRow(observation, evaluation.VerdictViolation, confidence), []*evaluation.Finding{finding}
	}

	// 2. Coverage Check (Is the data sufficient to say it's a PASS?)
	coverage := CoverageValidator{
		MinRequiredSpan: maxUnsafe,
		MaxAllowedGap:   s.deps.maxGapThreshold(),
	}
	if reason, ok := coverage.IsSufficient(t); !ok {
		observation.MarkInconclusive(reason)
		return observation, nil
	}

	// 3. Adequate coverage and no violation => PASS
	confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), maxUnsafe)
	return finalizeRow(observation, evaluation.VerdictPass, confidence), nil
}

// --- Recurrence Strategy ---

type unsafeRecurrenceStrategy struct {
	deps strategyDeps
	ctl  *policy.ControlDefinition
}

func (s *unsafeRecurrenceStrategy) Evaluate(t *asset.Timeline, now time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation := newControlRow(s.ctl, t)
	p := s.ctl.RecurrencePolicy()

	if !p.Enabled() {
		observation.Reason = "missing recurrence parameters"
		return finalizeRow(observation, evaluation.VerdictPass, evaluation.ConfidenceHigh), nil
	}

	// 1. Violation Check
	if findings := EvaluateRecurrenceForControl(t, s.ctl, now); len(findings) > 0 {
		confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), p.WindowDuration())
		return finalizeRow(observation, evaluation.VerdictViolation, confidence), findings
	}

	// 2. Coverage Check
	coverage := CoverageValidator{MinRequiredSpan: p.WindowDuration()}
	if reason, ok := coverage.IsSufficient(t); !ok {
		observation.MarkInconclusive(reason)
		return observation, nil
	}

	confidence := s.deps.confidenceCalculator().Derive(t.Stats().MaxGap(), p.WindowDuration())
	return finalizeRow(observation, evaluation.VerdictPass, confidence), nil
}

// --- Specialized Strategies ---

type prefixExposureStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *prefixExposureStrategy) Evaluate(t *asset.Timeline, _ time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation, findings := EvaluatePrefixExposureForRow(t, s.ctl)
	return observation, wrapInPointers(findings)
}

type unsupportedStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *unsupportedStrategy) Evaluate(t *asset.Timeline, _ time.Time, _ IdentityIndex) (evaluation.ResourceCheck, []*evaluation.Finding) {
	observation := newControlRow(s.ctl, t)
	observation.Reason = "type not evaluatable: " + s.ctl.Type.String()
	return finalizeRow(observation, evaluation.VerdictSkipped, evaluation.ConfidenceHigh), nil
}

// --- Internal Helpers ---

func newControlRow(ctl *policy.ControlDefinition, t *asset.Timeline) evaluation.ResourceCheck {
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
