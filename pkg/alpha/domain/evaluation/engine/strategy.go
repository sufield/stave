package engine

import (
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// strategy defines how different control types analyze a timeline.
type strategy interface {
	Evaluate(t *asset.Timeline, now time.Time) (evaluation.Row, []*evaluation.Finding)
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
		return &unsafeStateStrategy{runner: r, ctl: ctl}
	case policy.TypeUnsafeDuration:
		return &unsafeDurationStrategy{runner: r, ctl: ctl}
	case policy.TypeUnsafeRecurrence:
		return &unsafeRecurrenceStrategy{runner: r, ctl: ctl}
	case policy.TypePrefixExposure:
		return &prefixExposureStrategy{ctl: ctl}
	default:
		return &unsupportedStrategy{ctl: ctl}
	}
}

// --- Duration & State Strategies ---

type unsafeStateStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s *unsafeStateStrategy) Evaluate(t *asset.Timeline, now time.Time) (evaluation.Row, []*evaluation.Finding) {
	row := newControlRow(s.ctl, t)
	maxUnsafe := s.runner.getMaxUnsafeForControl(s.ctl)

	if t.CurrentlySafe() {
		return finalizeRow(row, evaluation.DecisionPass, evaluation.ConfidenceHigh), nil
	}

	if t.MissingUnsafeTimestamps() {
		row.MarkInconclusive("missing timestamps")
		return row, nil
	}

	if t.ExceedsUnsafeThreshold(now, maxUnsafe) {
		row.WhyNow = t.FormatUnsafeSummary(maxUnsafe, now)
		finding := CreateDurationFinding(DurationFindingInput{
			Timeline:        t,
			Control:         s.ctl,
			Threshold:       maxUnsafe,
			Now:             now,
			Identities:      s.runner.identitiesAt(t.LastSeenUnsafeAt()),
			PredicateParser: s.runner.PredicateParser,
		})
		return finalizeRow(row, evaluation.DecisionViolation, evaluation.ConfidenceHigh), []*evaluation.Finding{finding}
	}

	return finalizeRow(row, evaluation.DecisionPass, evaluation.ConfidenceHigh), nil
}

type unsafeDurationStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s *unsafeDurationStrategy) Evaluate(t *asset.Timeline, now time.Time) (evaluation.Row, []*evaluation.Finding) {
	row := newControlRow(s.ctl, t)
	maxUnsafe := s.runner.getMaxUnsafeForControl(s.ctl)

	// 1. Violation Check (Always takes precedence)
	if t.ExceedsUnsafeThreshold(now, maxUnsafe) {
		row.WhyNow = t.FormatUnsafeSummary(maxUnsafe, now)
		finding := CreateDurationFinding(DurationFindingInput{
			Timeline:        t,
			Control:         s.ctl,
			Threshold:       maxUnsafe,
			Now:             now,
			Identities:      s.runner.identitiesAt(t.LastSeenUnsafeAt()),
			PredicateParser: s.runner.PredicateParser,
		})
		confidence := evaluation.DeriveConfidenceLevel(t.Stats().MaxGap(), maxUnsafe)
		return finalizeRow(row, evaluation.DecisionViolation, confidence), []*evaluation.Finding{finding}
	}

	// 2. Coverage Check (Is the data sufficient to say it's a PASS?)
	coverage := CoverageValidator{
		MinRequiredSpan: maxUnsafe,
		MaxAllowedGap:   s.runner.maxGapThreshold(),
	}
	if reason, ok := coverage.IsSufficient(t); !ok {
		row.MarkInconclusive(reason)
		return row, nil
	}

	// 3. Adequate coverage and no violation => PASS
	confidence := evaluation.DeriveConfidenceLevel(t.Stats().MaxGap(), maxUnsafe)
	return finalizeRow(row, evaluation.DecisionPass, confidence), nil
}

// --- Recurrence Strategy ---

type unsafeRecurrenceStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s *unsafeRecurrenceStrategy) Evaluate(t *asset.Timeline, now time.Time) (evaluation.Row, []*evaluation.Finding) {
	row := newControlRow(s.ctl, t)
	p := s.ctl.RecurrencePolicy()

	if !p.Configured() {
		row.Reason = "missing recurrence parameters"
		return finalizeRow(row, evaluation.DecisionPass, evaluation.ConfidenceHigh), nil
	}

	// 1. Violation Check
	if findings := EvaluateRecurrenceForControl(t, s.ctl, now); len(findings) > 0 {
		confidence := evaluation.DeriveConfidenceLevel(t.Stats().MaxGap(), p.WindowDuration())
		return finalizeRow(row, evaluation.DecisionViolation, confidence), findings
	}

	// 2. Coverage Check
	coverage := CoverageValidator{MinRequiredSpan: p.WindowDuration()}
	if reason, ok := coverage.IsSufficient(t); !ok {
		row.MarkInconclusive(reason)
		return row, nil
	}

	confidence := evaluation.DeriveConfidenceLevel(t.Stats().MaxGap(), p.WindowDuration())
	return finalizeRow(row, evaluation.DecisionPass, confidence), nil
}

// --- Specialized Strategies ---

type prefixExposureStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *prefixExposureStrategy) Evaluate(t *asset.Timeline, now time.Time) (evaluation.Row, []*evaluation.Finding) {
	row, findings := EvaluatePrefixExposureForRow(t, s.ctl, now)
	return row, wrapInPointers(findings)
}

type unsupportedStrategy struct {
	ctl *policy.ControlDefinition
}

func (s *unsupportedStrategy) Evaluate(t *asset.Timeline, _ time.Time) (evaluation.Row, []*evaluation.Finding) {
	row := newControlRow(s.ctl, t)
	row.Reason = "type not evaluatable: " + s.ctl.Type.String()
	return finalizeRow(row, evaluation.DecisionSkipped, evaluation.ConfidenceHigh), nil
}

// --- Internal Helpers ---

func newControlRow(ctl *policy.ControlDefinition, t *asset.Timeline) evaluation.Row {
	resType := t.Asset().Type
	return evaluation.Row{
		ControlID:   ctl.ID,
		AssetID:     t.ID,
		AssetType:   resType,
		AssetDomain: resType.Domain(),
	}
}

func finalizeRow(r evaluation.Row, d evaluation.Decision, c evaluation.ConfidenceLevel) evaluation.Row {
	r.Decision = d
	r.Confidence = c
	return r
}

func wrapInPointers(findings []evaluation.Finding) []*evaluation.Finding {
	if len(findings) == 0 {
		return nil
	}
	res := make([]*evaluation.Finding, len(findings))
	for i := range findings {
		res[i] = &findings[i]
	}
	return res
}
