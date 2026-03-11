package engine

import (
	"time"

	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/policy"
)

type controlEvalStrategy interface {
	Evaluate(timeline *asset.Timeline, now time.Time) (evaluation.Row, []evaluation.Finding)
}

// Compile-time interface assertions.
var (
	_ controlEvalStrategy = unsafeStateStrategy{}
	_ controlEvalStrategy = unsafeDurationStrategy{}
	_ controlEvalStrategy = unsafeRecurrenceStrategy{}
	_ controlEvalStrategy = prefixExposureStrategy{}
	_ controlEvalStrategy = unsupportedStrategy{}
)

func (e *Runner) strategyFor(ctl *policy.ControlDefinition) controlEvalStrategy {
	switch ctl.Type {
	case policy.TypeUnsafeState:
		return unsafeStateStrategy{runner: e, ctl: ctl}
	case policy.TypeUnsafeDuration:
		return unsafeDurationStrategy{runner: e, ctl: ctl}
	case policy.TypeUnsafeRecurrence:
		return unsafeRecurrenceStrategy{runner: e, ctl: ctl}
	case policy.TypePrefixExposure:
		return prefixExposureStrategy{ctl: ctl}
	default:
		return unsupportedStrategy{ctl: ctl}
	}
}

type unsafeStateStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s unsafeStateStrategy) Evaluate(timeline *asset.Timeline, now time.Time) (evaluation.Row, []evaluation.Finding) {
	row := newControlRow(s.ctl, timeline)

	if timeline.CurrentlySafe() {
		row.Decision = evaluation.DecisionPass
		row.Confidence = evaluation.ConfidenceHigh
		return row, nil
	}
	if timeline.MissingUnsafeTimestamps() {
		row.MarkInconclusive("missing timestamps")
		return row, nil
	}

	maxUnsafe := s.runner.getMaxUnsafeForControl(s.ctl)
	if timeline.ExceedsUnsafeThreshold(now, maxUnsafe) {
		row.Decision = evaluation.DecisionViolation
		row.Confidence = evaluation.ConfidenceHigh
		row.WhyNow = timeline.FormatUnsafeSummary(maxUnsafe, now)
		return row, []evaluation.Finding{CreateDurationFinding(timeline, s.ctl, maxUnsafe, now)}
	}

	row.Decision = evaluation.DecisionPass
	row.Confidence = evaluation.ConfidenceHigh
	return row, nil
}

type unsafeDurationStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s unsafeDurationStrategy) Evaluate(timeline *asset.Timeline, now time.Time) (evaluation.Row, []evaluation.Finding) {
	row := newControlRow(s.ctl, timeline)
	maxUnsafe := s.runner.getMaxUnsafeForControl(s.ctl)

	// First check for VIOLATION (takes precedence over INCONCLUSIVE).
	if timeline.ExceedsUnsafeThreshold(now, maxUnsafe) {
		row.Decision = evaluation.DecisionViolation
		row.Confidence = evaluation.DeriveConfidenceLevel(timeline.Stats().MaxGap(), maxUnsafe)
		row.WhyNow = timeline.FormatUnsafeSummary(maxUnsafe, now)
		return row, []evaluation.Finding{CreateDurationFinding(timeline, s.ctl, maxUnsafe, now)}
	}

	coverage := CoverageValidator{
		MinRequiredSpan: maxUnsafe,
		MaxAllowedGap:   s.runner.maxGapThreshold(),
	}
	if reason, ok := coverage.IsSufficient(timeline); !ok {
		row.MarkInconclusive(reason)
		return row, nil
	}

	// Adequate coverage and no violation => PASS.
	row.Decision = evaluation.DecisionPass
	row.Confidence = evaluation.DeriveConfidenceLevel(timeline.Stats().MaxGap(), maxUnsafe)
	return row, nil
}

type unsafeRecurrenceStrategy struct {
	runner *Runner
	ctl    *policy.ControlDefinition
}

func (s unsafeRecurrenceStrategy) Evaluate(timeline *asset.Timeline, now time.Time) (evaluation.Row, []evaluation.Finding) {
	row := newControlRow(s.ctl, timeline)
	recurrence := s.ctl.RecurrencePolicy()

	if !recurrence.Configured() {
		row.Decision = evaluation.DecisionPass
		row.Confidence = evaluation.ConfidenceHigh
		row.Reason = "missing recurrence parameters"
		return row, nil
	}

	episodesInWindow := timeline.History().RecurringViolationCount(recurrence.Window(now))
	if episodesInWindow >= recurrence.Limit {
		row.Decision = evaluation.DecisionViolation
		row.Confidence = evaluation.DeriveConfidenceLevel(timeline.Stats().MaxGap(), recurrence.WindowDuration())
		return row, EvaluateRecurrenceForControl(timeline, s.ctl, now)
	}

	coverage := CoverageValidator{
		MinRequiredSpan: recurrence.WindowDuration(),
		// No gap-based inconclusive for recurrence controls.
	}
	if reason, ok := coverage.IsSufficient(timeline); !ok {
		row.MarkInconclusive(reason)
		return row, nil
	}

	row.Decision = evaluation.DecisionPass
	row.Confidence = evaluation.DeriveConfidenceLevel(timeline.Stats().MaxGap(), recurrence.WindowDuration())
	return row, nil
}

type prefixExposureStrategy struct {
	ctl *policy.ControlDefinition
}

func (s prefixExposureStrategy) Evaluate(timeline *asset.Timeline, now time.Time) (evaluation.Row, []evaluation.Finding) {
	return EvaluatePrefixExposureForRow(timeline, s.ctl, now)
}

type unsupportedStrategy struct {
	ctl *policy.ControlDefinition
}

func (s unsupportedStrategy) Evaluate(timeline *asset.Timeline, _ time.Time) (evaluation.Row, []evaluation.Finding) {
	resourceType := timeline.Asset().Type
	return evaluation.Row{
		ControlID:   s.ctl.ID,
		AssetID:     timeline.ID,
		AssetType:   resourceType,
		AssetDomain: resourceType.Domain(),
		Decision:    evaluation.DecisionSkipped,
		Confidence:  evaluation.ConfidenceHigh,
		Reason:      "type not evaluatable: " + s.ctl.Type.String(),
	}, nil
}

func newControlRow(ctl *policy.ControlDefinition, timeline *asset.Timeline) evaluation.Row {
	resourceType := timeline.Asset().Type
	return evaluation.Row{
		ControlID:   ctl.ID,
		AssetID:     timeline.ID,
		AssetType:   resourceType,
		AssetDomain: resourceType.Domain(),
	}
}
