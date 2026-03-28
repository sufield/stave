package upcoming

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/core/kernel"
)

// EvalConfig holds domain computation inputs for upcoming risk analysis.
type EvalConfig struct {
	Controls          []policy.ControlDefinition
	Snapshots         []asset.Snapshot
	MaxUnsafeDuration time.Duration
	DueSoon           time.Duration
	Now               time.Time
	Filter            risk.ThresholdFilter
	Sanitizer         kernel.Sanitizer
	PredicateParser   func(any) (*policy.UnsafePredicate, error)
}

// OutputMetadata holds presentation-only fields for the report envelope.
// These values are echoed in the JSON output but not used for computation.
type OutputMetadata struct {
	ControlsDir          string
	ObservationsDir      string
	MaxUnsafeDurationRaw string
	DueSoonRaw           string
}

// Runner orchestrates the risk analysis and timeline projection.
type Runner struct{}

// Run computes upcoming action items and returns the assembled output.
func (r *Runner) Run(cfg EvalConfig, meta OutputMetadata) (UpcomingReport, error) {
	riskItems := risk.ComputeItems(risk.ThresholdRequest{
		Controls:                cfg.Controls,
		Snapshots:               cfg.Snapshots,
		GlobalMaxUnsafeDuration: cfg.MaxUnsafeDuration,
		Now:                     cfg.Now,
		PredicateParser:         cfg.PredicateParser,
	})
	riskItems = riskItems.Filter(cfg.Filter)

	items := mapRiskItems(riskItems)
	if cfg.Sanitizer != nil {
		items = sanitizeItems(cfg.Sanitizer, items)
	}
	summary := summarizeUpcoming(items, cfg.DueSoon)

	output := UpcomingReport{
		GeneratedAt:       cfg.Now,
		ControlsDir:       meta.ControlsDir,
		Observations:      meta.ObservationsDir,
		MaxUnsafeDuration: meta.MaxUnsafeDurationRaw,
		DueSoon:           meta.DueSoonRaw,
		UpcomingSummary:   summary,
		Items:             items,
	}
	return output, nil
}
