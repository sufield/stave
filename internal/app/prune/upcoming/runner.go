package upcoming

import (
	"context"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/risk"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// Config defines the resolved parameters for upcoming action analysis.
type Config struct {
	// Pre-loaded data.
	Controls  []policy.ControlDefinition
	Snapshots []asset.Snapshot

	// Resolved parameters.
	MaxUnsafe       time.Duration
	MaxUnsafeRaw    string
	DueSoon         time.Duration
	DueSoonRaw      string
	Now             time.Time
	Filter          risk.FilterCriteria
	Sanitizer       kernel.Sanitizer
	PredicateParser func(any) (*policy.UnsafePredicate, error)

	// Output metadata (echoed in JSON output).
	ControlsDir     string
	ObservationsDir string
}

// Runner orchestrates the risk analysis and timeline projection.
type Runner struct{}

// NewRunner creates a new upcoming analysis runner.
func NewRunner() *Runner {
	return &Runner{}
}

// Run computes upcoming action items and returns the assembled output.
func (r *Runner) Run(_ context.Context, cfg Config) (Output, error) {
	riskItems := risk.ComputeItems(risk.Request{
		Controls:        cfg.Controls,
		Snapshots:       cfg.Snapshots,
		GlobalMaxUnsafe: cfg.MaxUnsafe,
		Now:             cfg.Now,
		PredicateParser: cfg.PredicateParser,
	})
	riskItems = riskItems.Filter(cfg.Filter)

	// Map domain items to display DTOs
	items := mapRiskItems(riskItems)
	if cfg.Sanitizer != nil {
		items = sanitizeItems(cfg.Sanitizer, items)
	}
	summary := summarizeUpcoming(items, cfg.DueSoon)

	// Assemble final output
	output := Output{
		GeneratedAt:  cfg.Now,
		ControlsDir:  cfg.ControlsDir,
		Observations: cfg.ObservationsDir,
		MaxUnsafe:    cfg.MaxUnsafeRaw,
		DueSoon:      cfg.DueSoonRaw,
		Summary:      summary,
		Items:        items,
	}
	return output, nil
}
