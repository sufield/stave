package snapshot

import (
	"context"
	"io"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
)

// QualityConfig defines the resolved parameters for a quality assessment.
type QualityConfig struct {
	Snapshots         []asset.Snapshot
	Now               time.Time
	MinSnapshots      int
	MaxStaleness      time.Duration
	MaxGap            time.Duration
	RequiredResources []string
	Strict            bool
	Format            ui.OutputFormat
	Quiet             bool
	Stdout            io.Writer
}

// QualityRunner orchestrates the evaluation and reporting of snapshot readiness.
type QualityRunner struct{}

// NewQualityRunner creates a new quality assessment runner.
func NewQualityRunner() *QualityRunner {
	return &QualityRunner{}
}

// Run executes the quality assessment workflow.
func (r *QualityRunner) Run(_ context.Context, cfg QualityConfig) error {
	report := assessQuality(qualityParams{
		Snapshots:         cfg.Snapshots,
		Now:               cfg.Now,
		MinSnapshots:      cfg.MinSnapshots,
		MaxStaleness:      cfg.MaxStaleness,
		MaxGap:            cfg.MaxGap,
		RequiredResources: cfg.RequiredResources,
		Strict:            cfg.Strict,
	})

	if err := writeQualityOutput(cfg.Stdout, cfg.Format, report, cfg.Quiet); err != nil {
		return err
	}
	if !report.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}
