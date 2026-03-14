package snapshot

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
)

// QualityConfig defines the resolved parameters for a quality assessment.
type QualityConfig struct {
	ObservationsDir   string
	MinSnapshots      int
	MaxStaleness      time.Duration
	MaxGap            time.Duration
	RequiredResources []string
	Strict            bool
	Now               time.Time
	Format            ui.OutputFormat
	Quiet             bool
	Stdout            io.Writer
}

// QualityRunner orchestrates the evaluation and reporting of snapshot readiness.
type QualityRunner struct{}

// Run executes the quality assessment workflow.
func (r *QualityRunner) Run(ctx context.Context, cfg QualityConfig) error {
	snapshots, err := compose.LoadSnapshots(ctx, cfg.ObservationsDir)
	if err != nil {
		return fmt.Errorf("loading snapshots from %q: %w", cfg.ObservationsDir, err)
	}

	report := assessQuality(qualityParams{
		Snapshots:         snapshots,
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
