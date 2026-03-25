package snapshot

import (
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
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
	Format            appcontracts.OutputFormat
	Quiet             bool
	Stdout            io.Writer
}

// QualityRunner orchestrates the evaluation and reporting of snapshot readiness.
type QualityRunner struct{}

// Run executes the quality assessment workflow.
func (r *QualityRunner) Run(cfg QualityConfig) error {
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
	if !report.Passed {
		return appcontracts.ErrViolationsFound
	}
	return nil
}
