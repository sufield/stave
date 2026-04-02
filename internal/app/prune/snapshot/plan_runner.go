package snapshot

import (
	"fmt"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/retention"
	snapshotdomain "github.com/sufield/stave/internal/core/snapplan"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// PlanConfig defines the resolved parameters for multi-tier snapshot retention.
type PlanConfig struct {
	// Pre-loaded data.
	Files       []appcontracts.SnapshotFile
	Tiers       map[string]retention.Tier
	TierRules   []retention.Rule
	DefaultTier string

	// Resolved parameters.
	Now              time.Time
	ObservationsRoot string
	ArchiveDir       string
	Apply            bool
	Force            bool
	AllowSymlink     bool
	Format           appcontracts.OutputFormat
	Quiet            bool
	Stdout           io.Writer
}

// PlanRunner orchestrates the recursive inspection and lifecycle execution.
type PlanRunner struct {
	ApplyFn PlanApplyFunc
}

// NewPlanRunner creates a new plan runner with the given apply function.
func NewPlanRunner(applyFn PlanApplyFunc) *PlanRunner {
	return &PlanRunner{ApplyFn: applyFn}
}

// Run executes the multi-tier planning workflow.
func (r *PlanRunner) Run(cfg PlanConfig) error {
	p, err := buildPlan(planBuildParams{
		Now:         cfg.Now,
		ObsRoot:     cfg.ObservationsRoot,
		ArchiveDir:  cfg.ArchiveDir,
		DefaultTier: cfg.DefaultTier,
		TierRules:   cfg.TierRules,
		Tiers:       cfg.Tiers,
		Files:       cfg.Files,
		Apply:       cfg.Apply,
		Force:       cfg.Force,
	})
	if err != nil {
		return err
	}

	if err := writePlanOutput(cfg, p); err != nil {
		return err
	}
	if p.Applied {
		if err := r.ApplyFn(ApplyParams{
			Entries:         toPlanEntries(p.Files),
			ObservationsDir: cfg.ObservationsRoot,
			ArchiveDir:      cfg.ArchiveDir,
			AllowSymlink:    cfg.AllowSymlink,
		}); err != nil {
			return fmt.Errorf("applying snapshot lifecycle plan: %w", err)
		}
	}
	return nil
}

func writePlanOutput(cfg PlanConfig, p *snapshotdomain.PlanOutput) error {
	if cfg.Quiet {
		return nil
	}
	w := cfg.Stdout
	if cfg.Format.IsJSON() {
		if err := jsonutil.WriteIndented(w, p); err != nil {
			return fmt.Errorf("write plan output: %w", err)
		}
		return nil
	}
	if err := snapshotdomain.RenderPlanText(w, p); err != nil {
		return fmt.Errorf("write plan output: %w", err)
	}
	return nil
}
