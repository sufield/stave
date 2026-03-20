package snapshot

import (
	"context"
	"fmt"
	"io"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
	snapshotdomain "github.com/sufield/stave/pkg/alpha/domain/snapshot"
)

// PlanConfig defines the resolved parameters for multi-tier snapshot retention.
type PlanConfig struct {
	// Pre-loaded data.
	Files       []appcontracts.SnapshotFile
	Tiers       map[string]retention.TierConfig
	TierRules   []retention.MappingRule
	DefaultTier string

	// Resolved parameters.
	Now              time.Time
	ObservationsRoot string
	ArchiveDir       string
	Apply            bool
	Force            bool
	AllowSymlink     bool
	Format           ui.OutputFormat
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
func (r *PlanRunner) Run(_ context.Context, cfg PlanConfig) error {
	p := buildPlan(planBuildParams{
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

	if err := writePlanOutput(cfg, p); err != nil {
		return err
	}
	if p.Applied {
		return applyPlan(r.ApplyFn, p, cfg.ObservationsRoot, cfg.ArchiveDir, cfg.AllowSymlink)
	}
	return nil
}

func writePlanOutput(cfg PlanConfig, p snapshotdomain.PlanOutput) error {
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
