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
//
// The config carries no "apply", "force", or archive-destination
// fields: the plan command is read-only by design. External tools
// consume the rendered output and execute the recommended actions
// themselves.
type PlanConfig struct {
	// Pre-loaded data.
	Files       []appcontracts.SnapshotFile
	Tiers       map[string]retention.Tier
	TierRules   []retention.Rule
	DefaultTier string

	// Resolved parameters.
	Now              time.Time
	ObservationsRoot string
	Format           appcontracts.OutputFormat
	Quiet            bool
	Stdout           io.Writer
}

// PlanRunner orchestrates the recursive inspection and renders the
// resulting plan. It performs no filesystem mutation.
type PlanRunner struct{}

// NewPlanRunner creates a new plan runner.
func NewPlanRunner() *PlanRunner {
	return &PlanRunner{}
}

// Run executes the multi-tier planning workflow.
func (r *PlanRunner) Run(cfg PlanConfig) error {
	p, err := buildPlan(planBuildParams{
		Now:         cfg.Now,
		ObsRoot:     cfg.ObservationsRoot,
		DefaultTier: cfg.DefaultTier,
		TierRules:   cfg.TierRules,
		Tiers:       cfg.Tiers,
		Files:       cfg.Files,
	})
	if err != nil {
		return err
	}

	return writePlanOutput(cfg, p)
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
