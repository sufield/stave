package cleanup

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/adapters/pruner"
	"github.com/sufield/stave/internal/adapters/pruner/report"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// --- Config ---

// config defines the resolved parameters for a snapshot prune operation.
type config struct {
	ObservationsDir string
	OlderThan       time.Duration
	RetentionTier   string
	Now             time.Time
	KeepMin         int
	DryRun          bool
	Force           bool
	Quiet           bool
	Format          appcontracts.OutputFormat
	Stdout          io.Writer
	Runtime         *ui.Runtime
}

// --- Runner ---

// executionPlan holds the calculated state of what will be pruned.
type executionPlan struct {
	allFiles       []appcontracts.SnapshotFile
	candidateFiles []appcontracts.SnapshotFile
	output         report.PruneOutput
}

// runner orchestrates the identification and removal of stale snapshot files.
// It implements appeval.CleanupOrchestrator directly.
type runner struct {
	NewSnapshotRepo compose.SnapshotRepoFactory
	cfg             config
	plan            *executionPlan
}

// Run executes the full pruning workflow via the appeval.RunCleanup lifecycle.
func (r *runner) Run(ctx context.Context, cfg config) error {
	obsDir := fsutil.CleanUserPath(cfg.ObservationsDir)
	if obsDir == "" {
		return &ui.UserError{Err: fmt.Errorf("--observations cannot be empty")}
	}
	if cfg.KeepMin < 0 {
		return &ui.UserError{Err: fmt.Errorf("invalid --keep-min %d: must be >= 0", cfg.KeepMin)}
	}

	cfg.ObservationsDir = obsDir
	cfg.DryRun = cfg.DryRun || !cfg.Force
	r.cfg = cfg

	done := cfg.Runtime.BeginProgress("prune stale snapshots")
	defer done()

	return appeval.RunCleanup(ctx, r)
}

// Render outputs the plan to the user in the requested format.
func (r *runner) Render(_ context.Context, _ appeval.CleanupPlan) error {
	return report.RenderSnapshotCleanupExecutionPlan(r.cfg.Stdout, report.SnapshotCleanupRenderInput{
		Format:         r.cfg.Format,
		Output:         r.plan.output,
		OutputKind:     "prune",
		ActionLabel:    "prune",
		SummaryPrefix:  "Prune",
		Action:         pruner.ActionDelete,
		DryRun:         r.cfg.DryRun,
		AllFiles:       r.plan.allFiles,
		CandidateFiles: r.plan.candidateFiles,
		OlderThan:      r.cfg.OlderThan,
		KeepMin:        r.cfg.KeepMin,
		Tier:           r.cfg.RetentionTier,
		Now:            r.cfg.Now,
		Quiet:          r.cfg.Quiet,
	})
}
