package cleanup

import (
	"context"
	"fmt"
	"io"
	"time"

	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

// --- Config ---

// Config defines the resolved parameters for a snapshot prune operation.
type Config struct {
	ObservationsDir string
	OlderThan       time.Duration
	RetentionTier   string
	Now             time.Time
	KeepMin         int
	DryRun          bool
	Force           bool
	Quiet           bool
	Format          ui.OutputFormat
	Stdout          io.Writer
}

// --- Runner ---

// executionPlan holds the calculated state of what will be pruned.
type executionPlan struct {
	obsDir         string
	allFiles       []pruner.SnapshotFile
	candidateFiles []pruner.SnapshotFile
	output         pruner.PruneOutput
	dryRun         bool
}

// Runner orchestrates the identification and removal of stale snapshot files.
// It implements appeval.CleanupOrchestrator directly.
type Runner struct {
	cfg  Config
	plan *executionPlan
}

// Run executes the full pruning workflow via the appeval.RunCleanup lifecycle.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	obsDir := fsutil.CleanUserPath(cfg.ObservationsDir)
	if obsDir == "" {
		return fmt.Errorf("--observations cannot be empty")
	}
	if cfg.KeepMin < 0 {
		return fmt.Errorf("invalid --keep-min %d: must be >= 0", cfg.KeepMin)
	}

	cfg.ObservationsDir = obsDir
	cfg.DryRun = cfg.DryRun || !cfg.Force
	r.cfg = cfg

	return appeval.RunCleanup(r)
}

// BuildPlan identifies which snapshots meet the criteria for pruning.
func (r *Runner) BuildPlan() (appeval.CleanupPlan, error) {
	allFiles, err := pruneshared.ListObservationSnapshotFiles(context.Background(), r.cfg.ObservationsDir)
	if err != nil {
		return appeval.CleanupPlan{}, fmt.Errorf("listing snapshots: %w", err)
	}

	candidates := pruneshared.PlanPrune(allFiles, pruner.Criteria{
		Now:       r.cfg.Now,
		OlderThan: r.cfg.OlderThan,
		KeepMin:   r.cfg.KeepMin,
	})

	out := pruner.BuildPruneOutput(pruner.CleanupInput{
		Now:             r.cfg.Now,
		Action:          pruner.ActionDelete,
		DryRun:          r.cfg.DryRun,
		ObservationsDir: r.cfg.ObservationsDir,
		Tier:            r.cfg.RetentionTier,
		OlderThan:       r.cfg.OlderThan,
		KeepMin:         r.cfg.KeepMin,
		AllFiles:        allFiles,
		CandidateFiles:  candidates,
	})

	r.plan = &executionPlan{
		obsDir:         r.cfg.ObservationsDir,
		allFiles:       allFiles,
		candidateFiles: candidates,
		output:         out,
		dryRun:         r.cfg.DryRun,
	}

	return appeval.CleanupPlan{
		CandidateCount: len(candidates),
		DryRun:         r.cfg.DryRun,
	}, nil
}

// Render outputs the plan to the user in the requested format.
func (r *Runner) Render(_ appeval.CleanupPlan) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(r.cfg.Stdout, pruner.SnapshotCleanupRenderInput{
		Format:         r.cfg.Format,
		Output:         r.plan.output,
		OutputKind:     "prune",
		ActionLabel:    "prune",
		SummaryPrefix:  "Prune",
		Action:         pruner.ActionDelete,
		DryRun:         r.plan.dryRun,
		AllFiles:       r.plan.allFiles,
		CandidateFiles: r.plan.candidateFiles,
		OlderThan:      r.cfg.OlderThan,
		KeepMin:        r.cfg.KeepMin,
		Tier:           r.cfg.RetentionTier,
		Now:            r.cfg.Now,
		Quiet:          r.cfg.Quiet,
	})
}

// Apply executes the file deletions.
func (r *Runner) Apply(_ appeval.CleanupPlan) error {
	deletion, err := pruner.ApplyDelete(pruner.DeleteInput{
		ObservationsDir: r.plan.obsDir,
		Files:           toDeleteFiles(r.plan.candidateFiles),
	})
	if err != nil {
		return fmt.Errorf("deleting snapshots: %w", err)
	}

	if !r.cfg.Quiet && !r.cfg.Format.IsJSON() {
		fmt.Fprintf(r.cfg.Stdout, "Deleted %d snapshot(s).\n", deletion.Deleted)
	}
	return nil
}

// --- Helpers ---

func toDeleteFiles(in []pruner.SnapshotFile) []pruner.DeleteFile {
	out := make([]pruner.DeleteFile, 0, len(in))
	for _, sf := range in {
		out = append(out, pruner.DeleteFile{Path: sf.Path})
	}
	return out
}
