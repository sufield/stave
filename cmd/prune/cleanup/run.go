package cleanup

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	"github.com/sufield/stave/internal/adapters/pruner/report"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
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
	allFiles       []appcontracts.SnapshotFile
	candidateFiles []appcontracts.SnapshotFile
	output         report.PruneOutput
}

// Runner orchestrates the identification and removal of stale snapshot files.
// It implements appeval.CleanupOrchestrator directly.
type Runner struct {
	NewSnapshotRepo compose.SnapshotRepoFactory
	cfg             Config
	plan            *executionPlan
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

	return appeval.RunCleanup(ctx, r)
}

// BuildPlan identifies which snapshots meet the criteria for pruning.
func (r *Runner) BuildPlan(ctx context.Context) (appeval.CleanupPlan, error) {
	allFiles, err := pruneretention.ListObservationSnapshotFiles(ctx, r.NewSnapshotRepo, r.cfg.ObservationsDir)
	if err != nil {
		return appeval.CleanupPlan{}, fmt.Errorf("listing snapshots: %w", err)
	}

	candidates := pruneretention.PlanPrune(allFiles, retention.Criteria{
		Now:       r.cfg.Now,
		OlderThan: r.cfg.OlderThan,
		KeepMin:   r.cfg.KeepMin,
	})

	pruneFiles := make([]report.CleanupFile, 0, len(candidates))
	for _, sf := range candidates {
		pruneFiles = append(pruneFiles, report.CleanupFile{
			Name:       sf.Name,
			CapturedAt: sf.CapturedAt.UTC(),
		})
	}
	out := report.PruneOutput{
		CleanupOutput: report.CleanupOutput{
			SchemaVersion:   kernel.SchemaSnapshotPrune,
			Kind:            kernel.KindSnapshotPrune,
			CheckedAt:       r.cfg.Now.UTC(),
			Mode:            report.ActionDelete.ModeString(r.cfg.DryRun),
			Applied:         !r.cfg.DryRun && len(candidates) > 0,
			ObservationsDir: r.cfg.ObservationsDir,
			RetentionTier:   r.cfg.RetentionTier,
			OlderThan:       timeutil.FormatDuration(r.cfg.OlderThan),
			KeepMin:         r.cfg.KeepMin,
			TotalSnapshots:  len(allFiles),
			Candidates:      len(candidates),
			Files:           pruneFiles,
		},
	}

	r.plan = &executionPlan{
		allFiles:       allFiles,
		candidateFiles: candidates,
		output:         out,
	}

	return appeval.CleanupPlan{
		CandidateCount: len(candidates),
		DryRun:         r.cfg.DryRun,
	}, nil
}

// Render outputs the plan to the user in the requested format.
func (r *Runner) Render(_ context.Context, _ appeval.CleanupPlan) error {
	return report.RenderSnapshotCleanupExecutionPlan(r.cfg.Stdout, report.SnapshotCleanupRenderInput{
		Format:         r.cfg.Format,
		Output:         r.plan.output,
		OutputKind:     "prune",
		ActionLabel:    "prune",
		SummaryPrefix:  "Prune",
		Action:         report.ActionDelete,
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

// Apply executes the file deletions.
func (r *Runner) Apply(_ context.Context, _ appeval.CleanupPlan) error {
	deletion, err := fsops.ApplyDelete(fsops.DeleteInput{
		ObservationsDir: r.cfg.ObservationsDir,
		Files:           r.toDeleteFiles(),
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

func (r *Runner) toDeleteFiles() []fsops.DeleteFile {
	out := make([]fsops.DeleteFile, 0, len(r.plan.candidateFiles))
	for _, sf := range r.plan.candidateFiles {
		out = append(out, fsops.DeleteFile{Path: sf.Path})
	}
	return out
}
