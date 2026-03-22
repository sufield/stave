package archive

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	"github.com/sufield/stave/internal/adapters/pruner/report"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/retention"
)

// --- Config ---

// Config defines the resolved parameters for a snapshot archive operation.
type Config struct {
	ObservationsDir string
	ArchiveDir      string
	OlderThan       time.Duration
	RetentionTier   string
	Now             time.Time
	KeepMin         int
	DryRun          bool
	Force           bool
	Quiet           bool
	Format          ui.OutputFormat
	AllowSymlink    bool
	Stdout          io.Writer
}

// --- Runner ---

// executionPlan holds the calculated state of what will be archived.
type executionPlan struct {
	obsDir         string
	archiveDir     string
	allFiles       []appcontracts.SnapshotFile
	candidateFiles []appcontracts.SnapshotFile
	output         report.ArchiveOutput
	dryRun         bool
}

// Runner orchestrates the snapshot archiving process.
// It holds the calculated plan between BuildPlan and Apply phases.
type Runner struct {
	Provider *compose.Provider
	cfg      Config
	plan     *executionPlan
}

// Run executes the full archiving workflow via the appeval.RunCleanup lifecycle.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	obsDir, archiveDir, err := resolveArchivePaths(cfg.ObservationsDir, cfg.ArchiveDir)
	if err != nil {
		return err
	}
	if cfg.KeepMin < 0 {
		return fmt.Errorf("invalid --keep-min %d: must be >= 0", cfg.KeepMin)
	}

	cfg.ObservationsDir = obsDir
	cfg.ArchiveDir = archiveDir
	cfg.DryRun = cfg.DryRun || !cfg.Force
	r.cfg = cfg

	return appeval.RunCleanup(ctx, r)
}

// BuildPlan identifies which snapshots meet the criteria for archiving.
func (r *Runner) BuildPlan(ctx context.Context) (appeval.CleanupPlan, error) {
	allFiles, err := pruneretention.ListObservationSnapshotFiles(ctx, r.Provider, r.cfg.ObservationsDir)
	if err != nil {
		return appeval.CleanupPlan{}, fmt.Errorf("listing snapshots: %w", err)
	}

	candidates := pruneretention.PlanPrune(allFiles, retention.Criteria{
		Now:       r.cfg.Now,
		OlderThan: r.cfg.OlderThan,
		KeepMin:   r.cfg.KeepMin,
	})

	out := report.BuildArchiveOutput(report.ArchiveOutputInput{
		CleanupInput: report.CleanupInput{
			Now:             r.cfg.Now,
			Action:          report.ActionMove,
			DryRun:          r.cfg.DryRun,
			ObservationsDir: r.cfg.ObservationsDir,
			Tier:            r.cfg.RetentionTier,
			OlderThan:       r.cfg.OlderThan,
			KeepMin:         r.cfg.KeepMin,
			AllFiles:        allFiles,
			CandidateFiles:  candidates,
		},
		ArchiveDir: r.cfg.ArchiveDir,
	})

	r.plan = &executionPlan{
		obsDir:         r.cfg.ObservationsDir,
		archiveDir:     r.cfg.ArchiveDir,
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
func (r *Runner) Render(_ context.Context, _ appeval.CleanupPlan) error {
	return report.RenderSnapshotCleanupExecutionPlan(r.cfg.Stdout, report.SnapshotCleanupRenderInput{
		Format:         r.cfg.Format,
		Output:         r.plan.output,
		OutputKind:     "archive",
		ActionLabel:    "archive",
		SummaryPrefix:  "Archive",
		Action:         report.ActionMove,
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

// Apply executes the file moves.
func (r *Runner) Apply(_ context.Context, _ appeval.CleanupPlan) error {
	_, err := fsops.ApplyArchive(fsops.ArchiveInput{
		ArchiveDir: r.plan.archiveDir,
		Moves:      r.toArchiveMoves(),
		Options: fsops.MoveOptions{
			Overwrite:    r.cfg.Force,
			AllowSymlink: r.cfg.AllowSymlink,
		},
	})
	if err != nil {
		return fmt.Errorf("archiving snapshots: %w", err)
	}

	if !r.cfg.Quiet && !r.cfg.Format.IsJSON() {
		fmt.Fprintf(r.cfg.Stdout, "Archived %d snapshot(s) to %s.\n",
			len(r.plan.candidateFiles), r.plan.archiveDir)
	}
	return nil
}

// --- Helpers ---

func (r *Runner) toArchiveMoves() []fsops.ArchiveMove {
	moves := make([]fsops.ArchiveMove, 0, len(r.plan.candidateFiles))
	for _, sf := range r.plan.candidateFiles {
		moves = append(moves, fsops.ArchiveMove{
			Src: sf.Path,
			Dst: filepath.Join(r.plan.archiveDir, sf.Name),
		})
	}
	return moves
}

func resolveArchivePaths(observationsPath, archivePath string) (string, string, error) {
	obsDir := fsutil.CleanUserPath(observationsPath)
	if obsDir == "" {
		return "", "", fmt.Errorf("--observations cannot be empty")
	}
	destArchiveDir := fsutil.CleanUserPath(archivePath)
	if destArchiveDir == "" {
		return "", "", fmt.Errorf("--archive-dir cannot be empty")
	}
	return obsDir, destArchiveDir, nil
}
