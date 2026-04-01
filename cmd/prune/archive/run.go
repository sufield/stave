package archive

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

// config defines the resolved parameters for a snapshot archive operation.
type config struct {
	ObservationsDir string
	ArchiveDir      string
	OlderThan       time.Duration
	RetentionTier   string
	Now             time.Time
	KeepMin         int
	DryRun          bool
	Force           bool
	Quiet           bool
	Format          appcontracts.OutputFormat
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

// runner orchestrates the snapshot archiving process.
// It holds the calculated plan between BuildPlan and Apply phases.
type runner struct {
	NewSnapshotRepo compose.SnapshotRepoFactory
	cfg             config
	plan            *executionPlan
}

// Run executes the full archiving workflow via the appeval.RunCleanup lifecycle.
func (r *runner) Run(ctx context.Context, cfg config) error {
	obsDir, archiveDir, err := resolveArchivePaths(cfg.ObservationsDir, cfg.ArchiveDir)
	if err != nil {
		return err
	}
	if cfg.KeepMin < 0 {
		return &ui.UserError{Err: fmt.Errorf("invalid --keep-min %d: must be >= 0", cfg.KeepMin)}
	}

	cfg.ObservationsDir = obsDir
	cfg.ArchiveDir = archiveDir
	cfg.DryRun = cfg.DryRun || !cfg.Force
	r.cfg = cfg

	return appeval.RunCleanup(ctx, r)
}

// Render outputs the plan to the user in the requested format.
func (r *runner) Render(_ context.Context, _ appeval.CleanupPlan) error {
	return report.RenderSnapshotCleanupExecutionPlan(r.cfg.Stdout, report.SnapshotCleanupRenderInput{
		Format:         r.cfg.Format,
		Output:         r.plan.output,
		OutputKind:     "archive",
		ActionLabel:    "archive",
		SummaryPrefix:  "Archive",
		Action:         pruner.ActionMove,
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

// --- Helpers ---

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
