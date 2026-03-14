package archive

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"time"

	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

// --- Config & Runner ---

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

// Runner orchestrates the movement of stale snapshot files to an archive location.
type Runner struct{}

// Run executes the archiving workflow.
func (r *Runner) Run(ctx context.Context, cfg Config) error {
	obsDir, archiveDir, err := resolveArchivePaths(cfg.ObservationsDir, cfg.ArchiveDir)
	if err != nil {
		return err
	}
	if cfg.KeepMin < 0 {
		return fmt.Errorf("invalid --keep-min %d: must be >= 0", cfg.KeepMin)
	}

	effectiveDryRun := cfg.DryRun || !cfg.Force

	plan, err := r.buildPlan(ctx, cfg, obsDir, archiveDir, effectiveDryRun)
	if err != nil {
		return err
	}

	return appeval.RunCleanup(&archiveOrchestrator{
		cfg:  cfg,
		plan: plan,
	})
}

// --- Orchestrator ---

type archiveOutput = pruner.ArchiveOutput

type archiveExecutionPlan struct {
	pruneshared.CleanupPlan
	overwrite    bool
	allowSymlink bool
	archiveDir   string
	output       archiveOutput
}

type archiveOrchestrator struct {
	cfg  Config
	plan archiveExecutionPlan
}

func (a *archiveOrchestrator) BuildPlan() (appeval.CleanupPlan, error) {
	return appeval.CleanupPlan{
		CandidateCount: len(a.plan.CandidateFiles),
		DryRun:         a.plan.DryRun,
	}, nil
}

func (a *archiveOrchestrator) Render(_ appeval.CleanupPlan) error {
	return renderArchiveExecutionPlan(a.plan, a.cfg.Stdout)
}

func (a *archiveOrchestrator) Apply(_ appeval.CleanupPlan) error {
	if err := applyArchiveExecutionPlan(a.plan); err != nil {
		return err
	}
	if !a.cfg.Quiet && !a.plan.Format.IsJSON() {
		fmt.Fprintf(a.cfg.Stdout, "Archived %d snapshot(s) to %s.\n", len(a.plan.CandidateFiles), a.plan.archiveDir)
	}
	return nil
}

// --- Plan Building ---

func (r *Runner) buildPlan(ctx context.Context, cfg Config, obsDir, archiveDir string, dryRun bool) (archiveExecutionPlan, error) {
	allFiles, err := pruneshared.ListObservationSnapshotFiles(ctx, obsDir)
	if err != nil {
		return archiveExecutionPlan{}, err
	}
	candidateFiles := pruneshared.PlanPrune(allFiles, pruner.Criteria{Now: cfg.Now, OlderThan: cfg.OlderThan, KeepMin: cfg.KeepMin})
	out := pruner.BuildArchiveOutput(pruner.ArchiveOutputInput{
		CleanupInput: pruner.CleanupInput{
			Now:             cfg.Now,
			Action:          pruner.ActionMove,
			DryRun:          dryRun,
			ObservationsDir: obsDir,
			Tier:            cfg.RetentionTier,
			OlderThan:       cfg.OlderThan,
			KeepMin:         cfg.KeepMin,
			AllFiles:        allFiles,
			CandidateFiles:  candidateFiles,
		},
		ArchiveDir: archiveDir,
	})
	return archiveExecutionPlan{
		CleanupPlan: pruneshared.CleanupPlan{
			Now:             cfg.Now,
			Action:          pruner.ActionMove,
			DryRun:          dryRun,
			Quiet:           cfg.Quiet,
			Format:          cfg.Format,
			ObservationsDir: obsDir,
			Tier:            cfg.RetentionTier,
			OlderThan:       cfg.OlderThan,
			KeepMin:         cfg.KeepMin,
			AllFiles:        allFiles,
			CandidateFiles:  candidateFiles,
		},
		overwrite:    cfg.Force,
		allowSymlink: cfg.AllowSymlink,
		archiveDir:   archiveDir,
		output:       out,
	}, nil
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

func renderArchiveExecutionPlan(plan archiveExecutionPlan, out io.Writer) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(out, pruner.SnapshotCleanupRenderInput{
		Format:         plan.Format,
		Output:         plan.output,
		OutputKind:     "archive",
		ActionLabel:    "archive",
		SummaryPrefix:  "Archive",
		Action:         plan.Action,
		DryRun:         plan.DryRun,
		AllFiles:       plan.AllFiles,
		CandidateFiles: plan.CandidateFiles,
		OlderThan:      plan.OlderThan,
		KeepMin:        plan.KeepMin,
		Tier:           plan.Tier,
		Now:            plan.Now,
		Quiet:          plan.Quiet,
	})
}

func applyArchiveExecutionPlan(plan archiveExecutionPlan) error {
	_, err := pruner.ApplyArchive(pruner.ArchiveInput{
		ArchiveDir: plan.archiveDir,
		Moves:      toArchiveMoves(plan.CandidateFiles, plan.archiveDir),
		Options: pruner.MoveOptions{
			Overwrite:    plan.overwrite,
			AllowSymlink: plan.allowSymlink,
		},
	})
	return err
}

func toArchiveMoves(files []pruner.SnapshotFile, archiveDir string) []pruner.ArchiveMove {
	moves := make([]pruner.ArchiveMove, 0, len(files))
	for _, sf := range files {
		moves = append(moves, pruner.ArchiveMove{
			Src: sf.Path,
			Dst: filepath.Join(archiveDir, sf.Name),
		})
	}
	return moves
}

func moveSnapshotFile(src, dst string) error {
	return pruner.MoveSnapshotFile(src, dst, pruner.MoveOptions{})
}
