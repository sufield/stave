package archive

import (
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

var (
	archiveOpts archiveOptions
)

type archiveOptions struct {
	ObservationsDir string
	ArchiveDir      string
	OlderThan       string
	RetentionTier   string
	Now             string
	KeepMin         int
	DryRun          bool
	Format          string
}

type archiveOutput = pruner.ArchiveOutput

// ArchiveReportInput holds all data needed to build archive output.
type ArchiveReportInput = pruner.ArchiveOutputInput

type archiveExecutionPlan struct {
	now             time.Time
	mode            string
	dryRun          bool
	quiet           bool
	overwrite       bool
	allowSymlink    bool
	format          ui.OutputFormat
	observationsDir string
	archiveDir      string
	tier            string
	olderThan       time.Duration
	keepMin         int
	allFiles        []snapshotFile
	candidateFiles  []snapshotFile
	output          archiveOutput
}

type archiveResolvedInput struct {
	obsDir     string
	archiveDir string
	tier       string
	olderThan  time.Duration
	now        time.Time
	format     ui.OutputFormat
	keepMin    int
	dryRun     bool
	quiet      bool
	overwrite  bool
	allowSym   bool
	mode       string
}

func runArchive(cmd *cobra.Command, _ []string) error {
	var plan archiveExecutionPlan
	return appeval.RunCleanup(appeval.CleanupDeps{
		BuildPlan: func() (appeval.CleanupPlan, error) {
			p, err := buildArchiveExecutionPlan(cmd)
			if err != nil {
				return appeval.CleanupPlan{}, err
			}
			plan = p
			return appeval.CleanupPlan{
				CandidateCount: len(plan.candidateFiles),
				DryRun:         plan.dryRun,
			}, nil
		},
		Render: func(_ appeval.CleanupPlan) error {
			return renderArchiveExecutionPlan(plan, cmd.OutOrStdout())
		},
		Apply: func(_ appeval.CleanupPlan) error {
			if err := applyArchiveExecutionPlan(plan); err != nil {
				return err
			}
			if !cmdutil.QuietEnabled(cmd) && !plan.format.IsJSON() {
				fmt.Fprintf(cmd.OutOrStdout(), "Archived %d snapshot(s) to %s.\n", len(plan.candidateFiles), plan.archiveDir)
			}
			return nil
		},
	})
}

func buildArchiveExecutionPlan(cmd *cobra.Command) (archiveExecutionPlan, error) {
	in, err := resolveArchiveInput(cmd)
	if err != nil {
		return archiveExecutionPlan{}, err
	}
	allFiles, err := pruneshared.ListObservationSnapshotFiles(in.obsDir)
	if err != nil {
		return archiveExecutionPlan{}, err
	}
	candidateFiles := pruneshared.PlanPrune(allFiles, pruner.Criteria{Now: in.now, OlderThan: in.olderThan, KeepMin: in.keepMin})
	out := pruner.BuildArchiveOutput(ArchiveReportInput{
		Now:             in.now,
		Mode:            in.mode,
		DryRun:          in.dryRun,
		ObservationsDir: in.obsDir,
		ArchiveDir:      in.archiveDir,
		Tier:            in.tier,
		OlderThan:       in.olderThan,
		KeepMin:         in.keepMin,
		AllFiles:        allFiles,
		CandidateFiles:  candidateFiles,
	})
	return archiveExecutionPlan{
		now:             in.now,
		mode:            in.mode,
		dryRun:          in.dryRun,
		quiet:           in.quiet,
		overwrite:       in.overwrite,
		allowSymlink:    in.allowSym,
		format:          in.format,
		observationsDir: in.obsDir,
		archiveDir:      in.archiveDir,
		tier:            in.tier,
		olderThan:       in.olderThan,
		keepMin:         in.keepMin,
		allFiles:        allFiles,
		candidateFiles:  candidateFiles,
		output:          out,
	}, nil
}

func resolveArchiveInput(cmd *cobra.Command) (archiveResolvedInput, error) {
	obsDir, destArchiveDir, err := resolveArchivePaths(archiveOpts.ObservationsDir, archiveOpts.ArchiveDir)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	if archiveOpts.KeepMin < 0 {
		return archiveResolvedInput{}, fmt.Errorf("invalid --keep-min %d: must be >= 0", archiveOpts.KeepMin)
	}
	tier, err := pruneshared.ValidateRetentionTier(archiveOpts.RetentionTier)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	olderThan, err := pruneshared.ResolveOlderThan(cmd, archiveOpts.OlderThan, tier)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	now, err := cmdutil.ResolveNow(archiveOpts.Now)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	format, err := cmdutil.ResolveFormatValue(cmd, archiveOpts.Format)
	if err != nil {
		return archiveResolvedInput{}, err
	}

	overwrite := cmdutil.ForceEnabled(cmd)
	dryRun := archiveOpts.DryRun || !overwrite
	mode := "MOVE"
	if dryRun {
		mode = "DRY_RUN"
	}

	return archiveResolvedInput{
		obsDir:     obsDir,
		archiveDir: destArchiveDir,
		tier:       tier,
		olderThan:  olderThan,
		now:        now,
		format:     format,
		keepMin:    archiveOpts.KeepMin,
		dryRun:     dryRun,
		quiet:      cmdutil.QuietEnabled(cmd),
		overwrite:  overwrite,
		allowSym:   cmdutil.AllowSymlinkOutEnabled(cmd),
		mode:       mode,
	}, nil
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

func renderArchiveExecutionPlan(plan archiveExecutionPlan, out io.Writer) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(out, pruner.SnapshotCleanupRenderInput{
		Format:         plan.format,
		Output:         plan.output,
		OutputKind:     "archive",
		Action:         "archive",
		SummaryPrefix:  "Archive",
		Mode:           plan.mode,
		AllFiles:       plan.allFiles,
		CandidateFiles: plan.candidateFiles,
		OlderThan:      plan.olderThan,
		KeepMin:        plan.keepMin,
		Tier:           plan.tier,
		Now:            plan.now,
		Quiet:          plan.quiet,
	})
}

func applyArchiveExecutionPlan(plan archiveExecutionPlan) error {
	_, err := pruner.ApplyArchive(pruner.ArchiveInput{
		ArchiveDir: plan.archiveDir,
		Moves:      toArchiveMoves(plan.candidateFiles, plan.archiveDir),
		Options: pruner.MoveOptions{
			Overwrite:    plan.overwrite,
			AllowSymlink: plan.allowSymlink,
		},
	})
	return err
}

func toArchiveMoves(files []snapshotFile, archiveDir string) []pruner.ArchiveMove {
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
