package archive

import (
	"fmt"
	"io"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
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
	pruneshared.CleanupPlan
	overwrite    bool
	allowSymlink bool
	archiveDir   string
	output       archiveOutput
}

type archiveResolvedInput struct {
	pruneshared.CleanupRunInput
	ArchiveDir string
	Overwrite  bool
	AllowSym   bool
}

func runArchive(cmd *cobra.Command, opts *archiveOptions) error {
	var plan archiveExecutionPlan
	return appeval.RunCleanup(appeval.CleanupDeps{
		BuildPlan: func() (appeval.CleanupPlan, error) {
			p, err := buildArchiveExecutionPlan(cmd, opts)
			if err != nil {
				return appeval.CleanupPlan{}, err
			}
			plan = p
			return appeval.CleanupPlan{
				CandidateCount: len(plan.CandidateFiles),
				DryRun:         plan.DryRun,
			}, nil
		},
		Render: func(_ appeval.CleanupPlan) error {
			return renderArchiveExecutionPlan(plan, cmd.OutOrStdout())
		},
		Apply: func(_ appeval.CleanupPlan) error {
			if err := applyArchiveExecutionPlan(plan); err != nil {
				return err
			}
			if !cmdutil.QuietEnabled(cmd) && !plan.Format.IsJSON() {
				fmt.Fprintf(cmd.OutOrStdout(), "Archived %d snapshot(s) to %s.\n", len(plan.CandidateFiles), plan.archiveDir)
			}
			return nil
		},
	})
}

func buildArchiveExecutionPlan(cmd *cobra.Command, opts *archiveOptions) (archiveExecutionPlan, error) {
	in, err := resolveArchiveInput(cmd, opts)
	if err != nil {
		return archiveExecutionPlan{}, err
	}
	allFiles, err := pruneshared.ListObservationSnapshotFiles(cmd.Context(), in.ObsDir)
	if err != nil {
		return archiveExecutionPlan{}, err
	}
	candidateFiles := pruneshared.PlanPrune(allFiles, pruner.Criteria{Now: in.Now, OlderThan: in.OlderThan, KeepMin: in.KeepMin})
	out := pruner.BuildArchiveOutput(ArchiveReportInput{
		CleanupInputCore: pruner.CleanupInputCore{
			Now:             in.Now,
			Mode:            in.Mode,
			DryRun:          in.DryRun,
			ObservationsDir: in.ObsDir,
			Tier:            in.Tier,
			OlderThan:       in.OlderThan,
			KeepMin:         in.KeepMin,
			AllFiles:        allFiles,
			CandidateFiles:  candidateFiles,
		},
		ArchiveDir: in.ArchiveDir,
	})
	return archiveExecutionPlan{
		CleanupPlan: pruneshared.CleanupPlan{
			Now:             in.Now,
			Mode:            in.Mode,
			DryRun:          in.DryRun,
			Quiet:           in.Quiet,
			Format:          in.Format,
			ObservationsDir: in.ObsDir,
			Tier:            in.Tier,
			OlderThan:       in.OlderThan,
			KeepMin:         in.KeepMin,
			AllFiles:        allFiles,
			CandidateFiles:  candidateFiles,
		},
		overwrite:    in.Overwrite,
		allowSymlink: in.AllowSym,
		archiveDir:   in.ArchiveDir,
		output:       out,
	}, nil
}

func resolveArchiveInput(cmd *cobra.Command, opts *archiveOptions) (archiveResolvedInput, error) {
	obsDir, destArchiveDir, err := resolveArchivePaths(opts.ObservationsDir, opts.ArchiveDir)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	if opts.KeepMin < 0 {
		return archiveResolvedInput{}, fmt.Errorf("invalid --keep-min %d: must be >= 0", opts.KeepMin)
	}
	tier, err := pruneshared.ValidateRetentionTier(opts.RetentionTier)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	olderThan, err := pruneshared.ResolveOlderThan(cmd, opts.OlderThan, tier)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	now, err := compose.ResolveNow(opts.Now)
	if err != nil {
		return archiveResolvedInput{}, err
	}
	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return archiveResolvedInput{}, err
	}

	overwrite := cmdutil.ForceEnabled(cmd)
	dryRun := opts.DryRun || !overwrite
	mode := "MOVE"
	if dryRun {
		mode = "DRY_RUN"
	}

	return archiveResolvedInput{
		CleanupRunInput: pruneshared.CleanupRunInput{
			ObsDir:    obsDir,
			Tier:      tier,
			OlderThan: olderThan,
			Now:       now,
			Format:    format,
			KeepMin:   opts.KeepMin,
			DryRun:    dryRun,
			Quiet:     cmdutil.QuietEnabled(cmd),
			Mode:      mode,
		},
		ArchiveDir: destArchiveDir,
		Overwrite:  overwrite,
		AllowSym:   cmdutil.AllowSymlinkOutEnabled(cmd),
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
		Format:         plan.Format,
		Output:         plan.output,
		OutputKind:     "archive",
		Action:         "archive",
		SummaryPrefix:  "Archive",
		Mode:           plan.Mode,
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
