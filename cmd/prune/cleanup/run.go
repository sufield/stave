package cleanup

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

type deleteOptions struct {
	ObservationsDir string
	OlderThan       string
	RetentionTier   string
	Now             string
	KeepMin         int
	DryRun          bool
	Format          string
}

type deleteOutput = pruner.PruneOutput

// deleteReportInput holds all data needed to build prune output.
type deleteReportInput = pruner.PruneOutputInput

type deletePlan struct {
	now             time.Time
	mode            string
	dryRun          bool
	quiet           bool
	format          ui.OutputFormat
	observationsDir string
	tier            string
	olderThan       time.Duration
	keepMin         int
	allFiles        []snapshotFile
	candidateFiles  []snapshotFile
	output          deleteOutput
}

type deleteRunInput struct {
	obsDir    string
	tier      string
	olderThan time.Duration
	now       time.Time
	format    ui.OutputFormat
	keepMin   int
	dryRun    bool
	quiet     bool
	mode      string
}

func runDelete(cmd *cobra.Command, opts *deleteOptions) error {
	var plan deletePlan
	return appeval.RunCleanup(appeval.CleanupDeps{
		BuildPlan: func() (appeval.CleanupPlan, error) {
			p, err := buildDeletePlan(cmd, opts)
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
			return renderDeletePlan(plan, cmd.OutOrStdout())
		},
		Apply: func(_ appeval.CleanupPlan) error {
			deletion, err := pruner.ApplyDelete(pruner.DeleteInput{
				Files: toDeleteFiles(plan.candidateFiles),
			})
			if err != nil {
				return err
			}
			if !cmdutil.QuietEnabled(cmd) && !plan.format.IsJSON() {
				fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d snapshot(s).\n", deletion.Deleted)
			}
			return nil
		},
	})
}

func buildDeletePlan(cmd *cobra.Command, opts *deleteOptions) (deletePlan, error) {
	in, err := resolveDeleteInput(cmd, opts)
	if err != nil {
		return deletePlan{}, err
	}
	allFiles, err := pruneshared.ListObservationSnapshotFiles(in.obsDir)
	if err != nil {
		return deletePlan{}, err
	}
	candidateFiles := pruneshared.PlanPrune(allFiles, pruner.Criteria{Now: in.now, OlderThan: in.olderThan, KeepMin: in.keepMin})
	out := pruner.BuildPruneOutput(deleteReportInput{
		Now:             in.now,
		Mode:            in.mode,
		DryRun:          in.dryRun,
		ObservationsDir: in.obsDir,
		Tier:            in.tier,
		OlderThan:       in.olderThan,
		KeepMin:         in.keepMin,
		AllFiles:        allFiles,
		CandidateFiles:  candidateFiles,
	})
	return deletePlan{
		now:             in.now,
		mode:            in.mode,
		dryRun:          in.dryRun,
		quiet:           in.quiet,
		format:          in.format,
		observationsDir: in.obsDir,
		tier:            in.tier,
		olderThan:       in.olderThan,
		keepMin:         in.keepMin,
		allFiles:        allFiles,
		candidateFiles:  candidateFiles,
		output:          out,
	}, nil
}

func resolveDeleteInput(cmd *cobra.Command, opts *deleteOptions) (deleteRunInput, error) {
	obsDir := fsutil.CleanUserPath(opts.ObservationsDir)
	if obsDir == "" {
		return deleteRunInput{}, fmt.Errorf("--observations cannot be empty")
	}
	if opts.KeepMin < 0 {
		return deleteRunInput{}, fmt.Errorf("invalid --keep-min %d: must be >= 0", opts.KeepMin)
	}
	tier, err := pruneshared.ValidateRetentionTier(opts.RetentionTier)
	if err != nil {
		return deleteRunInput{}, err
	}
	olderThan, err := pruneshared.ResolveOlderThan(cmd, opts.OlderThan, tier)
	if err != nil {
		return deleteRunInput{}, err
	}
	now, err := compose.ResolveNow(opts.Now)
	if err != nil {
		return deleteRunInput{}, err
	}
	format, err := compose.ResolveFormatValue(cmd, opts.Format)
	if err != nil {
		return deleteRunInput{}, err
	}

	dryRun := opts.DryRun || !cmdutil.ForceEnabled(cmd)
	mode := "DELETE"
	if dryRun {
		mode = "DRY_RUN"
	}

	return deleteRunInput{
		obsDir:    obsDir,
		tier:      tier,
		olderThan: olderThan,
		now:       now,
		format:    format,
		keepMin:   opts.KeepMin,
		dryRun:    dryRun,
		quiet:     cmdutil.QuietEnabled(cmd),
		mode:      mode,
	}, nil
}

func renderDeletePlan(plan deletePlan, out io.Writer) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(out, pruner.SnapshotCleanupRenderInput{
		Format:         plan.format,
		Output:         plan.output,
		OutputKind:     "prune",
		Action:         "prune",
		SummaryPrefix:  "Prune",
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

func toDeleteFiles(in []snapshotFile) []pruner.DeleteFile {
	out := make([]pruner.DeleteFile, 0, len(in))
	for _, sf := range in {
		out = append(out, pruner.DeleteFile{Path: sf.Path})
	}
	return out
}
