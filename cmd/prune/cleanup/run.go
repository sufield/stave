package cleanup

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	appeval "github.com/sufield/stave/internal/app/eval"
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

type deletePlan struct {
	pruneshared.CleanupPlan
	output deleteOutput
}

type deleteRunInput struct {
	pruneshared.CleanupRunInput
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
				CandidateCount: len(plan.CandidateFiles),
				DryRun:         plan.DryRun,
			}, nil
		},
		Render: func(_ appeval.CleanupPlan) error {
			return renderDeletePlan(plan, cmd.OutOrStdout())
		},
		Apply: func(_ appeval.CleanupPlan) error {
			deletion, err := pruner.ApplyDelete(pruner.DeleteInput{
				Files: toDeleteFiles(plan.CandidateFiles),
			})
			if err != nil {
				return err
			}
			if !cmdutil.QuietEnabled(cmd) && !plan.Format.IsJSON() {
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
	allFiles, err := pruneshared.ListObservationSnapshotFiles(cmd.Context(), in.ObsDir)
	if err != nil {
		return deletePlan{}, err
	}
	candidateFiles := pruneshared.PlanPrune(allFiles, pruner.Criteria{Now: in.Now, OlderThan: in.OlderThan, KeepMin: in.KeepMin})
	out := pruner.BuildPruneOutput(pruner.CleanupInput{
		Now:             in.Now,
		Mode:            in.Mode,
		DryRun:          in.DryRun,
		ObservationsDir: in.ObsDir,
		Tier:            in.Tier,
		OlderThan:       in.OlderThan,
		KeepMin:         in.KeepMin,
		AllFiles:        allFiles,
		CandidateFiles:  candidateFiles,
	})
	return deletePlan{
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
		output: out,
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
	}, nil
}

func renderDeletePlan(plan deletePlan, out io.Writer) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(out, pruner.SnapshotCleanupRenderInput{
		Format:         plan.Format,
		Output:         plan.output,
		OutputKind:     "prune",
		Action:         "prune",
		SummaryPrefix:  "Prune",
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

func toDeleteFiles(in []snapshotFile) []pruner.DeleteFile {
	out := make([]pruner.DeleteFile, 0, len(in))
	for _, sf := range in {
		out = append(out, pruner.DeleteFile{Path: sf.Path})
	}
	return out
}
