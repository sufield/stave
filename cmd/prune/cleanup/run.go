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

type deleteOrchestrator struct {
	cmd  *cobra.Command
	opts *deleteOptions
	plan deletePlan
}

func (d *deleteOrchestrator) BuildPlan() (appeval.CleanupPlan, error) {
	p, err := buildDeletePlan(d.cmd, d.opts)
	if err != nil {
		return appeval.CleanupPlan{}, err
	}
	d.plan = p
	return appeval.CleanupPlan{
		CandidateCount: len(d.plan.CandidateFiles),
		DryRun:         d.plan.DryRun,
	}, nil
}

func (d *deleteOrchestrator) Render(_ appeval.CleanupPlan) error {
	return renderDeletePlan(d.plan, d.cmd.OutOrStdout())
}

func (d *deleteOrchestrator) Apply(_ appeval.CleanupPlan) error {
	deletion, err := pruner.ApplyDelete(pruner.DeleteInput{
		ObservationsDir: d.plan.ObservationsDir,
		Files:           toDeleteFiles(d.plan.CandidateFiles),
	})
	if err != nil {
		return err
	}
	if !cmdutil.GetGlobalFlags(d.cmd).Quiet && !d.plan.Format.IsJSON() {
		fmt.Fprintf(d.cmd.OutOrStdout(), "Deleted %d snapshot(s).\n", deletion.Deleted)
	}
	return nil
}

func runDelete(cmd *cobra.Command, opts *deleteOptions) error {
	return appeval.RunCleanup(&deleteOrchestrator{cmd: cmd, opts: opts})
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
		Action:          in.Action,
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
			Action:          in.Action,
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

	gf := cmdutil.GetGlobalFlags(cmd)
	dryRun := opts.DryRun || !gf.Force

	return deleteRunInput{
		CleanupRunInput: pruneshared.CleanupRunInput{
			ObsDir:    obsDir,
			Tier:      tier,
			OlderThan: olderThan,
			Now:       now,
			Format:    format,
			KeepMin:   opts.KeepMin,
			DryRun:    dryRun,
			Quiet:     gf.Quiet,
			Action:    pruner.ActionDelete,
		},
	}, nil
}

func renderDeletePlan(plan deletePlan, out io.Writer) error {
	return pruner.RenderSnapshotCleanupExecutionPlan(out, pruner.SnapshotCleanupRenderInput{
		Format:         plan.Format,
		Output:         plan.output,
		OutputKind:     "prune",
		ActionLabel:    "prune",
		SummaryPrefix:  "Prune",
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

func toDeleteFiles(in []pruner.SnapshotFile) []pruner.DeleteFile {
	out := make([]pruner.DeleteFile, 0, len(in))
	for _, sf := range in {
		out = append(out, pruner.DeleteFile{Path: sf.Path})
	}
	return out
}
