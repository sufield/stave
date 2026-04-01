package archive

import (
	"context"
	"fmt"

	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	"github.com/sufield/stave/internal/adapters/pruner"
	"github.com/sufield/stave/internal/adapters/pruner/report"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/retention"
)

// BuildPlan identifies which snapshots meet the criteria for archiving.
func (r *runner) BuildPlan(ctx context.Context) (appeval.CleanupPlan, error) {
	loader, err := r.NewSnapshotRepo()
	if err != nil {
		return appeval.CleanupPlan{}, fmt.Errorf("create snapshot loader: %w", err)
	}
	allFiles, err := pruneretention.ListObservationSnapshotFiles(ctx, loader, r.cfg.ObservationsDir)
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
			Action:          pruner.ActionMove,
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
