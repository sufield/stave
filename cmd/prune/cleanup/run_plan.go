package cleanup

import (
	"context"
	"fmt"

	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	"github.com/sufield/stave/internal/adapters/pruner"
	"github.com/sufield/stave/internal/adapters/pruner/report"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/retention"
)

// BuildPlan identifies which snapshots meet the criteria for pruning.
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
			Mode:            pruner.ActionDelete.ModeString(r.cfg.DryRun),
			Applied:         !r.cfg.DryRun && len(candidates) > 0,
			ObservationsDir: r.cfg.ObservationsDir,
			RetentionTier:   r.cfg.RetentionTier,
			OlderThan:       kernel.FormatDuration(r.cfg.OlderThan),
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
