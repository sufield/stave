package cleanup

import (
	"context"
	"fmt"

	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	appeval "github.com/sufield/stave/internal/app/eval"
)

// Apply executes the file deletions.
func (r *runner) Apply(ctx context.Context, _ appeval.CleanupPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	deletion, err := fsops.ApplyDelete(fsops.DeleteInput{
		ObservationsDir: r.cfg.ObservationsDir,
		Files:           r.toDeleteFiles(),
	})
	if err != nil {
		return fmt.Errorf("deleting snapshots: %w", err)
	}

	if !r.cfg.Quiet && !r.cfg.Format.IsJSON() {
		fmt.Fprintf(r.cfg.Stdout, "Deleted %d snapshot(s).\n", deletion.Deleted)
	}
	return nil
}

// --- Helpers ---

func (r *runner) toDeleteFiles() []fsops.DeleteFile {
	out := make([]fsops.DeleteFile, 0, len(r.plan.candidateFiles))
	for _, sf := range r.plan.candidateFiles {
		out = append(out, fsops.DeleteFile{Path: sf.Path})
	}
	return out
}
