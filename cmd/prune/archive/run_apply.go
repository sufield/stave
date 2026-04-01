package archive

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/sufield/stave/internal/adapters/pruner/fsops"
	appeval "github.com/sufield/stave/internal/app/eval"
)

// Apply executes the file moves.
func (r *runner) Apply(ctx context.Context, _ appeval.CleanupPlan) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := fsops.ApplyArchive(fsops.ArchiveInput{
		ArchiveDir: r.plan.archiveDir,
		Moves:      r.toArchiveMoves(),
		Options: fsops.MoveOptions{
			Overwrite:    r.cfg.Force,
			AllowSymlink: r.cfg.AllowSymlink,
		},
	})
	if err != nil {
		return fmt.Errorf("archiving snapshots: %w", err)
	}

	if !r.cfg.Quiet && !r.cfg.Format.IsJSON() {
		fmt.Fprintf(r.cfg.Stdout, "Archived %d snapshot(s) to %s.\n",
			len(r.plan.candidateFiles), r.plan.archiveDir)
	}
	return nil
}

// --- Helpers ---

func (r *runner) toArchiveMoves() []fsops.ArchiveMove {
	moves := make([]fsops.ArchiveMove, 0, len(r.plan.candidateFiles))
	for _, sf := range r.plan.candidateFiles {
		moves = append(moves, fsops.ArchiveMove{
			Src: sf.Path,
			Dst: filepath.Join(r.plan.archiveDir, sf.Name),
		})
	}
	return moves
}
