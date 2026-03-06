package hygiene

import (
	"fmt"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile
type PruningCriteria = pruner.Criteria

func listObservationSnapshotFiles(observationsDir string) ([]snapshotFile, error) {
	loader, err := cmdutil.NewSnapshotObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	files, err := pruner.ListSnapshotFilesFlatWithLoader(observationsDir, loader)
	if err != nil {
		return nil, err
	}
	return files, nil
}

func planPrune(files []snapshotFile, criteria PruningCriteria) []snapshotFile {
	items := make([]pruner.Candidate, 0, len(files))
	for i, sf := range files {
		items = append(items, pruner.Candidate{
			Index:      i,
			CapturedAt: sf.CapturedAt,
		})
	}
	selected := pruner.PlanPrune(items, criteria)
	out := make([]snapshotFile, 0, len(selected))
	for _, item := range selected {
		if item.Index < 0 || item.Index >= len(files) {
			continue
		}
		out = append(out, files[item.Index])
	}
	return out
}
