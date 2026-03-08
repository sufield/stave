package cleanup

import (
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile
type PruningCriteria = pruner.Criteria

var listObservationSnapshotFiles = pruneshared.ListObservationSnapshotFiles
var planPrune = pruneshared.PlanPrune
var validateRetentionTier = pruneshared.ValidateRetentionTier
var resolveCleanupOlderThan = pruneshared.ResolveOlderThan

func cleanUserPath(path string) string {
	return fsutil.CleanUserPath(path)
}
