package hygiene

import (
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/pruner"
)

type snapshotFile = pruner.SnapshotFile
type PruningCriteria = pruner.Criteria

var listObservationSnapshotFiles = pruneshared.ListObservationSnapshotFiles
var planPrune = pruneshared.PlanPrune
