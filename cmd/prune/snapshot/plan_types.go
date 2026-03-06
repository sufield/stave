package snapshot

import "github.com/sufield/stave/internal/pruner"

var (
	planObservationsRoot string
	planArchiveDir       string
	planNow              string
	planFormat           string
	planApply            bool
)

type planFileEntry = pruner.SnapshotPlanFile
type planTierSummary = pruner.SnapshotPlanTierSummary
type planOutput = pruner.SnapshotPlanOutput
