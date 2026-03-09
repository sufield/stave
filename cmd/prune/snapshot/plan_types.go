package snapshot

import "github.com/sufield/stave/internal/pruner"

type planFlagsType struct {
	observationsRoot string
	archiveDir       string
	now              string
	format           string
	apply            bool
}

type planFileEntry = pruner.SnapshotPlanFile
type planTierSummary = pruner.SnapshotPlanTierSummary
type planOutput = pruner.SnapshotPlanOutput
