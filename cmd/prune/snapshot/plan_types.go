package snapshot

import "github.com/sufield/stave/internal/pruner"

type planFileEntry = pruner.SnapshotPlanFile
type planTierSummary = pruner.SnapshotPlanTierSummary
type planOutput = pruner.SnapshotPlanOutput

// TODO : remove these type aliases and update all references to use pruner.SnapshotPlanFile, pruner.SnapshotPlanTierSummary, and pruner.SnapshotPlanOutput instead
