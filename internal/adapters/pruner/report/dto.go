package report

import (
	"time"

	"github.com/sufield/stave/internal/adapters/pruner"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// CleanupAction is an alias for the shared pruner CleanupAction type.
type CleanupAction = pruner.CleanupAction

// Action constants re-exported from pruner.
const (
	ActionDelete = pruner.ActionDelete
	ActionMove   = pruner.ActionMove
)

// CleanupFile is one snapshot listed in prune/archive output.
type CleanupFile struct {
	Name       string    `json:"name"`
	CapturedAt time.Time `json:"captured_at"`
}

// CleanupOutput holds the fields shared by PruneOutput and ArchiveOutput.
type CleanupOutput struct {
	SchemaVersion   kernel.Schema     `json:"schema_version"`
	Kind            kernel.OutputKind `json:"kind"`
	CheckedAt       time.Time         `json:"checked_at"`
	Mode            string            `json:"mode"`
	Applied         bool              `json:"applied"`
	ObservationsDir string            `json:"observations_dir"`
	RetentionTier   string            `json:"retention_tier"`
	OlderThan       string            `json:"older_than"`
	KeepMin         int               `json:"keep_min"`
	TotalSnapshots  int               `json:"total_snapshots"`
	Candidates      int               `json:"candidates"`
	Files           []CleanupFile     `json:"files"`
}

// PruneOutput is the structured output for prune command.
type PruneOutput struct {
	CleanupOutput
}

// ArchiveOutput is the structured output for archive command.
type ArchiveOutput struct {
	CleanupOutput
	ArchiveDir string `json:"archive_dir"`
}

// CleanupInput holds the shared fields for building prune/archive output.
type CleanupInput struct {
	Now             time.Time
	Action          CleanupAction
	DryRun          bool
	ObservationsDir string
	Tier            string
	OlderThan       time.Duration
	KeepMin         int
	AllFiles        []appcontracts.SnapshotFile
	CandidateFiles  []appcontracts.SnapshotFile
}

// ArchiveOutputInput holds all data needed to build archive output.
type ArchiveOutputInput struct {
	CleanupInput
	ArchiveDir string
}

// buildCleanupOutput constructs the JSON output payload for prune/archive.
//
// NOTE: Applied is a pre-computed intent flag, not a post-execution confirmation.
// The orchestrator sequence is BuildPlan -> Render -> Apply, so the JSON output
// (including Applied) is written to stdout before filesystem operations execute.
// If Apply fails partway through, the already-emitted JSON may be inaccurate.
// Fixing this requires a two-pass render (preview then result), which is deferred
// as a future enhancement.
func buildCleanupOutput(schema kernel.Schema, kind kernel.OutputKind, input CleanupInput) CleanupOutput {
	return CleanupOutput{
		SchemaVersion:   schema,
		Kind:            kind,
		CheckedAt:       input.Now.UTC(),
		Mode:            input.Action.ModeString(input.DryRun),
		Applied:         !input.DryRun && len(input.CandidateFiles) > 0,
		ObservationsDir: input.ObservationsDir,
		RetentionTier:   input.Tier,
		OlderThan:       kernel.FormatDuration(input.OlderThan),
		KeepMin:         input.KeepMin,
		TotalSnapshots:  len(input.AllFiles),
		Candidates:      len(input.CandidateFiles),
		Files:           toCleanupFiles(input.CandidateFiles),
	}
}

// BuildArchiveOutput creates archive JSON output payload.
func BuildArchiveOutput(input ArchiveOutputInput) ArchiveOutput {
	return ArchiveOutput{
		CleanupOutput: buildCleanupOutput(kernel.SchemaSnapshotArchive, kernel.KindSnapshotArchive, input.CleanupInput),
		ArchiveDir:    input.ArchiveDir,
	}
}

func toCleanupFiles(in []appcontracts.SnapshotFile) []CleanupFile {
	out := make([]CleanupFile, 0, len(in))
	for _, sf := range in {
		out = append(out, CleanupFile{
			Name:       sf.Name,
			CapturedAt: sf.CapturedAt.UTC(),
		})
	}
	return out
}
