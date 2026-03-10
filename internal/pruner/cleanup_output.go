package pruner

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// CleanupFile is one snapshot listed in prune/archive output.
type CleanupFile struct {
	Name       string    `json:"name"`
	CapturedAt time.Time `json:"captured_at"`
}

// CleanupOutput holds the fields shared by PruneOutput and ArchiveOutput.
type CleanupOutput struct {
	SchemaVersion   kernel.Schema `json:"schema_version"`
	Kind            string        `json:"kind"`
	CheckedAt       time.Time     `json:"checked_at"`
	Mode            string        `json:"mode"`
	Applied         bool          `json:"applied"`
	ObservationsDir string        `json:"observations_dir"`
	RetentionTier   string        `json:"retention_tier"`
	OlderThan       string        `json:"older_than"`
	KeepMin         int           `json:"keep_min"`
	TotalSnapshots  int           `json:"total_snapshots"`
	Candidates      int           `json:"candidates"`
	Files           []CleanupFile `json:"files"`
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
	Mode            string
	DryRun          bool
	ObservationsDir string
	Tier            string
	OlderThan       time.Duration
	KeepMin         int
	AllFiles        []SnapshotFile
	CandidateFiles  []SnapshotFile
}

// ArchiveOutputInput holds all data needed to build archive output.
type ArchiveOutputInput struct {
	CleanupInput
	ArchiveDir string
}

func buildCleanupOutput(schema kernel.Schema, kind string, input CleanupInput) CleanupOutput {
	return CleanupOutput{
		SchemaVersion:   schema,
		Kind:            kind,
		CheckedAt:       input.Now.UTC(),
		Mode:            input.Mode,
		Applied:         !input.DryRun && len(input.CandidateFiles) > 0,
		ObservationsDir: input.ObservationsDir,
		RetentionTier:   input.Tier,
		OlderThan:       timeutil.FormatDuration(input.OlderThan),
		KeepMin:         input.KeepMin,
		TotalSnapshots:  len(input.AllFiles),
		Candidates:      len(input.CandidateFiles),
		Files:           toCleanupFiles(input.CandidateFiles),
	}
}

// BuildPruneOutput creates prune JSON output payload.
func BuildPruneOutput(input CleanupInput) PruneOutput {
	return PruneOutput{
		CleanupOutput: buildCleanupOutput(kernel.SchemaSnapshotPrune, "snapshot_prune", input),
	}
}

// BuildArchiveOutput creates archive JSON output payload.
func BuildArchiveOutput(input ArchiveOutputInput) ArchiveOutput {
	return ArchiveOutput{
		CleanupOutput: buildCleanupOutput(kernel.SchemaSnapshotArchive, "snapshot_archive", input.CleanupInput),
		ArchiveDir:    input.ArchiveDir,
	}
}

// SnapshotCleanupRenderInput configures text/json rendering for prune/archive plan.
type SnapshotCleanupRenderInput struct {
	Format         ui.OutputFormat
	Output         any
	OutputKind     string
	Action         string
	SummaryPrefix  string
	Mode           string
	AllFiles       []SnapshotFile
	CandidateFiles []SnapshotFile
	OlderThan      time.Duration
	KeepMin        int
	Tier           string
	Now            time.Time
	Quiet          bool
}

// RenderSnapshotCleanupExecutionPlan writes prune/archive preview output.
func RenderSnapshotCleanupExecutionPlan(out io.Writer, in SnapshotCleanupRenderInput) error {
	if in.Quiet {
		return nil
	}
	if in.Format.IsJSON() {
		if err := writeJSON(out, in.Output); err != nil {
			return fmt.Errorf("write %s output: %w", in.OutputKind, err)
		}
		return nil
	}
	if len(in.CandidateFiles) == 0 {
		fmt.Fprintf(out, "No snapshots to %s (total=%d, older-than=%s, keep-min=%d).\n", in.Action, len(in.AllFiles), timeutil.FormatDuration(in.OlderThan), in.KeepMin)
		return nil
	}
	fmt.Fprintf(out, "%s mode=%s total=%d candidates=%d older-than=%s tier=%s keep-min=%d now=%s\n",
		in.SummaryPrefix, in.Mode, len(in.AllFiles), len(in.CandidateFiles), timeutil.FormatDuration(in.OlderThan), in.Tier, in.KeepMin, in.Now.Format(time.RFC3339))
	for _, sf := range in.CandidateFiles {
		fmt.Fprintf(out, "- %s (captured_at=%s)\n", sf.Name, sf.CapturedAt.Format(time.RFC3339))
	}
	return nil
}

func toCleanupFiles(in []SnapshotFile) []CleanupFile {
	out := make([]CleanupFile, 0, len(in))
	for _, sf := range in {
		out = append(out, CleanupFile{
			Name:       sf.Name,
			CapturedAt: sf.CapturedAt.UTC(),
		})
	}
	return out
}

func writeJSON(w io.Writer, v any) error {
	return jsonutil.WriteIndented(w, v)
}
