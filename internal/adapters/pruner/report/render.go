package report

import (
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/internal/adapters/pruner"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/pkg/timeutil"
)

// SnapshotCleanupRenderInput configures text/json rendering for prune/archive plan.
type SnapshotCleanupRenderInput struct {
	Format         ui.OutputFormat
	Output         any
	OutputKind     string
	ActionLabel    string
	SummaryPrefix  string
	Action         CleanupAction
	DryRun         bool
	AllFiles       []pruner.SnapshotFile
	CandidateFiles []pruner.SnapshotFile
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
		fmt.Fprintf(out, "No snapshots to %s (total=%d, older-than=%s, keep-min=%d).\n", in.ActionLabel, len(in.AllFiles), timeutil.FormatDuration(in.OlderThan), in.KeepMin)
		return nil
	}
	fmt.Fprintf(out, "%s mode=%s total=%d candidates=%d older-than=%s tier=%s keep-min=%d now=%s\n",
		in.SummaryPrefix, in.Action.ModeString(in.DryRun), len(in.AllFiles), len(in.CandidateFiles), timeutil.FormatDuration(in.OlderThan), in.Tier, in.KeepMin, in.Now.Format(time.RFC3339))
	for _, sf := range in.CandidateFiles {
		fmt.Fprintf(out, "- %s (captured_at=%s)\n", sf.Name, sf.CapturedAt.Format(time.RFC3339))
	}
	return nil
}

func writeJSON(w io.Writer, v any) error {
	return jsonutil.WriteIndented(w, v)
}
