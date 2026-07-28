package recommend

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/templates"
	"github.com/sufield/stave/pkg/stave"
	"github.com/sufield/stave/pkg/stave/snapshot"
	tmpl "github.com/sufield/stave/pkg/stave/template"
)

type options struct {
	SnapshotDir string
	Format      string
}

// NewCmd constructs the recommend command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "text"}

	cmd := &cobra.Command{
		Use:   "recommend",
		Short: "Recommend templates for a snapshot",
		Long: `Evaluate every template's recommend_when predicate against the
snapshot summary. Print applicable templates ranked by priority
(highest first). Highlight which snapshot facts triggered each.

Inputs:
  --snapshot PATH     Path to observation snapshot directory or file

Outputs:
  stdout              Ranked template recommendations

Exit Codes:
  0   Recommendations produced (or none matched)
  2   Invalid input
  4   Internal error`,
		Example: `  # Get recommendations for a snapshot
  stave recommend --snapshot ./observations

  # JSON output for automation
  stave recommend --snapshot ./observations --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(_ *cobra.Command, _ []string) error {
			if opts.SnapshotDir == "" {
				return errors.New("--snapshot is required")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRecommend(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.SnapshotDir, "snapshot", "", "path to observation snapshot directory or file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")

	return cmd
}

func runRecommend(ctx context.Context, w io.Writer, opts *options) error {
	allTemplates, err := tmpl.LoadAll("", templates.BuiltinTemplateFS)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	snapshots, err := stave.LoadSnapshots(ctx, opts.SnapshotDir)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}

	summary := snapshot.ExtractSummary(snapshots, false)

	recommendations, err := tmpl.Recommend(allTemplates, summary)
	if err != nil {
		return fmt.Errorf("evaluate recommendations: %w", err)
	}

	if len(recommendations) == 0 {
		fmt.Fprintln(w, "No templates matched this snapshot.")
		return nil
	}

	fmt.Fprintln(w, "Recommended templates for this snapshot:")
	fmt.Fprintln(w)

	for i := range recommendations {
		rec := &recommendations[i]
		fmt.Fprintf(w, "  %d. %s (priority %d)\n", i+1, rec.Template.Metadata.Name, rec.Template.RecommendWhen.Priority)
		if len(rec.MatchedFacts) > 0 {
			fmt.Fprintln(w, "     Matched facts:")
			for _, fact := range rec.MatchedFacts {
				fmt.Fprintf(w, "       ✓ %s\n", fact)
			}
		}
		fmt.Fprintf(w, "     Run: stave template init %s\n", rec.Template.Metadata.Name)
		fmt.Fprintln(w)
	}

	return nil
}
