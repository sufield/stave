package exempt

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

type suggestOptions struct {
	HistoryDir     string
	WindowRaw      string
	MinDwellRaw    string
	Format         string
	AcceptanceFile string
}

func newSuggestCmd() *cobra.Command {
	opts := suggestOptions{
		WindowRaw:      "30d",
		MinDwellRaw:    "14d",
		Format:         "table",
		AcceptanceFile: defaultFile,
	}

	cmd := &cobra.Command{
		Use:   "suggest",
		Short: "Suggest exemptions for chronic/oscillating findings",
		Long: `Analyze assessment history to identify findings that have been open
long enough to warrant a formal governance decision: fix, formally
accept the risk, or escalate.

Oscillating findings (fixed then returned) are separated from chronic
findings (continuously open). Each includes a copy-paste exemption command.

Exit Codes:
  0   Suggestions produced
  2   Invalid input`,
		Example: `  stave exempt suggest --history ./history --window 30d --min-dwell 14d
  stave exempt suggest --history ./history --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.SuggestExemptions(cmd.Context(), stave.SuggestConfig{
				HistoryDir:     opts.HistoryDir,
				Window:         opts.WindowRaw,
				MinDwell:       opts.MinDwellRaw,
				Format:         opts.Format,
				AcceptanceFile: opts.AcceptanceFile,
			})
			if err != nil {
				return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
			}
			_, werr := cmd.OutOrStdout().Write(out)
			return werr
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "directory of historical assessment JSON files (required)")
	cmd.Flags().StringVar(&opts.WindowRaw, "window", opts.WindowRaw, "how far back to look for patterns (e.g. 30d, 90d)")
	cmd.Flags().StringVar(&opts.MinDwellRaw, "min-dwell", opts.MinDwellRaw, "minimum time a finding must be open to be chronic (e.g. 14d)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "output format: table | json")
	cmd.Flags().StringVar(&opts.AcceptanceFile, "file", opts.AcceptanceFile, "path to acceptance file (for excluding already-exempted findings)")
	_ = cmd.MarkFlagRequired("history")

	return cmd
}
