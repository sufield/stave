package compliance

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the inspect compliance command.
func NewCmd() *cobra.Command {
	var (
		file       string
		frameworks []string
		checkIDs   []string
	)

	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Resolve compliance framework crosswalk",
		Long: `Compliance reads a crosswalk YAML mapping and resolves it against
requested compliance frameworks, producing a filtered mapping from
internal checks to external control references.

Inputs:
  --file, -f    Path to crosswalk YAML file (default: stdin)
  --framework   Compliance frameworks to include (repeatable; default: all)
  --check-id    Check IDs to resolve (repeatable; default: all from file)

Outputs:
  stdout        JSON crosswalk resolution

Exit Codes:
  0   - Resolution completed successfully
  2   - Invalid input (malformed YAML, unknown framework)
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  stave inspect compliance --file crosswalk.yaml
  stave inspect compliance --file crosswalk.yaml --framework nist_800_53
  cat crosswalk.yaml | stave inspect compliance
  stave inspect compliance --file crosswalk.yaml --check-id CTL.S3.PUBLIC.001 | jq .` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, file, frameworks, checkIDs) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to crosswalk YAML file (default: stdin)")
	cmd.Flags().StringSliceVar(&frameworks, "framework", nil, "Compliance frameworks to include (default: all)")
	cmd.Flags().StringSliceVar(&checkIDs, "check-id", nil, "Check IDs to resolve (default: all from file)")

	return cmd
}
