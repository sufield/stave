package status

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
)

func NewCmd() *cobra.Command {
	opts := &options{Dir: ".", Format: "text"}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show project context and the next recommended command",
		Long: `Status inspects local project artifacts and prints a quick "where to continue"
summary plus one recommended next command.

Examples:
  stave status
  cd ./stave-project && stave status
  stave status --format json` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, opts) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&opts.Dir, "dir", "d", opts.Dir, "Directory to inspect for Stave project context")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")
	return cmd
}
