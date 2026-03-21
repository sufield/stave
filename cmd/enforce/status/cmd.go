package status

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the status command.
func NewCmd() *cobra.Command {
	var (
		dirFlag    string
		formatFlag string
	)

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show project context and the next recommended command",
		Long: `Status inspects local project artifacts and prints a quick "where to continue"
summary plus one recommended next command.

Examples:
  stave status
  cd ./stave-project && stave status
  stave status --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := compose.ResolveFormatValue(cmd, formatFlag)
			if err != nil {
				return err
			}

			resolver, err := projctx.NewResolver()
			if err != nil {
				return err
			}

			runner := NewRunner(resolver)
			return runner.Run(cmd.Context(), Config{
				Dir:    dirFlag,
				Format: format,
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&dirFlag, "dir", "d", ".", "Directory to inspect for Stave project context")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text or json")
	return cmd
}
