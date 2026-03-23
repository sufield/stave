package status

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the status command.
func NewCmd() *cobra.Command {
	opts := &options{
		Dir:    ".",
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show project context and the next recommended command",
		Long: `Status inspects local project artifacts and prints a quick "where to continue"
summary plus one recommended next command.

Inputs:
  --dir, -d     Directory to inspect for Stave project context (default: .)
  --format, -f  Output format: text or json (default: text)

Outputs:
  stdout        Project status summary and next recommended command
  stderr        Error messages (if any)

Exit Codes:
  0   - Status retrieved successfully
  2   - Invalid input or configuration error
  130 - Interrupted (SIGINT)

Examples:
  stave status
  cd ./stave-project && stave status
  stave status --format json` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			format, err := opts.resolveFormat(cmd)
			if err != nil {
				return err
			}

			resolver, err := projctx.NewResolver()
			if err != nil {
				return err
			}

			runner := NewRunner(resolver)
			return runner.Run(Config{
				Dir:    opts.Dir,
				Format: format,
				Stdout: cmd.OutOrStdout(),
				Stderr: cmd.ErrOrStderr(),
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
