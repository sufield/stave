package manifest

import "github.com/spf13/cobra"

// NewCmd constructs the manifest command tree with closure-scoped flags per subcommand.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Generate and sign observation integrity manifests",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newGenerateCmd())
	cmd.AddCommand(newSignCmd())
	cmd.AddCommand(newKeygenCmd())
	return cmd
}
