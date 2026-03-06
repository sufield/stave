package manifest

import "github.com/spf13/cobra"

var Cmd = &cobra.Command{
	Use:   "manifest",
	Short: "Generate and sign observation integrity manifests",
	Args:  cobra.NoArgs,
}

func init() {
	Cmd.AddCommand(GenerateCmd)
	Cmd.AddCommand(SignCmd)
	Cmd.AddCommand(KeygenCmd)
}
