package acl

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the inspect acl command.
func NewCmd() *cobra.Command {
	var file string

	cmd := &cobra.Command{
		Use:   "acl",
		Short: "Analyze S3 ACL grants",
		Long: `ACL reads a JSON array of S3 ACL grants and evaluates their security
posture, identifying public, authenticated, and full-control grants.

Input: JSON array of grant objects from --file or stdin.
Output: JSON assessment with permission analysis.

Examples:
  stave inspect acl --file grants.json
  cat grants.json | stave inspect acl` + metadata.OfflineHelpSuffix,
		Args:          cobra.NoArgs,
		RunE:          func(cmd *cobra.Command, _ []string) error { return run(cmd, file) },
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&file, "file", "f", "", "Path to ACL grants JSON file (default: stdin)")

	return cmd
}
