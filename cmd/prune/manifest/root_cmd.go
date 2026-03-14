package manifest

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd constructs the manifest command tree.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "manifest",
		Short: "Generate and sign observation integrity manifests",
		Long: `Manifest provides tools to ensure the integrity of observation snapshots.
It supports indexing files with checksums, generating signing keys, and
creating cryptographically signed manifests to prevent tampering in
distributed or high-security environments.` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
	}

	cmd.AddCommand(
		newGenerateCmd(),
		newSignCmd(),
		newKeygenCmd(),
	)

	return cmd
}
