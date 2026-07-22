package bundle

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

func newVerifyCmd() *cobra.Command {
	var bundlePath, keyPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify the integrity of a sealed evidence bundle",
		Long: `Verify a .stave-bundle archive's manifest digests and optional
Ed25519 signature.

Inputs:
  --bundle PATH       Path to .stave-bundle archive (required)
  --public-key PATH   Path to Ed25519 public key PEM (optional)

Outputs:
  stdout              Verification result

Exit Codes:
  0   Verification passed
  2   Invalid input
  3   Verification failed`,
		Example: `  stave bundle verify --bundle evidence.stave-bundle
  stave bundle verify --bundle evidence.stave-bundle --public-key audit.pub`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.OutOrStdout(), bundlePath, keyPath)
		},
	}

	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to .stave-bundle archive (required)")
	cmd.Flags().StringVar(&keyPath, "public-key", "", "Path to Ed25519 public key PEM")
	cliflags.MustMarkRequired(cmd, "bundle")

	return cmd
}

func runVerify(stdout io.Writer, bundlePath, keyPath string) error {
	bundleData, err := os.ReadFile(fsutil.CleanUserPath(bundlePath)) //nolint:gosec // user-specified bundle path
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read bundle: %w", err)}
	}

	var publicKeyPEM []byte
	if keyPath != "" {
		pem, readErr := fsutil.ReadFileLimited(keyPath)
		if readErr != nil {
			return &ui.UserError{Err: fmt.Errorf("read public key: %w", readErr)}
		}
		publicKeyPEM = pem
	}

	result, err := stave.VerifyEvidenceBundle(bundleData, publicKeyPEM)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	if !result.ManifestValid {
		fmt.Fprintf(stdout, "Bundle verification failed: manifest digests do not match (%d files checked)\n", result.FileCount)
		return ui.ErrViolationsFound
	}

	if result.Signed && keyPath != "" && !result.SignatureValid {
		fmt.Fprintf(stdout, "Bundle verification failed: signature invalid (%d files, manifest digests OK)\n", result.FileCount)
		return ui.ErrViolationsFound
	}

	if result.Signed && keyPath == "" {
		fmt.Fprintf(stdout, "Bundle manifest verified (%d files). Bundle is signed but no --public-key provided; signature not checked.\n", result.FileCount)
		return nil
	}

	if result.Signed {
		fmt.Fprintf(stdout, "Bundle verified: manifest digests and signature valid (%d files)\n", result.FileCount)
	} else {
		fmt.Fprintf(stdout, "Bundle verified: manifest digests valid, unsigned (%d files)\n", result.FileCount)
	}
	return nil
}
