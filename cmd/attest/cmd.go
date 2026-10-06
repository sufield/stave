// Package attest implements the 'stave attest' command group for
// snapshot tamper detection via Ed25519 signatures.
package attest

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/stave"
)

// NewCmd constructs the attest command with sign, verify, and keygen subcommands.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Snapshot tamper detection via Ed25519 signatures",
		Long: `Sign, verify, and manage keys for snapshot attestation.

Subcommands:
  sign     Sign a snapshot's assets with an Ed25519 private key
  verify   Verify an attested snapshot against a public key
  keygen   Generate a new Ed25519 key pair

Exit Codes:
  0   Operation succeeded
  2   Invalid input
  3   Verification failed`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.AddCommand(newSignCmd())
	cmd.AddCommand(newVerifyCmd())
	cmd.AddCommand(newKeygenCmd())

	return cmd
}

func newSignCmd() *cobra.Command {
	var snapshotPath, keyPath, keyID, outPath string

	cmd := &cobra.Command{
		Use:   "sign",
		Short: "Sign a snapshot's assets with an Ed25519 private key",
		Long: `Sign a snapshot's assets array with an Ed25519 private key and
produce an attested snapshot with an inline attestation field.

Inputs:
  --snapshot PATH   Path to observation snapshot JSON (required)
  --key PATH        Path to Ed25519 private key PEM (required)
  --key-id STRING   Key identifier embedded in signature
  --out PATH        Write attested snapshot to file (default: stdout)

Outputs:
  stdout            Attested snapshot JSON (unless --out is set)

Exit Codes:
  0   Signing succeeded
  2   Invalid input`,
		Example: `  stave attest sign --snapshot obs.json --key private.pem
  stave attest sign --snapshot obs.json --key private.pem --out attested.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSign(cmd.OutOrStdout(), snapshotPath, keyPath, keyID, outPath)
		},
	}

	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "Path to snapshot JSON (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to Ed25519 private key PEM (required)")
	cmd.Flags().StringVar(&keyID, "key-id", "", "Key identifier for the signature")
	cmd.Flags().StringVar(&outPath, "out", "", "Write attested snapshot to file")
	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "key")

	return cmd
}

func newVerifyCmd() *cobra.Command {
	var snapshotPath, keyPath string

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify an attested snapshot against a public key",
		Long: `Verify an attested snapshot's inline attestation against an Ed25519
public key. Confirms that the assets array has not been tampered with
since signing.

Inputs:
  --snapshot PATH   Path to attested snapshot JSON (required)
  --key PATH        Path to Ed25519 public key PEM (required)

Outputs:
  stdout            Verification result message

Exit Codes:
  0   Verification passed
  2   Invalid input
  3   Verification failed`,
		Example:       `  stave attest verify --snapshot attested.json --key public.pem`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runVerify(cmd.OutOrStdout(), snapshotPath, keyPath)
		},
	}

	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "Path to attested snapshot JSON (required)")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to Ed25519 public key PEM (required)")
	cliflags.MustMarkRequired(cmd, "snapshot")
	cliflags.MustMarkRequired(cmd, "key")

	return cmd
}

func newKeygenCmd() *cobra.Command {
	var outPrefix string

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate a new Ed25519 key pair for snapshot attestation",
		Long: `Generate a new Ed25519 key pair for snapshot attestation and write
the private and public keys to PEM files.

Inputs:
  --out STRING   Output file prefix (default: stave-attest)

Outputs:
  <prefix>.pem   Ed25519 private key (mode 0600)
  <prefix>.pub   Ed25519 public key (mode 0644)

Exit Codes:
  0   Key pair generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave attest keygen --out stave-attest
  # produces stave-attest.pem (private) and stave-attest.pub (public)`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runKeygen(cmd.OutOrStdout(), outPrefix)
		},
	}

	cmd.Flags().StringVar(&outPrefix, "out", "stave-attest", "Output file prefix (produces <prefix>.pem and <prefix>.pub)")

	return cmd
}

func runSign(stdout io.Writer, snapshotPath, keyPath, keyID, outPath string) error {
	privateKey, err := stave.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	snapData, err := fsutil.ReadFileLimited(snapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}

	hostname, hostErr := os.Hostname()
	if hostErr != nil {
		fmt.Fprintf(os.Stderr,
			"Warning: os.Hostname failed (%v); recording attestation host as \"unknown\"\n", hostErr)
		hostname = "unknown"
	}

	out, err := stave.SignSnapshot(snapData, privateKey, keyID, hostname, time.Now().UTC())
	if err != nil {
		return &ui.UserError{Err: err}
	}

	if err := cmdutil.WriteTo(stdout, outPath, func(w io.Writer) error {
		_, werr := w.Write(out)
		return werr
	}); err != nil {
		return fmt.Errorf("write attested snapshot: %w", err)
	}
	return nil
}

func runVerify(stdout io.Writer, snapshotPath, keyPath string) error {
	publicKey, err := stave.LoadPublicKeyPEM(keyPath)
	if err != nil {
		return &ui.UserError{Err: err}
	}

	snapData, err := fsutil.ReadFileLimited(snapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}

	verified, err := stave.VerifySnapshot(snapData, publicKey)
	if err != nil {
		return &ui.UserError{Err: err}
	}
	if !verified {
		fmt.Fprintln(stdout, "Attestation failed: assets have been tampered with or key does not match")
		return ui.ErrViolationsFound
	}

	fmt.Fprintln(stdout, "Attestation verified: assets have not been tampered with")
	return nil
}

func runKeygen(stdout io.Writer, outPrefix string) error {
	pub, priv, err := stave.GenerateAttestKeyPair()
	if err != nil {
		return err //nolint:wrapcheck // stave.GenerateAttestKeyPair already wraps ("generate key pair")
	}

	privPath, pubPath, err := stave.SaveAttestKeyPair(outPrefix, pub, priv)
	if err != nil {
		return fmt.Errorf("failed to save attest key pair: %w", err)
	}

	fmt.Fprintf(stdout, "Generated Ed25519 key pair:\n  Private: %s\n  Public:  %s\n", privPath, pubPath)
	return nil
}
