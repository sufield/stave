// Package attest implements the 'stave attest' command group for
// snapshot tamper detection via Ed25519 signatures.
package attest

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	appatt "github.com/sufield/stave/internal/app/attest"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
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
	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("key")

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
	_ = cmd.MarkFlagRequired("snapshot")
	_ = cmd.MarkFlagRequired("key")

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
	// Load private key.
	keyData, err := fsutil.ReadFileLimited(keyPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read private key: %w", err)}
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return &ui.UserError{Err: fmt.Errorf("no PEM block found in %s", keyPath)}
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse private key: %w", err)}
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return &ui.UserError{Err: errors.New("key is not Ed25519")}
	}

	// Load snapshot and parse assets.
	snapData, err := fsutil.ReadFileLimited(snapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}
	var snapshot struct {
		SchemaVersion string               `json:"schema_version"`
		CapturedAt    time.Time            `json:"captured_at"`
		Source        asset.SnapshotSource `json:"source"`
		Assets        []asset.Asset        `json:"assets"`
	}
	if unmarshalErr := json.Unmarshal(snapData, &snapshot); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse snapshot: %w", unmarshalErr)}
	}

	// Sign assets.
	hostname, _ := os.Hostname()
	attestation, err := appatt.SignAssets(snapshot.Assets, privateKey, hostname, "stave-cli", time.Now().UTC())
	if err != nil {
		return fmt.Errorf("sign assets: %w", err)
	}
	if keyID != "" {
		attestation.PublicKeyFingerprint = keyID
	}

	attested := appatt.AttestedSnapshot{
		SchemaVersion: snapshot.SchemaVersion,
		CapturedAt:    snapshot.CapturedAt,
		Source:        snapshot.Source,
		Attestation:   attestation,
		Assets:        snapshot.Assets,
	}

	return cmdutil.WriteTo(stdout, outPath, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(attested)
	})
}

func runVerify(stdout io.Writer, snapshotPath, keyPath string) error {
	// Load public key.
	keyData, err := fsutil.ReadFileLimited(keyPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read public key: %w", err)}
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return &ui.UserError{Err: fmt.Errorf("no PEM block found in %s", keyPath)}
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse public key: %w", err)}
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return &ui.UserError{Err: errors.New("key is not Ed25519")}
	}

	// Load and parse attested snapshot.
	snapData, err := fsutil.ReadFileLimited(snapshotPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read snapshot: %w", err)}
	}
	var attested appatt.AttestedSnapshot
	if unmarshalErr := json.Unmarshal(snapData, &attested); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse attested snapshot: %w", unmarshalErr)}
	}

	if verifyErr := appatt.VerifyAssets(attested.Assets, attested.Attestation, publicKey); verifyErr != nil {
		return ui.ErrViolationsFound
	}

	fmt.Fprintln(stdout, "Attestation verified: assets have not been tampered with")
	return nil
}

func runKeygen(stdout io.Writer, outPrefix string) error {
	pub, priv, err := appatt.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}

	// Marshal private key.
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	})

	// Marshal public key.
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	privPath := outPrefix + ".pem"
	pubPath := outPrefix + ".pub"

	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		return fmt.Errorf("write private key: %w", err)
	}
	if err := os.WriteFile(pubPath, pubPEM, 0o644); err != nil { //nolint:gosec // public key
		return fmt.Errorf("write public key: %w", err)
	}

	fmt.Fprintf(stdout, "Generated Ed25519 key pair:\n  Private: %s\n  Public:  %s\n", privPath, pubPath)
	return nil
}
