package manifest

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
)

func runSnapshotManifestKeygen(cmd *cobra.Command, privateKeyOutPath, publicKeyOutPath string) error {
	privateOut := filepath.Clean(privateKeyOutPath)
	publicOut := filepath.Clean(publicKeyOutPath)

	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	privatePKCS8, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("marshal private key: %w", err)
	}
	publicPKIX, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("marshal public key: %w", err)
	}
	privatePEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privatePKCS8})
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicPKIX})

	if err := writeFileAtomic(privateOut, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key %q: %w", privateOut, err)
	}
	if err := writeFileAtomic(publicOut, publicPEM, 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", publicOut, err)
	}

	if cmdutil.GetGlobalFlags(cmd).TextOutputEnabled() {
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote private key: %s\n", privateOut)
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote public key: %s\n", publicOut)
	}
	return nil
}
