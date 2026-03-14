package manifest

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runSnapshotManifestSign(cmd *cobra.Command, inFile, keyPath, outFile string) error {
	in := filepath.Clean(inFile)
	out := filepath.Clean(outFile)
	privateKeyPath := filepath.Clean(keyPath)

	manifestData, err := fsutil.ReadFileLimited(in)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", in, err)
	}

	var manifest integrity.Manifest
	if err = json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest %q: %w", in, err)
	}
	if err = manifest.ValidateOverall(); err != nil {
		return fmt.Errorf("invalid manifest %q: %w", in, err)
	}
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return fmt.Errorf("load private key %q: %w", privateKeyPath, err)
	}

	message, err := manifest.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("marshal manifest for signing: %w", err)
	}
	sig := platformcrypto.Sign(privateKey, message)

	signed := integrity.SignedManifest{
		Manifest:  manifest,
		Signature: sig,
	}
	signedData, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signed manifest: %w", err)
	}
	if err := fsutil.WriteFileAtomic(out, signedData, 0o600); err != nil {
		return fmt.Errorf("write signed manifest %q: %w", out, err)
	}

	if cmdutil.GetGlobalFlags(cmd).TextOutputEnabled() {
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote signed manifest: %s\n", out)
	}
	return nil
}

func loadPrivateKey(path string) (ed25519.PrivateKey, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}
	privateKey, err := platformcrypto.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("unsupported key encoding; expected PEM private key: %w", err)
	}
	return privateKey, nil
}
