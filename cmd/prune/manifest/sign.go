package manifest

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/integrity"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// SignConfig defines the parameters for signing a manifest.
type SignConfig struct {
	InPath         string
	PrivateKeyPath string
	OutPath        string
	TextOutput     bool
	Stdout         io.Writer
}

// SignRunner handles cryptographic signing of observation manifests.
type SignRunner struct{}

// Run loads an unsigned manifest and a private key, computes a signature,
// and persists the signed envelope.
func (r *SignRunner) Run(_ context.Context, cfg SignConfig) error {
	manifestData, err := fsutil.ReadFileLimited(cfg.InPath)
	if err != nil {
		return fmt.Errorf("read manifest %q: %w", cfg.InPath, err)
	}

	var manifest integrity.Manifest
	if err = json.Unmarshal(manifestData, &manifest); err != nil {
		return fmt.Errorf("parse manifest %q: %w", cfg.InPath, err)
	}
	if err = manifest.ValidateOverall(); err != nil {
		return fmt.Errorf("invalid manifest %q: %w", cfg.InPath, err)
	}

	signer, err := loadSigner(cfg.PrivateKeyPath)
	if err != nil {
		return fmt.Errorf("load private key %q: %w", cfg.PrivateKeyPath, err)
	}

	message, err := manifest.CanonicalBytes()
	if err != nil {
		return fmt.Errorf("marshal manifest for signing: %w", err)
	}
	sig, err := signer.Sign(message)
	if err != nil {
		return fmt.Errorf("sign manifest: %w", err)
	}

	signed := integrity.SignedManifest{
		Manifest:  manifest,
		Signature: sig,
	}
	signedData, err := json.MarshalIndent(signed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal signed manifest: %w", err)
	}
	if err := fsutil.WriteFileAtomic(cfg.OutPath, signedData, 0o600); err != nil {
		return fmt.Errorf("write signed manifest %q: %w", cfg.OutPath, err)
	}

	if cfg.TextOutput {
		fmt.Fprintf(cfg.Stdout, "Wrote signed manifest: %s\n", cfg.OutPath)
	}
	return nil
}

func loadSigner(path string) (platformcrypto.Signer, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, err
	}
	signer, err := platformcrypto.ParsePrivateKeyPEM(data)
	if err != nil {
		return nil, fmt.Errorf("unsupported key encoding; expected PEM private key: %w", err)
	}
	return signer, nil
}
