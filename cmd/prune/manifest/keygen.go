package manifest

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/platform/crypto"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// KeygenConfig defines the parameters for generating a signing keypair.
type KeygenConfig struct {
	PrivateKeyPath string
	PublicKeyPath  string
	TextOutput     bool
	Stdout         io.Writer
}

// KeygenRunner handles Ed25519 keypair generation for manifest signing.
type KeygenRunner struct{}

// Run generates a new Ed25519 keypair and persists the keys to disk.
func (r *KeygenRunner) Run(cfg KeygenConfig) error {
	privatePEM, publicPEM, err := crypto.GenerateSigningKeyPair()
	if err != nil {
		return fmt.Errorf("generate keypair: %w", err)
	}

	if err := fsutil.WriteFileAtomic(cfg.PrivateKeyPath, privatePEM, 0o600); err != nil {
		return fmt.Errorf("write private key %q: %w", cfg.PrivateKeyPath, err)
	}
	if err := fsutil.WriteFileAtomic(cfg.PublicKeyPath, publicPEM, 0o644); err != nil {
		return fmt.Errorf("write public key %q: %w", cfg.PublicKeyPath, err)
	}

	if cfg.TextOutput {
		fmt.Fprintf(cfg.Stdout, "Wrote private key: %s\n", cfg.PrivateKeyPath)
		fmt.Fprintf(cfg.Stdout, "Wrote public key: %s\n", cfg.PublicKeyPath)
	}
	return nil
}
