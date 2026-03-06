package integrity

import (
	"encoding/json"
	"fmt"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/platform/crypto"
)

// Validator compares actual input hashes against a manifest.
type Validator struct {
	ActualHashes *evaluation.InputHashes
}

// Verify checks that actual hashes match the manifest exactly:
// no missing files, no extra files, no mismatched hashes.
func (v *Validator) Verify(m Manifest) error {
	if v.ActualHashes == nil {
		return fmt.Errorf("no hashes provided for verification")
	}

	for name, expected := range m.Files {
		actual, ok := v.ActualHashes.Files[name]
		if !ok {
			return fmt.Errorf("integrity error: missing required file %s", name)
		}
		if actual != expected {
			return fmt.Errorf("integrity error: hash mismatch for %s (expected %s, got %s)", name, expected, actual)
		}
	}

	for name := range v.ActualHashes.Files {
		if _, ok := m.Files[name]; !ok {
			return fmt.Errorf("integrity error: untrusted file %s found in directory", name)
		}
	}

	if v.ActualHashes.Overall != m.Overall {
		return fmt.Errorf("integrity error: overall manifest hash mismatch (expected %s, got %s)", m.Overall, v.ActualHashes.Overall)
	}

	return nil
}

// UnmarshalSigned parses a signed manifest and verifies its signature.
func UnmarshalSigned(data []byte, pubKeyPEM []byte) (Manifest, error) {
	var signed SignedManifest
	if err := json.Unmarshal(data, &signed); err != nil {
		return Manifest{}, fmt.Errorf("parse signed integrity manifest: %w", err)
	}

	publicKey, err := crypto.ParsePublicKeyPEM(pubKeyPEM)
	if err != nil {
		return Manifest{}, fmt.Errorf("parse integrity public key: unsupported key encoding; expected PEM public key: %w", err)
	}

	verifier := &crypto.Ed25519Verifier{PublicKey: publicKey}
	if err = VerifySignedManifest(signed, verifier); err != nil {
		return Manifest{}, fmt.Errorf("integrity check failed: %w", err)
	}

	return signed.Manifest, nil
}
