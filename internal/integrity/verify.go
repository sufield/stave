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
		return fmt.Errorf("%w: no hashes provided for verification", ErrIntegrityViolation)
	}

	for name, expected := range m.Files {
		actual, ok := v.ActualHashes.Files[name]
		if !ok {
			return fmt.Errorf("%w: missing required file %s", ErrIntegrityViolation, name)
		}
		if actual != expected {
			return fmt.Errorf("%w: hash mismatch for %s (expected %s, got %s)", ErrIntegrityViolation, name, expected, actual)
		}
	}

	// If counts differ, at least one actual file isn't in the manifest.
	// The first loop already confirmed every manifest file exists in actual,
	// so a count mismatch means extra files — find one for reporting.
	if len(v.ActualHashes.Files) != len(m.Files) {
		for name := range v.ActualHashes.Files {
			if _, ok := m.Files[name]; !ok {
				return fmt.Errorf("%w: untrusted file %s found in directory", ErrIntegrityViolation, name)
			}
		}
	}

	if v.ActualHashes.Overall != m.Overall {
		return fmt.Errorf("%w: overall manifest hash mismatch (expected %s, got %s)", ErrIntegrityViolation, m.Overall, v.ActualHashes.Overall)
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
