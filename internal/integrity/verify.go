package integrity

import (
	"encoding/json"
	"fmt"
	"slices"

	"github.com/sufield/stave/internal/core/evaluation"
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
			return fmt.Errorf("%w: %s", ErrMissingFile, name)
		}
		if actual != expected {
			return fmt.Errorf("%w: %s (expected %s, got %s)", ErrHashMismatch, name, expected, actual)
		}
	}

	// If counts differ, at least one actual file isn't in the manifest.
	// The first loop already confirmed every manifest file exists in actual,
	// so a count mismatch means extra files — collect and sort for
	// deterministic error output.
	if len(v.ActualHashes.Files) != len(m.Files) {
		var extra []string
		for name := range v.ActualHashes.Files {
			if _, ok := m.Files[name]; !ok {
				extra = append(extra, string(name))
			}
		}
		slices.Sort(extra)
		if len(extra) > 0 {
			return fmt.Errorf("%w: %s", ErrUntrustedFile, extra[0])
		}
	}

	if v.ActualHashes.Overall != m.Overall {
		return fmt.Errorf("%w: overall digest mismatch (expected %s, got %s)", ErrHashMismatch, m.Overall, v.ActualHashes.Overall)
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
		return Manifest{}, fmt.Errorf("parse integrity public key: %w", err)
	}

	verifier, err := crypto.NewVerifier(publicKey)
	if err != nil {
		return Manifest{}, fmt.Errorf("create verifier: %w", err)
	}
	if err = VerifySignedManifest(signed, verifier); err != nil {
		return Manifest{}, fmt.Errorf("%w: signature verification failed: %w", ErrIntegrityViolation, err)
	}

	return signed.Manifest, nil
}
