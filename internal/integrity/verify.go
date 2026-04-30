package integrity

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/platform/crypto"
)

// Validator compares actual input hashes against a manifest.
type Validator struct {
	ActualHashes *evaluation.InputHashes
}

// Verify checks that actual hashes match the manifest exactly:
// no missing files, no extra files, no mismatched hashes.
//
// For unsigned manifests (those that did not flow through
// UnmarshalSigned, where signature verification establishes the
// manifest's internal consistency), an empty Overall is rejected
// outright: without an aggregate digest there is no check that the
// per-file map itself has not been swapped wholesale. The previous
// "per-file only" mode let an attacker substitute a manifest whose
// per-file hashes match attacker-supplied content while Overall
// carries no constraint at all — so we now require every manifest
// reaching Verify to carry an Overall, and validate it for internal
// consistency before trusting the per-file string compare.
func (v *Validator) Verify(m Manifest) error {
	if v.ActualHashes == nil {
		return fmt.Errorf("%w: no hashes provided for verification", ErrIntegrityViolation)
	}
	if m.Overall == "" {
		return fmt.Errorf("%w: manifest is missing the overall aggregate digest; refusing to verify per-file hashes against an unbounded manifest", ErrIntegrityViolation)
	}
	if len(m.Files) == 0 {
		// An empty Files map paired with a non-empty Overall is a
		// malformed manifest: the Overall hashes "no files" while
		// the recipient has actual files to verify against. Reject
		// outright with the typed sentinel so callers can branch on
		// errors.Is(err, ErrEmptyManifest).
		return ErrEmptyManifest
	}
	if err := m.ValidateOverall(); err != nil {
		return fmt.Errorf("%w: %w", ErrIntegrityViolation, err)
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
		return fmt.Errorf("%w: %s", ErrUntrustedFile, strings.Join(extra, ", "))
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
