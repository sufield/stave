// Package crypto provides centralized cryptographic primitives for the stave CLI.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"

	"github.com/sufield/stave/internal/domain/kernel"
)

// HashBytes returns the SHA-256 hex digest of data.
func HashBytes(data []byte) kernel.Digest {
	sum := sha256.Sum256(data)
	return kernel.Digest(hex.EncodeToString(sum[:]))
}

// ShortToken returns a deterministic 8-hex-char token (first 4 bytes of SHA-256).
func ShortToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:4])
}

// StableID returns a prefixed, deterministic 16-hex-char identifier (first 8 bytes of SHA-256).
// Use this for domain identifiers that must be stable across runs (e.g., fix plan IDs).
func StableID(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return prefix + hex.EncodeToString(sum[:8])
}

// HashDelimited computes the SHA-256 hex digest of parts joined by sep.
// Each part is followed by sep (e.g. "a\nb\n" for sep='\n').
func HashDelimited(parts []string, sep byte) kernel.Digest {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{sep})
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil)))
}

// NewHasher returns the default ports.Hasher implementation.
// This is the single point of change if the hashing algorithm is swapped.
func NewHasher() *sha256Hasher { return &sha256Hasher{} }

// sha256Hasher implements ports.Hasher using SHA-256.
type sha256Hasher struct{}

func (*sha256Hasher) HashDelimited(parts []string, sep byte) kernel.Digest {
	return HashDelimited(parts, sep)
}

func (*sha256Hasher) GenerateID(prefix, data string) string {
	return StableID(prefix, data)
}

// HashReader returns the SHA-256 hex digest of data read from r.
// It streams input into the hasher to avoid loading all bytes into memory.
func HashReader(r io.Reader) (kernel.Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", err
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil))), nil
}
