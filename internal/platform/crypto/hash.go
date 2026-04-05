// Package crypto provides centralized cryptographic primitives for the stave CLI.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
)

// Compile-time interface guards.
var (
	_ ports.Digester          = (*SHA256Hasher)(nil)
	_ ports.IdentityGenerator = (*SHA256Hasher)(nil)
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
// Uses io.WriteString to avoid per-part []byte allocations.
func HashDelimited(parts []string, sep byte) kernel.Digest {
	h := sha256.New()
	var sepBuf [1]byte
	sepBuf[0] = sep
	for _, p := range parts {
		io.WriteString(h, p) //nolint:errcheck,gosec // hash.Write never returns an error
		h.Write(sepBuf[:])
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil)))
}

// NewHasher returns the default ports.Digester and ports.IdentityGenerator
// implementation. This is the single point of change if the hashing
// algorithm is swapped.
func NewHasher() *SHA256Hasher { return &SHA256Hasher{} }

// SHA256Hasher implements ports.Digester and ports.IdentityGenerator using SHA-256.
type SHA256Hasher struct{}

// Digest hashes components with a delimiter byte separator.
func (*SHA256Hasher) Digest(components []string, sep byte) kernel.Digest {
	return HashDelimited(components, sep)
}

// GenerateID produces a stable identifier from a prefix and components.
func (*SHA256Hasher) GenerateID(prefix string, components ...string) string {
	return StableID(prefix, strings.Join(components, "|"))
}
