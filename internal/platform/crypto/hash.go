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

// shortTokenBytes is the truncation length (in bytes) used for
// ShortToken / StableID outputs. 8 bytes = 64 bits of entropy, which
// keeps the birthday-collision probability ≈3e-8 at one million
// sanitized identifiers — comfortably safe for any token volume Stave
// processes. Encoded as 2*shortTokenBytes hex chars.
const shortTokenBytes = 8

// HashBytes returns the SHA-256 hex digest of data.
func HashBytes(data []byte) kernel.Digest {
	sum := sha256.Sum256(data)
	return kernel.Digest(hex.EncodeToString(sum[:]))
}

// ShortToken returns a deterministic 16-hex-char token (first 8 bytes
// of SHA-256). 32 bits of token entropy was below the threshold where
// birthday collisions are likely on large sanitized output corpora —
// at 1M sanitized identifiers the collision probability under 32-bit
// truncation was ≈12%; at 64 bits it drops to ≈3e-8, comfortably
// safe for any token volume Stave realistically processes.
func ShortToken(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:shortTokenBytes])
}

// StableID returns a prefixed, deterministic 16-hex-char identifier (first 8 bytes of SHA-256).
// Use this for domain identifiers that must be stable across runs (e.g., fix plan IDs).
func StableID(prefix, input string) string {
	sum := sha256.Sum256([]byte(input))
	return prefix + hex.EncodeToString(sum[:shortTokenBytes])
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
