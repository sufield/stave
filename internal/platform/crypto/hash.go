// Package crypto provides centralized cryptographic primitives for the stave CLI.
package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// Compile-time interface guards.
var (
	_ ports.Digester          = (*sha256Hasher)(nil)
	_ ports.IdentityGenerator = (*sha256Hasher)(nil)
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
func NewHasher() *sha256Hasher { return &sha256Hasher{} }

// sha256Hasher implements ports.Digester and ports.IdentityGenerator using SHA-256.
type sha256Hasher struct{}

func (*sha256Hasher) Digest(components []string, sep byte) kernel.Digest {
	return HashDelimited(components, sep)
}

func (*sha256Hasher) GenerateID(prefix string, components ...string) string {
	return StableID(prefix, strings.Join(components, "|"))
}
