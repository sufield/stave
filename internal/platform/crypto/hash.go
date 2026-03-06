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

// HashDelimited computes the SHA-256 hex digest of parts joined by sep.
// Each part is followed by sep (e.g. "a\nb\n" for sep='\n').
func HashDelimited(parts []string, sep byte) string {
	h := sha256.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{sep})
	}
	return hex.EncodeToString(h.Sum(nil))
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
