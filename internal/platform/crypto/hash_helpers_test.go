package crypto

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// HashReader returns the SHA-256 hex digest of data read from r.
func HashReader(r io.Reader) (kernel.Digest, error) {
	h := sha256.New()
	if _, err := io.Copy(h, r); err != nil {
		return "", fmt.Errorf("hash reader: %w", err)
	}
	return kernel.Digest(hex.EncodeToString(h.Sum(nil))), nil
}
