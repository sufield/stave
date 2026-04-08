package kernel

import "fmt"

const sha256HexLen = 64 // hex.EncodedLen(32)

// Digest represents a hex-encoded cryptographic hash (typically SHA-256).
type Digest string

// NewDigest returns a validated Digest. The raw value must be a 64-character
// lowercase hex string (SHA-256). Use this at trust boundaries where hash
// values enter the system from external sources (manifests, config files).
func NewDigest(raw string) (Digest, error) {
	if len(raw) != sha256HexLen {
		return "", fmt.Errorf("invalid digest length: want %d, got %d", sha256HexLen, len(raw))
	}
	if !isLowerHex(raw) {
		return "", fmt.Errorf("invalid digest %q: must be lowercase hex", raw)
	}
	return Digest(raw), nil
}

func (d Digest) String() string { return string(d) }

// UnmarshalText implements encoding.TextUnmarshaler. Validates that the
// digest is a well-formed 64-character lowercase hex string when
// deserialized from JSON or YAML (trust boundary for external artifacts).
func (d *Digest) UnmarshalText(text []byte) error {
	s := string(text)
	if s == "" {
		*d = ""
		return nil
	}
	v, err := NewDigest(s)
	if err != nil {
		return err
	}
	*d = v
	return nil
}

// IsValid reports whether d is a well-formed, lowercase, 64-character hex string.
func (d Digest) IsValid() bool {
	if len(d) != sha256HexLen {
		return false
	}
	return isLowerHex(string(d))
}

// Signature represents a hex-encoded cryptographic signature.
type Signature string

func (s Signature) String() string { return string(s) }

// IsValid reports whether s is a non-empty, even-length, lowercase hex string.
func (s Signature) IsValid() bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	return isLowerHex(string(s))
}

// isLowerHex checks if a string consists only of decimal digits and lowercase a-f.
func isLowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		// Standard hex check: 0-9 or a-f
		if c < '0' || (c > '9' && c < 'a') || c > 'f' {
			return false
		}
	}
	return true
}
