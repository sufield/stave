package kernel

const sha256HexLen = 64 // hex.EncodedLen(32)

// Digest represents a hex-encoded cryptographic hash (typically SHA-256).
type Digest string

func (d Digest) String() string { return string(d) }

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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}
