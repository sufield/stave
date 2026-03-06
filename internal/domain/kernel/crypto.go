package kernel

import "encoding/hex"

// Digest is a hex-encoded cryptographic hash digest (currently SHA-256).
type Digest string

func (d Digest) String() string { return string(d) }

// IsValid reports whether d is a well-formed lowercase hex-encoded SHA-256 digest
// (exactly 64 hex characters).
func (d Digest) IsValid() bool {
	if len(d) != hex.EncodedLen(32) {
		return false
	}
	for i := range len(d) {
		c := d[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// Signature is a hex-encoded cryptographic signature.
type Signature string

func (s Signature) String() string { return string(s) }

// IsValid reports whether s is a non-empty, valid hex string with even length.
func (s Signature) IsValid() bool {
	if len(s) == 0 || len(s)%2 != 0 {
		return false
	}
	for i := range len(s) {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
