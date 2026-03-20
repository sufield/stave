package identity

import (
	"slices"

	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// HashString returns the SHA-256 hex digest of s.
func HashString(s string) string {
	return string(platformcrypto.HashBytes([]byte(s)))
}

// HashStrings returns the SHA-256 hex digest of the sorted, newline-delimited
// concatenation of strs. Returns "" for empty input.
func HashStrings(strs []string) string {
	if len(strs) == 0 {
		return ""
	}
	sorted := slices.Clone(strs)
	slices.Sort(sorted)
	return string(platformcrypto.HashDelimited(sorted, '\n'))
}
