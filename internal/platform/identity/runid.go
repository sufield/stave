package identity

import (
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// RunIDLength is the length of the truncated run ID.
const RunIDLength = 12

// ComputeRunIDParts computes a deterministic run ID from any ordered parts.
// Formula: sha256(part1 + "\n" + part2 + "\n" + ... + partN + "\n")[:RunIDLength]
func ComputeRunIDParts(parts ...string) string {
	digest := string(platformcrypto.HashDelimited(parts, '\n'))
	if len(digest) > RunIDLength {
		return digest[:RunIDLength]
	}
	return digest
}
