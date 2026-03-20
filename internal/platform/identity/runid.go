package identity

import (
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
)

// RunIDLength is the length of the truncated run ID.
const RunIDLength = 12

// ComputeRunID computes a deterministic run ID from version and input hashes.
// Formula: sha256(version + "\n" + inputsHash + "\n" + controlsHash + "\n")[:12]
func ComputeRunID(version, inputsHash, controlsHash string) string {
	return ComputeRunIDParts(version, inputsHash, controlsHash)
}

// ComputeRunIDParts computes a deterministic run ID from any ordered parts.
// Formula: sha256(part1 + "\n" + part2 + "\n" + ... + partN + "\n")[:RunIDLength]
func ComputeRunIDParts(parts ...string) string {
	digest := string(platformcrypto.HashDelimited(parts, '\n'))
	if len(digest) > RunIDLength {
		return digest[:RunIDLength]
	}
	return digest
}
