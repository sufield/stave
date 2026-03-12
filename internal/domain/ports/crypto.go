package ports

import "github.com/sufield/stave/internal/domain/kernel"

// Verifier validates a cryptographic signature over data.
type Verifier interface {
	Verify(data []byte, sig kernel.Signature) error
}

// Hasher provides deterministic hashing operations for domain identifiers.
type Hasher interface {
	// HashDelimited computes a hex digest of parts joined by sep.
	HashDelimited(parts []string, sep byte) kernel.Digest
	// StableID returns a prefixed, deterministic identifier derived from input.
	StableID(prefix, input string) string
}
