package ports

import "github.com/sufield/stave/internal/domain/kernel"

// Verifier validates a cryptographic signature over data.
type Verifier interface {
	Verify(data []byte, sig kernel.Signature) error
}

// Hasher provides deterministic content hashing for domain aggregates.
type Hasher interface {
	// HashDelimited computes a hex digest of parts joined by sep.
	HashDelimited(parts []string, sep byte) kernel.Digest
}

// IdentityGenerator produces stable, deterministic identifiers for domain entities.
type IdentityGenerator interface {
	GenerateID(prefix, data string) string
}
