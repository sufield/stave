package ports

import "github.com/sufield/stave/internal/core/kernel"

// Verifier defines the capability to validate cryptographic signatures
// against raw data, ensuring authenticity and integrity.
type Verifier interface {
	Verify(data []byte, sig kernel.Signature) error
}

// Digester provides deterministic content digests for auditing
// and tracking changes in domain entities.
type Digester interface {
	// Digest computes a unique, stable summary for the provided components.
	Digest(components []string, sep byte) kernel.Digest
}

// IdentityGenerator produces stable, deterministic identifiers used to
// track entities (like remediation plans) across different evaluation runs.
type IdentityGenerator interface {
	// GenerateID creates a stable string ID by combining a prefix with unique data.
	GenerateID(prefix string, components ...string) string
}
