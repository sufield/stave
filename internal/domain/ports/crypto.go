package ports

import "github.com/sufield/stave/internal/domain/kernel"

// Verifier validates a cryptographic signature over data.
type Verifier interface {
	Verify(data []byte, sig kernel.Signature) error
}
