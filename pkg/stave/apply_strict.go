package stave

import (
	"fmt"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/controls/pack"
)

// StrictPackIntegrityCheck validates the embedded control-pack registry
// against the embedded control filesystem (the `apply --strict` pre-check).
// Returns a plain error on mismatch; the command decorates it with a
// next-command hint and runs it under a progress span.
func StrictPackIntegrityCheck() error {
	reg, err := pack.NewEmbeddedRegistry()
	if err != nil {
		return fmt.Errorf("load default pack registry: %w", err)
	}
	if err := reg.ValidateStrict(ctlbuiltin.EmbeddedFS()); err != nil {
		return fmt.Errorf("strict integrity check: %w", err)
	}
	return nil
}
