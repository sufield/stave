package eval

import (
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
)

// ConfigureIntegrityCheck sets manifest verification on the loader.
// Returns an error if the loader does not support integrity checking,
// preventing silent misconfiguration.
func ConfigureIntegrityCheck(loader appcontracts.ObservationRepository, manifestPath, publicKeyPath string) error {
	if manifestPath == "" {
		return nil
	}
	cfg, ok := loader.(appcontracts.IntegrityCheckConfigurer)
	if !ok {
		return fmt.Errorf("observation loader %T does not support integrity verification", loader)
	}
	cfg.ConfigureIntegrityCheck(manifestPath, publicKeyPath)
	return nil
}
