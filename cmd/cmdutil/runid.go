package cmdutil

import (
	"strings"

	"github.com/sufield/stave/internal/platform/identity"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/version"
)

// AttachRunID computes a deterministic run ID from input hashes and sets it on
// the default logger.
func AttachRunID(inputsHash, controlsHash string) {
	logger := logging.DefaultLogger()
	runID := identity.ComputeRunID(version.Version, strings.TrimSpace(inputsHash), strings.TrimSpace(controlsHash))
	logging.SetDefaultLogger(logging.WithRunID(logger, runID))
}
