package runid

import (
	"log/slog"
	"strings"

	"github.com/sufield/stave/internal/platform/identity"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/version"
)

// GenerateRunID computes a deterministic ID based on the tool version
// and the hashes of the inputs (observations and controls).
func GenerateRunID(inputsHash, controlsHash string) string {
	return identity.ComputeRunIDParts(
		version.String,
		strings.TrimSpace(inputsHash),
		strings.TrimSpace(controlsHash),
	)
}

// SetupLoggingWithRunID computes a Run ID and returns a new logger
// decorated with that ID. This avoids mutating global logger state.
func SetupLoggingWithRunID(logger *slog.Logger, inputsHash, controlsHash string) *slog.Logger {
	runID := GenerateRunID(inputsHash, controlsHash)
	return logging.WithRunID(logger, runID)
}
