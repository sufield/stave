package stave

import (
	"context"
	"log/slog"

	"github.com/sufield/stave/pkg/stave/internal/validatecmd"
)

// ValidateContentContract runs the collector contract check against raw
// observation data (the --in single-file path). Returns rendered output
// and an exit-code sentinel.
func ValidateContentContract(data []byte, format string, fixHints bool) (ValidateProjectResult, error) {
	return validatecmd.ValidateContentContract(data, format, fixHints) //nolint:wrapcheck // engine wraps; preserve exit-code sentinels.
}

// ContractViolationCount loads observations from obsDir and returns the
// number of collector contract violations. Returns 0 on any error —
// callers use this for a non-blocking pre-flight warning.
func ContractViolationCount(ctx context.Context, obsDir string) int {
	n, err := validatecmd.ContractViolationCount(ctx, obsDir)
	if err != nil {
		slog.Debug("contract pre-flight skipped", "error", err)
		return 0
	}
	return n
}
