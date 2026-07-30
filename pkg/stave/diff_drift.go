package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/stave/internal/cmderr"
	"github.com/sufield/stave/pkg/stave/internal/driftdiff"
)

// ObservationDriftConfig parameterizes [DiffObservationDrift]. It mirrors the
// `stave snapshot diff` flags plus the global --sanitize / --path-mode
// settings.
type ObservationDriftConfig = driftdiff.Config

// ObservationDriftChangeTypes returns the valid --change-type filter values
// (for shell completion).
func ObservationDriftChangeTypes() []string { return driftdiff.ChangeTypeNames() }

// DiffObservationDrift loads the latest two snapshots in the configured
// observations directory, computes the asset-level drift, applies the
// requested change-type / asset-type / asset-id filter, sanitizes
// identifiers, and renders the delta as text or JSON — returning the
// rendered bytes. An invalid change-type or unknown format wraps
// [ErrInvalidInput] (exit 2); load/compute/render failures stay plain
// (exit 4). It is the library entry point behind `stave snapshot diff`
// (the command owns the progress span and quiet/output handling).
func DiffObservationDrift(ctx context.Context, cfg ObservationDriftConfig) ([]byte, error) {
	out, err := driftdiff.Run(ctx, cfg)
	if err != nil {
		var ie *cmderr.InputError
		if errors.As(err, &ie) {
			return nil, fmt.Errorf("%w: %w", ie.Err, ErrInvalidInput)
		}
		return nil, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return out, nil
}
