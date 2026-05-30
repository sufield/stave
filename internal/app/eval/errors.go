package eval

import "errors"

// Sentinel errors for evaluation intent checks.
var (
	// ErrNoControls is returned when the controls directory contains no valid control files.
	ErrNoControls = errors.New("no controls found")

	// ErrNoSnapshots is returned when the observations directory contains no valid snapshots.
	ErrNoSnapshots = errors.New("no snapshots found")
)
