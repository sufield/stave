package eval

import "errors"

// Sentinel errors for evaluation intent checks.
var (
	// ErrNoControls is returned when the controls directory contains no valid control files.
	ErrNoControls = errors.New("no controls found")

	// ErrNoSnapshots is returned when the observations directory contains no valid snapshots.
	ErrNoSnapshots = errors.New("no snapshots found")

	// ErrSourceTypeMissing is returned when a snapshot lacks generated_by.source_type.
	ErrSourceTypeMissing = errors.New("source_type missing")

	// ErrSourceTypeUnsupported is returned when a snapshot has an unrecognized source_type.
	ErrSourceTypeUnsupported = errors.New("source_type unsupported")
)
