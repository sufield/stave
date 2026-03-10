package asset

import "errors"

// Sentinel errors for snapshot delta operations.
var (
	// ErrInsufficientSnapshots is returned when fewer than 2 snapshots are provided for delta computation.
	ErrInsufficientSnapshots = errors.New("insufficient snapshots")

	// ErrSnapshotsNotOrdered is returned when snapshots are not in chronological order.
	ErrSnapshotsNotOrdered = errors.New("snapshots are not chronologically ordered")
)
