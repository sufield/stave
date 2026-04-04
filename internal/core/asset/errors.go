package asset

import "errors"

// Sentinel errors for the asset package.
var (
	// ErrInsufficientSnapshots is returned when fewer than 2 snapshots are provided for delta computation.
	ErrInsufficientSnapshots = errors.New("insufficient snapshots")

	// ErrSnapshotsNotOrdered is returned when snapshots are not in chronological order.
	ErrSnapshotsNotOrdered = errors.New("snapshots are not chronologically ordered")

	// ErrZeroTimestamp is returned when a zero-value time is passed to RecordObservation.
	ErrZeroTimestamp = errors.New("record observation: time must not be zero")
)
