package observations

import (
	"context"
	"fmt"
	"io"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// LoadSnapshotFromReader loads a single snapshot from an io.Reader.
// This supports reading from stdin when using "-" as the observations path.
func (l *ObservationLoader) LoadSnapshotFromReader(ctx context.Context, r io.Reader, sourceName string) (asset.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return asset.Snapshot{}, err
	}

	data, err := fsutil.LimitedReadAll(r, sourceName)
	if err != nil {
		return asset.Snapshot{}, fmt.Errorf("read from %s: %w", sourceName, err)
	}

	snap, _, err := l.process(data, sourceName)
	if err != nil {
		return asset.Snapshot{}, err
	}

	return snap, nil
}

// StdinObservationLoader wraps a SnapshotReader to read from stdin.
// It implements contracts.ObservationRepository for use with the apply command.
type StdinObservationLoader struct {
	loader appcontracts.SnapshotReader
	reader io.Reader
}

var _ appcontracts.ObservationRepository = (*StdinObservationLoader)(nil)

// NewStdinObservationLoader creates a loader that reads from the given reader.
func NewStdinObservationLoader(loader appcontracts.SnapshotReader, r io.Reader) *StdinObservationLoader {
	if loader == nil {
		loader = NewObservationLoader()
	}
	if r == nil {
		r = strings.NewReader("")
	}
	return &StdinObservationLoader{
		loader: loader,
		reader: r,
	}
}

// LoadSnapshots implements contracts.ObservationRepository by reading from stdin.
// The dir parameter is ignored; data is read from the configured reader.
// The returned LoadResult has nil Hashes because stdin doesn't support hashing.
func (s *StdinObservationLoader) LoadSnapshots(ctx context.Context, _ string) (appcontracts.LoadResult, error) {
	snap, err := s.loader.LoadSnapshotFromReader(ctx, s.reader, "stdin")
	if err != nil {
		return appcontracts.LoadResult{}, err
	}
	return appcontracts.LoadResult{Snapshots: []asset.Snapshot{snap}}, nil
}
