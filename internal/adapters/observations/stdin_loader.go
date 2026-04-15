package observations

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"strings"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	platformcrypto "github.com/sufield/stave/internal/platform/crypto"
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
// Stdin data is hashed so that integrity verification can proceed normally.
func (s *StdinObservationLoader) LoadSnapshots(ctx context.Context, _ string) (appcontracts.LoadResult, error) {
	// Read stdin with context cancellation support — if the upstream
	// process hangs, the context deadline will unblock the caller.
	type readResult struct {
		data []byte
		err  error
	}
	ch := make(chan readResult, 1)
	go func() {
		data, err := fsutil.LimitedReadAll(s.reader, "stdin")
		ch <- readResult{data, err}
	}()

	var data []byte
	select {
	case <-ctx.Done():
		return appcontracts.LoadResult{}, fmt.Errorf("stdin read cancelled: %w", ctx.Err())
	case res := <-ch:
		if res.err != nil {
			return appcontracts.LoadResult{}, fmt.Errorf("read from stdin: %w", res.err)
		}
		data = res.data
	}
	hash := platformcrypto.HashBytes(data)

	snap, err := s.loader.LoadSnapshotFromReader(ctx, bytes.NewReader(data), "stdin")
	if err != nil {
		return appcontracts.LoadResult{}, err
	}

	hashes := &evaluation.InputHashes{
		Files:   map[evaluation.FilePath]kernel.Digest{"stdin": hash},
		Overall: hash,
	}
	return appcontracts.LoadResult{Snapshots: []asset.Snapshot{snap}, Hashes: hashes}, nil
}
