// Package observations also provides stdin-based snapshot loading.
//
// CLI ONE-SHOT USE ONLY. The stdin loaders below spawn a reader
// goroutine that cannot be interrupted by ctx cancellation — Go's
// stdlib io.Reader has no portable cross-platform mechanism to
// unblock a pending Read on os.Stdin (no SetReadDeadline, no
// shutdown(2) equivalent). When ctx fires, the loader returns
// promptly but the goroutine stays blocked on the underlying read
// until the OS produces input or EOF.
//
// For a CLI invocation that exits after a single assessment this is
// fine — process death reaps the goroutine. For a long-running
// daemon, server, or watch loop the goroutines accumulate per
// invocation and the process leaks descriptors and memory. Daemon
// callers must require a file path (load via the file-backed
// loader) rather than "-" / stdin.
package observations

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"

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

	// Intentional discard: process() returns (snap, hash, err) where
	// `hash` is platformcrypto.HashBytes(data) — the same digest the
	// caller (StdinObservationLoader.LoadSnapshots) already
	// computes from the same `data` bytes before invoking us. The
	// two hashes are identical by construction (same input, same
	// digest function), so dropping the inner one here keeps the
	// SnapshotReader interface narrow (single return, single error)
	// without losing information; the caller's recomputation is
	// the authoritative copy used in InputHashes.
	//
	// FOLLOW-UP: a future widening of SnapshotReader to return
	// (snap, hash, err) would let StdinObservationLoader skip the
	// upfront HashBytes call and reuse this one instead, removing
	// the duplicate hash work. Worth doing if the hash function
	// becomes more expensive than SHA-256.
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

// NewStdinObservationLoader builds a stdin-style observation loader.
//
// Two parameters with two different contracts:
//
//   - loader is an OPTIONAL extension point. A nil falls back to the
//     standard ObservationLoader, so callers that don't need a custom
//     parser implementation can pass nil and inherit the default.
//   - r is the REQUIRED data source. A nil reader is a terminal
//     wiring bug — the previous shape silently substituted an empty
//     reader, which presented as "no data" and masked the missing
//     pipe (a forgotten os.Stdin, a misrouted dependency injection).
//     Returning an error here forces the wiring bug to surface at
//     constructor time instead of producing a silent empty-result
//     run that looks like a legitimate clean evaluation.
func NewStdinObservationLoader(loader appcontracts.SnapshotReader, r io.Reader) (*StdinObservationLoader, error) {
	if loader == nil {
		loader = NewObservationLoader()
	}
	if r == nil {
		return nil, errors.New("observations: nil io.Reader provided to StdinObservationLoader")
	}
	return &StdinObservationLoader{
		loader: loader,
		reader: r,
	}, nil
}

// LoadSnapshots implements contracts.ObservationRepository by reading from stdin.
// The dir parameter is ignored; data is read from the configured reader.
// Stdin data is hashed so that integrity verification can proceed normally.
//
// Cancellation note: if ctx is cancelled while LimitedReadAll is blocked
// on a hung reader (most realistically a TTY or hung pipe), the caller
// returns immediately but the read goroutine continues until the
// underlying read unblocks or the process exits. The channel write is
// buffered (capacity 1) so the goroutine never blocks on send — when
// the read finally completes, the result is silently dropped and the
// goroutine exits cleanly. There is no permanent goroutine or memory
// leak; the only resource held is the read syscall itself, which is a
// caller-side responsibility (this loader does not own the reader and
// must not close it).
//
// Caller-side guidance: if you need bounded shutdown, the caller must
// either (a) close the underlying *os.File / pipe so the read syscall
// returns EOF, or (b) accept that the goroutine outlives ctx until the
// process exits. Without OS-specific tricks (SetReadDeadline on socket
// readers, signaling a process group on a pipe peer) Go cannot
// interrupt a blocked read syscall — wrapping a timeout context here
// is necessary but not sufficient.
func (s *StdinObservationLoader) LoadSnapshots(ctx context.Context, _ string) (appcontracts.LoadResult, error) {
	// DAEMON-UNSAFE: see the package doc and ErrDaemonUnsafe. The
	// reader goroutine below cannot be interrupted on ctx
	// cancellation, so a daemon caller invoking LoadSnapshots in a
	// loop would accumulate leaked goroutines. Reject the call up
	// front when the context was tagged via DaemonContext.
	if isDaemonContext(ctx) {
		return appcontracts.LoadResult{}, ErrDaemonUnsafe
	}
	// Read stdin with context cancellation support — if the upstream
	// process hangs, the context deadline will unblock the caller.
	//
	// LEAK NOTE: this goroutine outlives the LoadSnapshots call when
	// ctx is cancelled before the read completes. Go's runtime cannot
	// interrupt a blocked read on a non-deadline-capable file
	// descriptor (the os.Stdin path here), so the goroutine remains
	// parked on the syscall until the OS returns control — typically
	// at process exit, or when an upstream pipe peer closes. The
	// channel send is buffered (capacity 1) so the goroutine's
	// eventual write does not panic, but the goroutine itself is
	// genuinely leaked for the remainder of the LoadSnapshots
	// caller's lifetime.
	//
	// This is acceptable for a one-shot CLI invocation. Long-lived
	// daemons reusing this loader should: (a) wrap the underlying
	// reader in something that supports SetReadDeadline (a *net.Conn
	// adapter, for example), (b) close the reader from a sibling
	// goroutine on ctx cancellation, or (c) accept the leak as a
	// known cost of stdin-style ingestion.
	type readResult struct {
		data []byte
		err  error
	}
	// Buffered so the goroutine's send always succeeds even if the
	// caller has already returned via the ctx.Done() branch.
	ch := make(chan readResult, 1)
	// KNOWN GO LIMITATION: this goroutine blocks in
	// fsutil.LimitedReadAll until the OS delivers input or EOF on
	// stdin. ctx cancellation cannot interrupt that read on plain
	// os.Stdin — no SetReadDeadline. The goroutine leaks for the
	// remainder of the process when the caller takes the
	// ctx.Done() branch below. CLI one-shot use only. Daemons
	// must require a file path.
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
