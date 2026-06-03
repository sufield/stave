// CLI ONE-SHOT USE ONLY. The bundle loader below spawns a reader
// goroutine that cannot be interrupted on ctx cancellation — Go's
// stdlib offers no portable mechanism to unblock a pending Read on a
// regular file descriptor (no SetReadDeadline on *os.File, no
// shutdown(2) equivalent). When ctx fires before fsutil.ReadFileLimited
// returns, LoadBundle returns ctx.Err() promptly but the goroutine
// stays blocked on the syscall until the OS returns control —
// typically when the read completes naturally on the underlying
// filesystem.
//
// For a single CLI invocation, process death reaps the goroutine.
// For a long-running daemon, watcher, or server the goroutines
// accumulate per invocation and the process leaks descriptors and
// heap. Daemon callers must wrap their inbound context via
// DaemonContext so the runtime guard rejects the call rather than
// leaking; LoadBundleSync is the deadline-free synchronous variant
// for callers that have already committed to a process-blocking
// load and would rather skip the goroutine spawn.
//
// LONG-TERM FIX: when Go exposes context.AfterFunc-driven cancellation
// for blocking syscalls (or we introduce a deadline-capable file-fd
// wrapper), replace the spawned goroutine with a directly-cancellable
// reader. Until then the leak is a known cost of the read pattern.
package observations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// BundleLoader implements appcontracts.SnapshotBundleLoader for the
// single-file multi-snapshot observation bundle format. Distinct from
// ObservationLoader (directory of files) because bundles skip per-file
// schema validation — see ParseBundle for why.
type BundleLoader struct{}

// NewBundleLoader returns the standard bundle loader.
func NewBundleLoader() *BundleLoader { return &BundleLoader{} }

var _ appcontracts.SnapshotBundleLoader = (*BundleLoader)(nil)

// DAEMON-UNSAFE: LoadBundle spawns a reader goroutine that cannot be
// interrupted on ctx.Done() — Go's runtime cannot abort a blocked
// disk read on a non-deadline-capable file descriptor, so the
// goroutine outlives this call until the OS returns control. CLI
// one-shot use only; long-running daemons must wrap their inbound
// context with DaemonContext so the runtime guard below fails fast
// instead of leaking a goroutine per invocation.
//
// LoadBundle reads and parses a bundle file. ctx is honoured around
// the blocking disk read so a long-stalled read on a network mount
// or a paused filesystem can be interrupted by the caller cancelling
// the context. The previous shape ignored ctx; a stuck call to
// fsutil.ReadFileLimited would hang the runner with no recourse.
func (BundleLoader) LoadBundle(ctx context.Context, path string) ([]asset.Snapshot, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("load bundle: %w", err)
	}
	if isDaemonContext(ctx) {
		return nil, ErrDaemonUnsafe
	}
	type result struct {
		data []asset.Snapshot
		err  error
	}
	done := make(chan result, 1)
	// KNOWN GO LIMITATION: the disk read here cannot be interrupted
	// by ctx cancellation — file descriptors do not support
	// SetReadDeadline. The goroutine outlives this call when ctx
	// fires first. CLI one-shot use only; daemon callers must own
	// the read with a deadline-capable fd.
	go func() {
		snaps, err := LoadBundle(path)
		done <- result{snaps, err}
	}()
	select {
	case <-ctx.Done():
		// LEAK NOTE: the read goroutine outlives this call when ctx
		// is cancelled before fsutil.ReadFileLimited returns. Go
		// cannot interrupt a blocked read on a non-deadline-capable
		// fd (the disk read here), so the goroutine remains parked
		// on the syscall until the OS returns control —
		// typically when the read completes naturally. The
		// channel send is buffered (capacity 1) so the goroutine's
		// eventual write does not deadlock, but the goroutine
		// itself is genuinely leaked for the duration of the read.
		//
		// Acceptable for one-shot CLI invocations. Long-lived
		// daemons should wrap the path in something that supports
		// SetReadDeadline (a *net.Conn-style adapter) or close the
		// underlying fd from a sibling goroutine on ctx
		// cancellation.
		//
		// Bookkeeping: bump the package-level counter so daemon
		// operators or stress-test harnesses inspecting
		// LeakedReadGoroutines() see ctx-cancelled bundle reads
		// reflected in the running total.
		recordLeakedReadGoroutine()
		return nil, fmt.Errorf("load bundle: %w", ctx.Err())
	case r := <-done:
		return r.data, r.err
	}
}

// ObservationBundle represents a bundled observations file containing multiple snapshots.
type ObservationBundle struct {
	SchemaVersion kernel.Schema    `json:"schema_version"`
	Snapshots     []asset.Snapshot `json:"snapshots"`
}

// ParseBundle unmarshals observation bundle JSON from raw bytes
// and applies minimum-shape validation: the top-level
// `snapshots` array must be present and non-empty, and every
// contained snapshot must carry a non-zero `captured_at`
// timestamp.
//
// Why bundle entries are NOT schema-validated against the
// obs.v0.1 single-file schema: the obs.v0.1 schema requires
// `schema_version`, `captured_at`, and `assets` at the top
// level. Bundle entries omit `schema_version` (it's hoisted to
// the bundle wrapper), so applying the single-file schema would
// reject every legitimate bundle. The validation contract is
// instead carried by the type-system (ObservationBundle field
// definitions) and the explicit captured_at + non-empty
// snapshots checks below. Single-file intake (loader_core.go)
// runs the full schema validator because each file is itself a
// complete obs.v0.1 document.
//
// Standard directory loading runs equivalent shape checks via
// ObservationLoader.process; bundle loading must match.
func ParseBundle(data []byte) ([]asset.Snapshot, error) {
	var bundle ObservationBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("parse observations JSON: %w", err)
	}
	if len(bundle.Snapshots) == 0 {
		return nil, errors.New("observation bundle contains no snapshots (expected a top-level `snapshots` array)")
	}
	for i := range bundle.Snapshots {
		if bundle.Snapshots[i].CapturedAt.IsZero() {
			return nil, fmt.Errorf("observation bundle snapshot %d is missing required `captured_at` timestamp", i)
		}
		// Mirror loader_core.go: bundle and directory loaders must
		// produce snapshots with the same shape, otherwise predicates
		// that depend on type-coerced fields (asset.ID, kernel.AssetType)
		// silently behave differently between the two intake paths.
		if err := normalizeSnapshotTypes(&bundle.Snapshots[i]); err != nil {
			return nil, fmt.Errorf("normalize snapshot %d: %w", i, err)
		}
	}
	return bundle.Snapshots, nil
}

// LoadBundle reads and unmarshals an observation bundle from the given path.
func LoadBundle(path string) ([]asset.Snapshot, error) {
	data, err := fsutil.ReadFileLimited(path)
	if err != nil {
		return nil, fmt.Errorf("read observations file: %w", err)
	}
	return ParseBundle(data)
}
