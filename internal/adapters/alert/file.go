package alert

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sync"

	"github.com/sufield/stave/internal/core/ports"
)

// FileSink appends JSONL alerts to a file.
type FileSink struct {
	Path   string
	mu     sync.Mutex
	f      *os.File
	closed bool
}

var _ ports.AlertSink = (*FileSink)(nil)

// Emit appends a JSON line to the file.
//
// On marshal failure after a lazy open: close the just-opened file
// and clear s.f so the next Emit retries the open. The previous
// shape leaked the descriptor when Marshal failed because the
// caller would never reach Close() — only the lifecycle owner does.
func (s *FileSink) Emit(_ context.Context, a ports.WatchAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errSinkClosed
	}

	openedNow := false
	if s.f == nil {
		f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // user-specified path
		if err != nil {
			return fmt.Errorf("open alert file %s: %w", s.Path, err)
		}
		s.f = f
		openedNow = true
	}

	data, err := json.Marshal(a)
	if err != nil {
		// Close the file regardless of openedNow. A persistent
		// marshal failure (programming bug in WatchAlert
		// serialization, upstream type that doesn't round-trip)
		// would otherwise hold the FD open forever — never written
		// to, but never released. Close + clear s.f means the next
		// Emit lazily reopens cleanly. We do NOT set s.closed —
		// marshal failures are typically per-message rather than
		// terminal, so the sink stays usable for the next alert.
		_ = openedNow
		if s.f != nil {
			closeErr := s.f.Close()
			s.f = nil
			if closeErr != nil {
				return errors.Join(fmt.Errorf("marshal alert: %w", err),
					fmt.Errorf("close alert file %s: %w", s.Path, closeErr))
			}
		}
		return fmt.Errorf("marshal alert: %w", err)
	}
	data = append(data, '\n')
	if _, err = s.f.Write(data); err != nil {
		// Close + mark the sink failed before propagating. A write
		// failure (disk full, broken pipe, NFS stale handle) leaves
		// the file descriptor in an undefined state — leaving it
		// open would leak the FD across every subsequent Emit call,
		// and continuing to write through it could corrupt later
		// alert lines. Marking the sink closed is the conservative
		// choice: subsequent Emit returns errSinkClosed, signalling
		// to the caller that the alert pipeline needs explicit
		// reconfiguration rather than a silent retry.
		closeErr := s.f.Close()
		s.f = nil
		s.closed = true
		if closeErr != nil {
			return errors.Join(
				fmt.Errorf("write alert to file %s: %w", s.Path, err),
				fmt.Errorf("close alert file after write failure: %w", closeErr),
			)
		}
		return fmt.Errorf("write alert to file %s: %w", s.Path, err)
	}
	return nil
}

// Close flushes and closes the file. Subsequent Emit calls return errSinkClosed.
//
// Sync is called before Close so a process exit immediately after
// Close cannot lose buffered alert lines on filesystems where the
// page cache hasn't yet flushed (the same durability concern that
// drives fsync on rename in fsutil.crossFSCopy). The earlier shape
// dropped buffered writes silently.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.f == nil {
		return nil
	}
	syncErr := s.f.Sync()
	closeErr := s.f.Close()
	s.f = nil
	// errors.Join keeps both diagnostics visible when both fail —
	// previously closeErr was silently dropped on a Sync failure,
	// hiding a separate underlying problem (e.g. EBADF).
	return errors.Join(syncErr, closeErr)
}
