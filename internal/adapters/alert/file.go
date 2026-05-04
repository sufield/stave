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
		if openedNow {
			// Close the descriptor we just acquired — caller will
			// never reach Close() if this Emit returns an error,
			// and the next attempt should re-open cleanly.
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
	_, err = s.f.Write(data)
	return err
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
