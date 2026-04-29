package alert

import (
	"context"
	"encoding/json"
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
func (s *FileSink) Emit(_ context.Context, a ports.WatchAlert) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return errSinkClosed
	}

	if s.f == nil {
		f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) //nolint:gosec // user-specified path
		if err != nil {
			return fmt.Errorf("open alert file %s: %w", s.Path, err)
		}
		s.f = f
	}

	data, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("marshal alert: %w", err)
	}
	data = append(data, '\n')
	_, err = s.f.Write(data)
	return err
}

// Close flushes and closes the file. Subsequent Emit calls return errSinkClosed.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	if s.f == nil {
		return nil
	}
	err := s.f.Close()
	s.f = nil
	return err
}
