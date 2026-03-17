package logging

import (
	"io"
	"log/slog"
	"os"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// LogCloser wraps a logger with an optional closer for file handles.
type LogCloser struct {
	Logger *slog.Logger
	closer io.Closer
}

// Close closes the underlying writer.
func (lc *LogCloser) Close() error {
	return lc.closer.Close()
}

// NewLogger creates a new logger based on configuration.
// Returns a LogCloser that should be closed when done.
func NewLogger(cfg Config) (*LogCloser, error) {
	wc, err := openLogWriter(cfg)
	if err != nil {
		return nil, err
	}

	logger := slog.New(newHandler(cfg, wc))

	return &LogCloser{
		Logger: logger,
		closer: wc,
	}, nil
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func openLogWriter(cfg Config) (io.WriteCloser, error) {
	if cfg.LogFile == "" {
		return nopCloser{os.Stderr}, nil
	}
	return fsutil.SafeOpenAppend(cfg.LogFile, fsutil.WriteOptions{
		Perm:         0o644,
		AllowSymlink: cfg.AllowSymlink,
	})
}

func newHandler(cfg Config, out io.Writer) slog.Handler {
	opts := &slog.HandlerOptions{
		Level:       cfg.Level,
		ReplaceAttr: cfg.Scrub,
	}

	if cfg.Format == FormatJSON {
		return slog.NewJSONHandler(out, opts)
	}
	return slog.NewTextHandler(out, opts)
}
