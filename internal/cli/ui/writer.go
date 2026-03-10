// Writer manages CLI output streams with mode awareness.
// It enforces the standard streams contract: machine output (JSON) to stdout,
// human messages to stderr.
package ui

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// Writer manages output streams with mode awareness.
type Writer struct {
	stdout io.Writer
	stderr io.Writer
	mode   OutputFormat
	quiet  bool
	rt     *Runtime
}

// NewWriter creates a Writer.
// Passing nil streams defaults to os.Stdout/os.Stderr.
func NewWriter(stdout, stderr io.Writer, mode OutputFormat, quiet bool) *Writer {
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	rt := NewRuntime(stdout, stderr)
	rt.Quiet = quiet
	return &Writer{
		stdout: stdout,
		stderr: stderr,
		mode:   mode,
		quiet:  quiet,
		rt:     rt,
	}
}

// Stdout returns the appropriate stdout writer.
// In quiet mode with text output, returns io.Discard.
func (w *Writer) Stdout() io.Writer {
	if w.quiet && w.mode == OutputFormatText {
		return io.Discard
	}
	return w.stdout
}

// Stderr returns the appropriate stderr writer.
// In quiet mode, returns io.Discard.
func (w *Writer) Stderr() io.Writer {
	if w.quiet {
		return io.Discard
	}
	return w.stderr
}

// Mode returns the output format.
func (w *Writer) Mode() OutputFormat {
	return w.mode
}

// IsJSON returns true if output mode is JSON.
func (w *Writer) IsJSON() bool {
	return w.mode == OutputFormatJSON
}

// Envelope wraps data in the standard ok/data envelope for JSON output.
type Envelope struct {
	OK   bool `json:"ok"`
	Data any  `json:"data,omitempty"`
}

// WriteJSON writes data wrapped in the ok envelope to stdout.
func (w *Writer) WriteJSON(data any) error {
	return w.encode(Envelope{
		OK:   true,
		Data: data,
	})
}

// WriteJSONRaw writes data directly to stdout without envelope.
func (w *Writer) WriteJSONRaw(data any) error {
	return w.encode(data)
}

func (w *Writer) encode(v any) error {
	enc := json.NewEncoder(w.stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// Info writes a diagnostic info message to stderr.
func (w *Writer) Info(message string) {
	if w.quiet {
		return
	}
	label := SeverityLabel("info", message, w.stderr)
	if w.rt != nil {
		label = w.rt.SeverityLabel("info", message)
	}
	_, _ = fmt.Fprintln(w.Stderr(), label)
}
