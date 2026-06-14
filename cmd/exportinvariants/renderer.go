package exportinvariants

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave export-controls`. The export has a single real format
// (json); the interface exists so new formats add an
// implementation here plus a factory case in NewRenderer rather
// than another inline `switch opts.Format` block.
//
// JSONRenderer delegates to encoding/json with the same indentation
// the pre-Renderer-pattern handler used, so the rendered bytes are
// byte-identical to the previous output.
type Renderer interface {
	Render(w io.Writer, out *stave.InvariantExport) error
}

// JSONRenderer encodes the export as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, out *stave.InvariantExport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode controls: %w", err)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// The format is normalized (lower-cased, trimmed) before dispatch;
// empty string maps to the json default. Unknown formats wrap
// stave.ErrInvalidInput so the CLI surface maps them to exit code 2
// — the same contract the previous validation switch enforced. The
// error keeps the original (un-normalized) format string in the
// message, matching the historical wording verbatim.
func NewRenderer(format string) (Renderer, error) {
	trimmed := strings.TrimSpace(format)
	if trimmed == "" || strings.EqualFold(trimmed, "json") {
		return JSONRenderer{}, nil
	}
	return nil, fmt.Errorf("--format must be json (got %q): %w", format, stave.ErrInvalidInput)
}
