package bisect

import (
	"fmt"
	"io"
	"log/slog"

	appbisect "github.com/sufield/stave/internal/app/bisect"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave bisect`. Concrete implementations delegate to
// jsonutil.WriteIndented / writeText so the rendered bytes are
// byte-identical to the pre-Renderer-pattern output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(stdout, stderr io.Writer, result appbisect.Result, logger *slog.Logger) error
}

// JSONRenderer encodes the bisect result as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(stdout, _ io.Writer, result appbisect.Result, _ *slog.Logger) error {
	if err := jsonutil.WriteIndented(stdout, result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// TextRenderer writes the default human-readable transition report.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(stdout, stderr io.Writer, result appbisect.Result, logger *slog.Logger) error {
	return writeText(stdout, stderr, result, logger)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; the empty string maps to the
// text default, matching the --format flag default.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "text", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}
