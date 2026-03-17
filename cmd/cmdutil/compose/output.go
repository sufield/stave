package compose

import (
	"fmt"
	"io"
	"os"
	"strings"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outsarif "github.com/sufield/stave/internal/adapters/output/sarif"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
)

// DefaultFindingWriter is the standard implementation for finding marshalers.
func DefaultFindingWriter(format string, jsonMode bool) (appcontracts.FindingMarshaler, error) {
	const indented = true
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "text":
		return outtext.NewFindingWriter(), nil
	case "json":
		if jsonMode {
			return outjson.NewFindingWriterWithEnvelope(indented), nil
		}
		return outjson.NewFindingWriter(indented), nil
	case "sarif":
		return outsarif.NewFindingWriter(), nil
	default:
		return nil, fmt.Errorf("invalid --format %q (use text, json, or sarif)", format)
	}
}

// ResolveStdout returns a writer based on quiet settings and format.
func ResolveStdout(w io.Writer, quiet bool, format ui.OutputFormat) io.Writer {
	if quiet && !format.IsJSON() {
		return io.Discard
	}
	if w == nil {
		return os.Stdout
	}
	return w
}
