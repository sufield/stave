package catalog

import (
	"fmt"
	"io"

	appcaps "github.com/sufield/stave/internal/app/capabilities"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// catalogReport is the JSON-shape contract for `stave capabilities
// catalog`. Extracted from an inline anonymous struct so the renderer
// has a named payload type — making the JSON contract grep-able and
// stable across the migration. TotalCapabilities is derived from
// len(Capabilities); both fields are present so JSON consumers don't
// recompute it.
type catalogReport struct {
	TotalCapabilities int                  `json:"total_capabilities"`
	Capabilities      []appcaps.Capability `json:"capabilities"`

	// View state for the human (text/wide) renderers only. These are
	// UNEXPORTED so encoding/json never emits them — the JSON contract stays
	// exactly {total_capabilities, capabilities}. The JSON renderer ignores
	// them; the text renderer dispatches on mode.
	summary     appcaps.Summary       // header counts (control-group-scoped severity)
	services    []appcaps.ServiceRow  // per-service rollup for the summary table
	leafs       []appcaps.LeafControl // leaf controls for the --leaf / --severity view
	mode        viewMode              // which human view to render
	serviceArg  string                // the drilled-in service, for headings
	categoryArg string                // the --category filter, for headings + leaf filtering
	sevFilter   string                // the --severity value, for the leaf-view heading
	wide        bool                  // wide variant: more columns (set by WideRenderer)
}

// viewMode selects the human-readable view. JSON is unaffected (it always emits
// the full capabilities list regardless of mode).
type viewMode int

const (
	viewSummary viewMode = iota // default: header + one line per service
	viewService                 // one service's capabilities, one line each
	viewKind                    // a single --kind listing (chains / operational)
	viewLeaf                    // leaf controls (--leaf / --severity)
)

// Renderer is the polymorphic format-dispatch interface for
// `stave capabilities catalog`. The validation switch in run() and
// the `if format == "json"` dispatch in run() collapse to a single
// NewRenderer call at the top.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, r catalogReport) error
}

// JSONRenderer encodes the report via jsonutil.WriteIndented.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, r catalogReport) error {
	if err := jsonutil.WriteIndented(w, r); err != nil {
		return fmt.Errorf("write catalog JSON: %w", err)
	}
	return nil
}

// TextRenderer writes the human-readable catalog.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, r catalogReport) error {
	return renderView(w, r)
}

// WideRenderer writes the same views as TextRenderer with extra columns. The
// wide flag is data on the report, so the per-mode renderers share one path.
type WideRenderer struct{}

// Render implements Renderer.
func (WideRenderer) Render(w io.Writer, r catalogReport) error {
	r.wide = true
	return renderView(w, r)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats. "auto" is the default human view
// (paged when stdout is a TTY — the command decides paging, not the renderer);
// "text" is its non-paged alias kept for back-compat.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "wide":
		return WideRenderer{}, nil
	case "text", "auto", "":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("--format must be text | auto | wide | json (got %q)", format)
}
