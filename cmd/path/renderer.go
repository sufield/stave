package path

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/app/attackpath"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave path`. Three formats: json, dot (Graphviz), csv-edges.
// There is no default human-readable format — the pre-migration
// switch returned an error for any unknown value, including the
// empty string. The factory preserves that: the empty string is an
// invalid format here.
type Renderer interface {
	Render(w io.Writer, g *attackpath.Graph) error
}

// JSONRenderer encodes the graph as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, g *attackpath.Graph) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(g)
}

// DOTRenderer emits the Graphviz DOT representation.
type DOTRenderer struct{}

// Render implements Renderer.
func (DOTRenderer) Render(w io.Writer, g *attackpath.Graph) error {
	return attackpath.WriteDOT(w, g)
}

// CSVEdgesRenderer emits the edge list as CSV.
type CSVEdgesRenderer struct{}

// Render implements Renderer.
func (CSVEdgesRenderer) Render(w io.Writer, g *attackpath.Graph) error {
	return attackpath.WriteCSVEdges(w, g)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats. The pre-migration code had
// no default text format — every input that wasn't json/dot/csv-edges
// errored. The empty string is included in the error set for the
// same reason.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "dot":
		return DOTRenderer{}, nil
	case "csv-edges":
		return CSVEdgesRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, dot, csv-edges)", format)
}
