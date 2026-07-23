package cidiff

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the polymorphic format-dispatch interface for `stave ci diff`.
type Renderer interface {
	Render(w io.Writer, resp *stave.CIDiffResponse) error
}

// JSONRenderer encodes the diff response as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, resp *stave.CIDiffResponse) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

// TextRenderer writes a human-readable summary.
type TextRenderer struct{}

// Render implements Renderer.
func (TextRenderer) Render(w io.Writer, resp *stave.CIDiffResponse) error {
	fmt.Fprintf(w, "CI Diff: %s vs %s\n\n", resp.CurrentEvaluation, resp.BaselineEvaluation)
	fmt.Fprintf(w, "  Baseline findings:  %d\n", resp.Summary.BaselineFindings)
	fmt.Fprintf(w, "  Current findings:   %d\n", resp.Summary.CurrentFindings)
	fmt.Fprintf(w, "  New:                %d\n", resp.Summary.NewFindings)
	fmt.Fprintf(w, "  Resolved:           %d\n", resp.Summary.ResolvedFindings)
	fmt.Fprintf(w, "  Unchanged:          %d\n\n", resp.Summary.UnchangedFindings)

	if len(resp.NewFindings) > 0 {
		fmt.Fprintf(w, "New findings:\n")
		for _, f := range resp.NewFindings {
			fmt.Fprintf(w, "  %s on %s (%s)\n", f.ControlID, f.AssetID, f.AssetType)
		}
		fmt.Fprintln(w)
	}
	if len(resp.ResolvedFindings) > 0 {
		fmt.Fprintf(w, "Resolved findings:\n")
		for _, f := range resp.ResolvedFindings {
			fmt.Fprintf(w, "  %s on %s (%s)\n", f.ControlID, f.AssetID, f.AssetType)
		}
		fmt.Fprintln(w)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json", "":
		return JSONRenderer{}, nil
	case "text":
		return TextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, text)", format)
}
