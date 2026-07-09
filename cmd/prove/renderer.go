package prove

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/sufield/stave/pkg/stave"
)

// Renderer is the format-dispatch interface for `stave prove`.
type Renderer interface {
	Render(w io.Writer, r *stave.ProveResult) error
}

// NewRenderer maps a format string to its Renderer.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json", "":
		return jsonRenderer{}, nil
	case "text":
		return textRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, text)", format)
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, r *stave.ProveResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode prove result: %w", err)
	}
	return nil
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, r *stave.ProveResult) error {
	fmt.Fprintf(w, "Query:   %s\n", r.QueryName)
	fmt.Fprintf(w, "Result:  %s\n", r.Result)
	fmt.Fprintf(w, "Verdict: %s\n", r.Interpretation)
	if r.SolveTimeMs > 0 {
		fmt.Fprintf(w, "Time:    %dms\n", r.SolveTimeMs)
	}
	if len(r.Witness) > 0 {
		fmt.Fprintf(w, "\nWitness:\n")
		for k, v := range r.Witness {
			fmt.Fprintf(w, "  %s = %s\n", k, v)
		}
	}
	if len(r.UnsatCore) > 0 {
		fmt.Fprintf(w, "\nUnsat core:\n")
		for _, s := range r.UnsatCore {
			fmt.Fprintf(w, "  %s\n", s)
		}
	}
	if len(r.ModelCoverage.Modeled) > 0 {
		fmt.Fprintf(w, "\nModeled:     %s\n", strings.Join(r.ModelCoverage.Modeled, ", "))
	}
	if len(r.ModelCoverage.NotModeled) > 0 {
		fmt.Fprintf(w, "Not modeled: %s\n", strings.Join(r.ModelCoverage.NotModeled, ", "))
	}
	return nil
}
