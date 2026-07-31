package enumerate

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/network"
)

// Renderer is the format-dispatch interface for `stave network enumerate`.
type Renderer interface {
	Render(w io.Writer, r *network.EnumerateResult) error
}

// NewRenderer maps a format string to its Renderer.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return jsonRenderer{}, nil
	case "text", "":
		return textRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: json, text)", format)
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, r *network.EnumerateResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, r *network.EnumerateResult) error {
	fmt.Fprintf(w, "SSH Entry Points to Production (port %d)\n", r.Port)
	fmt.Fprintf(w, "Production hosts: %d\n", r.ProductionHosts)
	fmt.Fprintf(w, "Paths found: %d\n\n", len(r.Paths))

	for i, p := range r.Paths {
		fmt.Fprintf(w, "  %d. %s → %s  [%s]  sg:%s  via:%s\n",
			i+1, p.Source, p.Destination, p.PathType, p.RuleSG, p.RuleSource)
	}

	if len(r.Paths) == 0 {
		fmt.Fprintln(w, "  No SSH paths to production hosts found.")
	}
	return nil
}
