package enumerate

import (
	"encoding/json"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/core/network"
)

// ValidFormats contains the supported output format names.
var ValidFormats = []string{"json", "text"}

// IsValidFormat reports whether format is one of the supported output formats (or empty for default).
func IsValidFormat(format string) bool {
	return format == "" || slices.Contains(ValidFormats, format)
}

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
	return nil, fmt.Errorf("unknown format %q (valid: %s)", format, strings.Join(ValidFormats, ", "))
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
	fmt.Fprintf(w, "Paths found: %d\n\n", r.PathCount())

	for i, p := range r.Paths {
		fmt.Fprintln(w, p.FormatEntry(i+1))
	}

	if !r.HasPaths() {
		fmt.Fprintln(w, "  No SSH paths to production hosts found.")
	}
	return nil
}
