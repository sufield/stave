package plan

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Renderer is the format-dispatch interface for `stave plan`.
type Renderer interface {
	Render(w io.Writer, p preview) error
}

// NewRenderer maps a format string to its Renderer (unknown -> exit 2).
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "text", "":
		return textRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}

type jsonRenderer struct{}

func (jsonRenderer) Render(w io.Writer, p preview) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p); err != nil {
		return fmt.Errorf("encode plan JSON: %w", err)
	}
	return nil
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, p preview) error {
	if p.Pack != "" {
		fmt.Fprintf(w, "Plan for pack: %s\n\n", p.Pack)
	} else {
		fmt.Fprintf(w, "Plan for services: %s\n\n", strings.Join(p.Services, ", "))
	}
	fmt.Fprintf(w, "%-14s %9s %9s %5s %7s %5s\n", "Service", "Controls", "Critical", "High", "Medium", "Low")
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 56))
	for _, r := range p.Rows {
		fmt.Fprintf(w, "%-14s %9d %9d %5d %7d %5d\n",
			r.Service, r.Total, r.Critical, r.High, r.Medium, r.Low)
	}
	fmt.Fprintf(w, "%s\n", strings.Repeat("-", 56))
	fmt.Fprintf(w, "%-14s %9d %9d %5d %7d %5d\n",
		"total", p.Total.Total, p.Total.Critical, p.Total.High, p.Total.Medium, p.Total.Low)

	if len(p.CollectionOrder) > 0 {
		fmt.Fprintf(w, "\nRecommended collection order (most critical first):\n")
		for i, svc := range p.CollectionOrder {
			fmt.Fprintf(w, "  %d. %s\n", i+1, svc)
		}
	}
	fmt.Fprintf(w, "\nThis is a preview — no data collected, nothing evaluated.\n")
	fmt.Fprintf(w, "Next: `stave discover --services %s` for the collection manifest.\n",
		strings.Join(p.Services, ","))
	return nil
}
