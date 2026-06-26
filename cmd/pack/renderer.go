package pack

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Renderer is the format-dispatch interface for `stave pack`. New formats add a
// concrete type and a case in NewRenderer.
type Renderer interface {
	Render(w io.Writer, payload any) error
}

// NewRenderer maps a format string to its Renderer. Unknown formats are an
// explicit input error at the factory (exit 2), not at each call site.
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

func (jsonRenderer) Render(w io.Writer, payload any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(payload); err != nil {
		return fmt.Errorf("encode pack JSON: %w", err)
	}
	return nil
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, payload any) error {
	switch v := payload.(type) {
	case []listLine:
		fmt.Fprintln(w, "Available packs:")
		for _, l := range v {
			fmt.Fprintf(w, "  %-16s %s (%d controls)\n", l.Name, l.Title, l.Count)
		}
	case showPayload:
		renderShowText(w, v)
	default:
		return fmt.Errorf("pack text renderer: unsupported payload %T", payload)
	}
	return nil
}

func renderShowText(w io.Writer, s showPayload) {
	p := s.Pack
	fmt.Fprintf(w, "Pack:     %s\n", p.Name)
	fmt.Fprintf(w, "Title:    %s\n", p.Title)
	fmt.Fprintf(w, "Controls: %d resolved from the catalog\n", s.Count)
	if len(s.Missing) > 0 {
		fmt.Fprintf(w, "          (warning: %d explicitly-listed IDs not in catalog: %s)\n",
			len(s.Missing), strings.Join(s.Missing, ", "))
	}
	if d := strings.TrimSpace(p.Description); d != "" {
		fmt.Fprintf(w, "\n%s\n", d)
	}

	fmt.Fprintf(w, "\nRequired AWS API calls:\n")
	for _, sc := range p.Requirements.AWSAPICalls {
		fmt.Fprintf(w, "  %s:\n", sc.Service)
		for _, c := range sc.Calls {
			fmt.Fprintf(w, "    %s\n", c)
		}
		if sc.Notes != "" {
			fmt.Fprintf(w, "    # %s\n", sc.Notes)
		}
	}

	if len(p.Requirements.ObservationSignals) > 0 {
		fmt.Fprintf(w, "\nRequired observation signals:\n")
		for _, sig := range p.Requirements.ObservationSignals {
			fmt.Fprintf(w, "  %s\n", sig)
		}
	}

	if mp := strings.TrimSpace(p.Requirements.MinimumPermissions); mp != "" {
		fmt.Fprintf(w, "\nMinimum collector permissions:\n")
		for line := range strings.SplitSeq(mp, "\n") {
			fmt.Fprintf(w, "  %s\n", line)
		}
	}

	fmt.Fprintf(w, "\nNext: collect the calls above into a snapshot dir, then evaluate.\n")
	fmt.Fprintf(w, "      (scoped run: `stave apply --pack %s -o <snapshot>` — see roadmap)\n", p.Name)
}
