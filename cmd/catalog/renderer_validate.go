package catalog

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/pkg/stave"
)

// validateRenderer dispatches output to text or JSON.
type validateRenderer interface {
	Render(w io.Writer, result *stave.CatalogValidateResult) error
}

type validateTextRenderer struct{}

func (validateTextRenderer) Render(w io.Writer, r *stave.CatalogValidateResult) error {
	sections := []struct {
		name string
		sec  stave.CatalogValidateSection
	}{
		{"Control Lint", r.ControlLint},
		{"Chain Lint", r.ChainLint},
		{"Cross-Reference", r.CrossReference},
	}
	for _, s := range sections {
		if len(s.sec.Errors)+len(s.sec.Warnings) == 0 {
			continue
		}
		fmt.Fprintf(w, "== %s ==\n", s.name)
		for _, e := range s.sec.Errors {
			fmt.Fprintf(w, "  ERROR   %s\n", e)
		}
		for _, wn := range s.sec.Warnings {
			fmt.Fprintf(w, "  WARNING %s\n", wn)
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "%d error(s), %d warning(s)\n", r.TotalErrors, r.TotalWarnings)
	return nil
}

type validateJSONRenderer struct{}

func (validateJSONRenderer) Render(w io.Writer, r *stave.CatalogValidateResult) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode validate JSON: %w", err)
	}
	return nil
}

func newValidateRenderer(format string) (validateRenderer, error) {
	switch format {
	case "json":
		return validateJSONRenderer{}, nil
	case "text", "":
		return validateTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: text, json)", format)
}
