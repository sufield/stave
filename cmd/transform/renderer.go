package transform

import (
	"encoding/json"
	"fmt"
	"io"

	awstransform "github.com/sufield/stave/internal/adapters/aws/transform"
)

// result is the summary of a transform run, rendered after the observation is
// written.
type result struct {
	Files      int    `json:"files"`
	Assets     int    `json:"assets"`
	Skipped    int    `json:"skipped"`
	OutputPath string `json:"output_path"` // "-" when written to stdout
	Validated  bool   `json:"validated"`
}

// Renderer is the format-dispatch interface for `stave transform`. All format
// dispatch happens once in NewRenderer (the factory), per the renderer pattern.
type Renderer interface {
	Render(w io.Writer, r result) error
	RenderCoverage(w io.Writer, s []awstransform.Supported) error
}

// NewRenderer maps a format string to its Renderer (unknown -> exit 2 at the factory).
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

func (jsonRenderer) Render(w io.Writer, r result) error {
	return encodeJSON(w, r)
}

func (jsonRenderer) RenderCoverage(w io.Writer, s []awstransform.Supported) error {
	return encodeJSON(w, s)
}

func encodeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		return fmt.Errorf("encode JSON: %w", err)
	}
	return nil
}

type textRenderer struct{}

func (textRenderer) Render(w io.Writer, r result) error {
	fmt.Fprintf(w, "Transformed %d file(s) → %d resource(s)\n", r.Files-r.Skipped, r.Assets)
	if r.Skipped > 0 {
		fmt.Fprintf(w, "Skipped: %d file(s) (no matching filter)\n", r.Skipped)
	}
	if r.Validated {
		fmt.Fprintf(w, "Validation: passed obs.v0.1 schema check\n")
	}
	if r.OutputPath == "-" {
		fmt.Fprintf(w, "Wrote: stdout\n")
	} else {
		fmt.Fprintf(w, "Wrote: %s\n", r.OutputPath)
	}
	return nil
}

func (textRenderer) RenderCoverage(w io.Writer, s []awstransform.Supported) error {
	fmt.Fprintf(w, "Recognized raw input shapes (top-level JSON key → filter):\n")
	for _, in := range s {
		fmt.Fprintf(w, "  %-42s %s\n", in.TopLevelKey, in.Filter)
	}
	fmt.Fprintf(w, "\nFiles whose top-level key matches none of these are skipped.\n")
	return nil
}
