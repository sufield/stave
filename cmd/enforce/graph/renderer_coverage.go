package graph

import (
	"fmt"
	"io"

	"github.com/sufield/stave/internal/core/kernel"
)

// CoverageRenderer is the format-dispatch interface for the coverage graph
// produced by `stave enforce graph`. It is distinct from Renderer (the
// `stave graph export` surface in renderer.go): this one carries the
// CoverageResult payload plus a kernel.Sanitizer, and delegates to the
// writeDOT / writeJSON helpers in run.go.
type CoverageRenderer interface {
	Render(w io.Writer, result CoverageResult, sanitizer kernel.Sanitizer) error
}

// coverageDotRenderer emits the coverage graph in DOT form.
type coverageDotRenderer struct{}

// Render implements CoverageRenderer.
func (coverageDotRenderer) Render(w io.Writer, result CoverageResult, sanitizer kernel.Sanitizer) error {
	return writeDOT(w, result, sanitizer)
}

// coverageJSONRenderer emits the coverage graph as indented JSON.
type coverageJSONRenderer struct{}

// Render implements CoverageRenderer.
func (coverageJSONRenderer) Render(w io.Writer, result CoverageResult, sanitizer kernel.Sanitizer) error {
	return writeJSON(w, result, sanitizer)
}

// NewCoverageRenderer maps a validated Format to its concrete CoverageRenderer.
// Unknown formats return an error; callers that have already boundary-validated
// the format (validateFormat) treat that error as an unreachable no-op.
func NewCoverageRenderer(format Format) (CoverageRenderer, error) {
	switch format {
	case FormatDot:
		return coverageDotRenderer{}, nil
	case FormatJSON:
		return coverageJSONRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported coverage format %q", format)
}
