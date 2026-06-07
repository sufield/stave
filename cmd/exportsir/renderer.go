package exportsir

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/internal/core/sirfacts"
)

// Payload carries everything the renderers need: the nested SIR
// document (json format) and the extracted fact stream plus the
// closed-world toggle (jsonl / smt2 formats). One value covers all
// three formats so the factory can dispatch without re-deriving
// inputs at the call site.
type Payload struct {
	Doc         *sir.Document
	Facts       []sirfacts.Fact
	ClosedWorld bool
}

// Renderer is the polymorphic format-dispatch interface for
// `stave export-sir`. Concrete implementations delegate to
// sirfacts.SerializeJSONL / sirfacts.SerializeSMT2 / encoding/json
// so the rendered bytes are byte-identical to the pre-Renderer
// output.
//
// New formats add an implementation here and a factory case in
// NewRenderer.
type Renderer interface {
	Render(w io.Writer, p Payload) error
}

// JSONRenderer encodes the nested SIR document as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, p Payload) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(p.Doc); err != nil {
		return fmt.Errorf("encode SIR: %w", err)
	}
	return nil
}

// JSONLRenderer emits one (subject, predicate, object) triple per
// line for Datalog / ASP consumers.
type JSONLRenderer struct{}

// Render implements Renderer.
func (JSONLRenderer) Render(w io.Writer, p Payload) error {
	if err := sirfacts.SerializeJSONL(p.Facts, w); err != nil {
		return fmt.Errorf("encode jsonl: %w", err)
	}
	return nil
}

// SMT2Renderer emits SMT-LIB v2 declarations + assertions.
type SMT2Renderer struct{}

// Render implements Renderer.
func (SMT2Renderer) Render(w io.Writer, p Payload) error {
	if err := sirfacts.SerializeSMT2(p.Facts, w, sirfacts.SMT2Options{ClosedWorld: p.ClosedWorld}); err != nil {
		return fmt.Errorf("encode smt2: %w", err)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Unknown formats surface as a ui.UserError (exit code 2), matching
// the input-error contract the previous validation switch enforced.
// The empty string maps to the JSON default.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "", "json":
		return JSONRenderer{}, nil
	case "jsonl":
		return JSONLRenderer{}, nil
	case "smt2":
		return SMT2Renderer{}, nil
	}
	return nil, &ui.UserError{Err: fmt.Errorf("--format must be one of json | jsonl | smt2 (got %q)", format)}
}
