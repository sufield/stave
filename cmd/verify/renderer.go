package verify

import (
	"encoding/json"
	"fmt"
	"io"

	av "github.com/sufield/stave/internal/app/archiveverify"
)

// Renderer is the polymorphic format-dispatch interface for the
// verify command's output. Concrete implementations delegate to
// av.WriteTable / av.WriteMarkdown / encoding/json so the rendered
// bytes are identical to the pre-Renderer-pattern shape; the only
// behavioural change is that unknown formats become an explicit
// error at the factory rather than silently falling through to
// table at the default branch.
//
// New formats add an implementation here and a factory case in
// NewRenderer — not another switch in runVerify.
type Renderer interface {
	Render(w io.Writer, attestation *av.Attestation) error
}

// JSONRenderer encodes the attestation as indented JSON.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(w io.Writer, a *av.Attestation) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(a); err != nil {
		return fmt.Errorf("encode json: %w", err)
	}
	return nil
}

// MarkdownRenderer writes the audit-package markdown attestation.
type MarkdownRenderer struct{}

// Render implements Renderer.
func (MarkdownRenderer) Render(w io.Writer, a *av.Attestation) error {
	if err := av.WriteMarkdown(w, a); err != nil {
		return fmt.Errorf("render markdown: %w", err)
	}
	return nil
}

// TableRenderer writes the default human-readable table.
type TableRenderer struct{}

// Render implements Renderer.
func (TableRenderer) Render(w io.Writer, a *av.Attestation) error {
	if err := av.WriteTable(w, a); err != nil {
		return fmt.Errorf("render table: %w", err)
	}
	return nil
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats so the caller surfaces a
// UserError consistently. Previously the default branch silently
// rendered as table; the explicit error is the documented
// unification behaviour from renderer-pattern-debt.md.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "markdown":
		return MarkdownRenderer{}, nil
	case "table", "":
		return TableRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported format %q (expected: table | json | markdown)", format)
}
