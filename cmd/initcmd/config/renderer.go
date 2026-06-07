package config

import (
	"fmt"
	"io"

	appconfig "github.com/sufield/stave/internal/app/config"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// This file replaces the per-site `if format.IsJSON()` inline dispatch
// (and the ShowPresenter.Render(out, isJSON bool) bool-dispatch) with a
// typed-format factory per payload. Each factory maps the typed
// contracts.OutputFormat to a concrete Renderer; an unknown format
// yields an explicit error (defensive — the enum is validated upstream
// at the flag boundary). Concrete renderers delegate to the same
// jsonutil.WriteIndented / Fprintf / renderText helpers so the bytes
// stay identical to the pre-Renderer-pattern output.

// --- value payload (`config get`) ---

// ValueRenderer is the format-dispatch interface for a single resolved
// config value (`config get`).
type ValueRenderer interface {
	Render(w io.Writer, res ValueResult) error
}

// ValueJSONRenderer encodes the value as indented JSON.
type ValueJSONRenderer struct{}

// Render implements ValueRenderer.
func (ValueJSONRenderer) Render(w io.Writer, res ValueResult) error {
	if err := jsonutil.WriteIndented(w, res); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// ValueTextRenderer writes the bare value followed by a newline.
type ValueTextRenderer struct{}

// Render implements ValueRenderer.
func (ValueTextRenderer) Render(w io.Writer, res ValueResult) error {
	_, err := fmt.Fprintf(w, "%s\n", res.Value)
	return err
}

// NewValueRenderer maps a typed OutputFormat to its concrete
// ValueRenderer. JSON selects the indented-JSON renderer; every other
// format accepted upstream (text, and the sarif/markdown values the
// shared --format parser permits) renders the bare value — preserving
// the prior `if format.IsJSON() { ... } else { ... text }` behaviour,
// where any non-JSON format fell through to text. A genuinely unknown
// OutputFormat yields an explicit error (defensive; the enum is
// validated at the flag boundary).
func NewValueRenderer(format appcontracts.OutputFormat) (ValueRenderer, error) {
	if format.IsJSON() {
		return ValueJSONRenderer{}, nil
	}
	if isTextLike(format) {
		return ValueTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported output format %q (supported: text, json)", format)
}

// --- mutation payload (`config set` / `config delete`) ---

// MutationRenderer is the format-dispatch interface for a config
// mutation result (`config set` / `config delete`). Text rendering
// also emits an optional follow-up hint to stderr, so the renderer
// carries the mutation context.
type MutationRenderer interface {
	Render(w io.Writer, res ValueResult) error
}

// MutationJSONRenderer encodes the mutation result as indented JSON.
type MutationJSONRenderer struct{}

// Render implements MutationRenderer.
func (MutationJSONRenderer) Render(w io.Writer, res ValueResult) error {
	if err := jsonutil.WriteIndented(w, res); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// MutationTextRenderer writes a human-readable confirmation line and,
// when requested, a follow-up hint to stderr.
type MutationTextRenderer struct {
	Stderr   io.Writer
	Text     string
	ShowHint bool
	Quiet    bool
}

// Render implements MutationRenderer.
func (m MutationTextRenderer) Render(w io.Writer, _ ValueResult) error {
	if _, err := fmt.Fprintln(w, m.Text); err != nil {
		return err
	}
	if m.ShowHint && !m.Quiet {
		ui.WriteHint(m.Stderr, "stave config show")
	}
	return nil
}

// NewMutationRenderer maps a typed OutputFormat to its concrete
// MutationRenderer. The text renderer needs the mutation context
// (confirmation text, hint visibility, quiet flag, stderr) to
// reproduce the prior text branch exactly. Any non-JSON format
// accepted upstream renders as text (matching the prior
// `if opts.Format.IsJSON()` dispatch); a genuinely unknown
// OutputFormat yields an explicit error.
func NewMutationRenderer(format appcontracts.OutputFormat, stderr io.Writer, text string, opts MutationOpts, showHint bool) (MutationRenderer, error) {
	if format.IsJSON() {
		return MutationJSONRenderer{}, nil
	}
	if isTextLike(format) {
		return MutationTextRenderer{Stderr: stderr, Text: text, ShowHint: showHint, Quiet: opts.Quiet}, nil
	}
	return nil, fmt.Errorf("unsupported output format %q (supported: text, json)", format)
}

// --- show payload (`config show`) ---

// ShowRenderer is the format-dispatch interface for the effective
// configuration summary (`config show`).
type ShowRenderer interface {
	Render(w io.Writer, out appconfig.EffectiveConfig) error
}

// ShowJSONRenderer encodes the effective configuration as indented JSON.
type ShowJSONRenderer struct{}

// Render implements ShowRenderer.
func (ShowJSONRenderer) Render(w io.Writer, out appconfig.EffectiveConfig) error {
	if err := jsonutil.WriteIndented(w, out); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

// ShowTextRenderer writes the human-readable configuration summary,
// delegating to the existing renderText layout.
type ShowTextRenderer struct{}

// Render implements ShowRenderer.
func (ShowTextRenderer) Render(w io.Writer, out appconfig.EffectiveConfig) error {
	p := &ShowPresenter{Stdout: w}
	return p.renderText(out)
}

// NewShowRenderer maps a typed OutputFormat to its concrete
// ShowRenderer, preserving the prior ShowPresenter.Render(out, isJSON)
// bool dispatch: JSON renders as JSON, every other upstream-accepted
// format renders as text. A genuinely unknown OutputFormat yields an
// explicit error.
func NewShowRenderer(format appcontracts.OutputFormat) (ShowRenderer, error) {
	if format.IsJSON() {
		return ShowJSONRenderer{}, nil
	}
	if isTextLike(format) {
		return ShowTextRenderer{}, nil
	}
	return nil, fmt.Errorf("unsupported output format %q (supported: text, json)", format)
}

// isTextLike reports whether format is one of the non-JSON values the
// shared --format parser admits into this package. The pre-Renderer
// code branched solely on format.IsJSON(), so text, sarif, and
// markdown all fell through to the human-readable text path; this
// helper keeps that mapping centralized.
func isTextLike(format appcontracts.OutputFormat) bool {
	switch format {
	case appcontracts.FormatText, appcontracts.FormatSARIF, appcontracts.FormatMarkdown:
		return true
	}
	return false
}
