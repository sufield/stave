package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"

	appmon "github.com/sufield/stave/internal/app/monitor"
)

// Renderer is the polymorphic format-dispatch interface for
// `stave monitor`. Unlike most commands in this codebase, monitor
// has a third mode — `live` — that is not a one-shot render but a
// long-running poll loop. The interface therefore takes more inputs
// than the simpler renderer shapes: a context (for cancellation in
// the live mode), a state loader (the live loop reloads state on
// each tick), and the command's options (the live loop reads the
// poll interval and other fields).
//
// JSON/Plain renderers ignore ctx and opts; LiveRenderer uses them.
// The wider signature is the explicit cost of making the dispatch
// table single-shape across three structurally different modes.
type Renderer interface {
	Render(ctx context.Context, w io.Writer, opts *options, loadState func() (*appmon.State, error)) error
}

// JSONRenderer encodes the current state as indented JSON. Loads
// state once and exits.
type JSONRenderer struct{}

// Render implements Renderer.
func (JSONRenderer) Render(_ context.Context, w io.Writer, _ *options, loadState func() (*appmon.State, error)) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(state)
}

// PlainRenderer writes a plain-text snapshot of the current state.
// Loads state once and exits.
type PlainRenderer struct{}

// Render implements Renderer.
func (PlainRenderer) Render(_ context.Context, w io.Writer, _ *options, loadState func() (*appmon.State, error)) error {
	state, err := loadState()
	if err != nil {
		return err
	}
	appmon.RenderPlain(w, state, false)
	return nil
}

// LiveRenderer runs the long-poll live loop, refreshing state on
// each tick until ctx is cancelled. Delegates to the existing
// runLiveLoop implementation in cmd.go so the loop logic is
// unchanged by the migration.
type LiveRenderer struct{}

// Render implements Renderer.
func (LiveRenderer) Render(ctx context.Context, w io.Writer, opts *options, loadState func() (*appmon.State, error)) error {
	return runLiveLoop(ctx, w, opts, loadState)
}

// NewRenderer maps a format string to its concrete Renderer.
// Returns an error for unknown formats; this preserves the
// pre-migration error message verbatim.
func NewRenderer(format string) (Renderer, error) {
	switch format {
	case "json":
		return JSONRenderer{}, nil
	case "plain":
		return PlainRenderer{}, nil
	case "live":
		return LiveRenderer{}, nil
	}
	return nil, fmt.Errorf("unknown format %q (valid: live, json, plain)", format)
}
