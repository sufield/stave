package monitor

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	appmon "github.com/sufield/stave/internal/app/monitor"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"plain", PlainRenderer{}},
		{"live", LiveRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

// TestNewRenderer_EmptyAndUnknownErrors — monitor has no implicit
// default. Empty string is invalid; this preserves the pre-migration
// behaviour (default branch in the run() switch errored).
func TestNewRenderer_EmptyAndUnknownErrors(t *testing.T) {
	for _, format := range []string{"", "xml"} {
		t.Run(format, func(t *testing.T) {
			r, err := NewRenderer(format)
			if err == nil {
				t.Fatalf("NewRenderer(%q): want error, got %T", format, r)
			}
			if !strings.Contains(err.Error(), "unknown format") {
				t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
			}
		})
	}
}

// TestSnapshotRenderers_LoadStateOnce verifies json + plain renderers
// call the state loader exactly once and bubble its error. Live mode
// is tested separately via the existing runLiveLoop tests.
func TestSnapshotRenderers_LoadStateOnce(t *testing.T) {
	calls := 0
	loader := func() (*appmon.State, error) {
		calls++
		return &appmon.State{}, nil
	}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"plain", PlainRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls = 0
			var buf bytes.Buffer
			if err := tc.renderer.Render(context.Background(), &buf, &options{}, loader); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if calls != 1 {
				t.Errorf("loadState calls: got %d, want 1", calls)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// TestSnapshotRenderers_BubbleLoadStateError verifies that a loader
// error propagates through Render. The cmd layer wraps it in
// ui.UserError; the renderer itself just returns the underlying.
func TestSnapshotRenderers_BubbleLoadStateError(t *testing.T) {
	want := errors.New("boom")
	loader := func() (*appmon.State, error) { return nil, want }
	for _, r := range []Renderer{JSONRenderer{}, PlainRenderer{}} {
		t.Run(strings.TrimPrefix(strings.Split(strings.Trim(strings.TrimPrefix(fmtType(r), "monitor."), "{}"), "Renderer")[0], ""), func(t *testing.T) {
			err := r.Render(context.Background(), &bytes.Buffer{}, &options{}, loader)
			if !errors.Is(err, want) {
				t.Errorf("expected loader error to bubble, got: %v", err)
			}
		})
	}
}

func fmtType(r Renderer) string {
	type stringer interface{ String() string }
	if s, ok := any(r).(stringer); ok {
		return s.String()
	}
	switch r.(type) {
	case JSONRenderer:
		return "monitor.JSONRenderer"
	case PlainRenderer:
		return "monitor.PlainRenderer"
	}
	return "?"
}
