package diagnose

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/narrative"
)

func TestNewExplainNarrativeRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		depth  string
	}{
		{"json", "deep"},
		{"markdown", "deep"},
		{"narrative", "deep"},
		{"text", "shallow"},
		{"", "shallow"},
	}
	for _, tc := range cases {
		name := tc.format
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewExplainNarrativeRenderer(tc.format, tc.depth)
			if err != nil {
				t.Fatalf("NewExplainNarrativeRenderer(%q,%q): unexpected error: %v", tc.format, tc.depth, err)
			}
			switch tc.format {
			case "json":
				if _, ok := r.(ExplainNarrativeJSONRenderer); !ok {
					t.Errorf("got %T, want JSONRenderer", r)
				}
			case "markdown":
				md, ok := r.(ExplainNarrativeMarkdownRenderer)
				if !ok {
					t.Errorf("got %T, want MarkdownRenderer", r)
					return
				}
				if md.Depth != tc.depth {
					t.Errorf("Depth: got %q, want %q", md.Depth, tc.depth)
				}
			default:
				tx, ok := r.(ExplainNarrativeTextRenderer)
				if !ok {
					t.Errorf("got %T, want TextRenderer", r)
					return
				}
				if tx.Depth != tc.depth {
					t.Errorf("Depth: got %q, want %q", tx.Depth, tc.depth)
				}
			}
		})
	}
}

func TestNewExplainNarrativeRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewExplainNarrativeRenderer("xml", "deep")
	if err == nil {
		t.Fatalf("NewExplainNarrativeRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

// TestJSONRenderer_SinglePlaybookEmitsObject verifies the single-vs-
// array JSON shape: one playbook → bare object, multiple → array.
// This is the special-case preserved from the pre-migration switch.
func TestJSONRenderer_SinglePlaybookEmitsObject(t *testing.T) {
	r := ExplainNarrativeJSONRenderer{}
	cases := []struct {
		name      string
		playbooks []narrative.Playbook
		wantStart string
	}{
		{"one", []narrative.Playbook{{ControlID: "CTL.A.001"}}, "{"},
		{"two", []narrative.Playbook{{ControlID: "CTL.A.001"}, {ControlID: "CTL.B.002"}}, "["},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := r.Render(&buf, tc.playbooks); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if !strings.HasPrefix(strings.TrimLeft(buf.String(), " \n\t"), tc.wantStart) {
				t.Errorf("expected output to start with %q, got: %q", tc.wantStart, buf.String())
			}
		})
	}
}
