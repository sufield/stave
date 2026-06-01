package contract

import (
	"bytes"
	"strings"
	"testing"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{}},
		{"", TextRenderer{}},
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

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml")
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "--format must be text | json") {
		t.Errorf("error should preserve pre-migration message, got: %q", err.Error())
	}
}

// TestRenderers_HandleBothPayloadTypes is the foundational check for
// contract — JSONRenderer must accept both typeReport and listReport
// (it just delegates to writeJSON which takes `any`), and the text
// renderer must dispatch correctly between writeTypeText and
// writeListText. The renderer can be invoked from either runReport
// or runList paths and must not error on the payload variant it
// receives.
func TestRenderers_HandleBothPayloadTypes(t *testing.T) {
	cases := []struct {
		name     string
		renderer Renderer
		payload  any
	}{
		{"json+typeReport", JSONRenderer{}, typeReport{AssetType: "aws_s3_bucket"}},
		{"json+listReport", JSONRenderer{}, listReport{TotalTypes: 0}},
		{"text+typeReport", TextRenderer{}, typeReport{AssetType: "aws_s3_bucket"}},
		{"text+listReport", TextRenderer{}, listReport{TotalTypes: 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, tc.payload); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// TestTextRenderer_RejectsUnknownPayload asserts the type-switch in
// TextRenderer.Render returns an explicit error for payload types
// the renderer doesn't know about, rather than silently writing
// nothing.
func TestTextRenderer_RejectsUnknownPayload(t *testing.T) {
	var buf bytes.Buffer
	err := TextRenderer{}.Render(&buf, "not-a-report")
	if err == nil {
		t.Fatalf("expected error for unknown payload type, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported payload type") {
		t.Errorf("error should mention \"unsupported payload type\", got: %q", err.Error())
	}
}
