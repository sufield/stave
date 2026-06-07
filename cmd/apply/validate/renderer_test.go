package validate

import (
	"bytes"
	"strings"
	"testing"

	appvalidation "github.com/sufield/stave/internal/app/validation"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		name   string
		format string
		want   any
	}{
		{"json", "json", JSONRenderer{}},
		{"text", "text", TextRenderer{}},
		{"empty defaults to text", "", TextRenderer{}},
		{"template path", "./out.tmpl", TemplateRenderer{template: "./out.tmpl"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reporter := &Reporter{}
			r, err := NewRenderer(tc.format, reporter)
			if err != nil {
				t.Fatalf("NewRenderer(%q): unexpected error: %v", tc.format, err)
			}
			switch want := tc.want.(type) {
			case JSONRenderer:
				if _, ok := r.(JSONRenderer); !ok {
					t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, r, want)
				}
			case TemplateRenderer:
				got, ok := r.(TemplateRenderer)
				if !ok {
					t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, r, want)
				}
				if got.template != want.template {
					t.Errorf("NewRenderer(%q) template = %q, want %q", tc.format, got.template, want.template)
				}
			case TextRenderer:
				got, ok := r.(TextRenderer)
				if !ok {
					t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, r, want)
				}
				if got.reporter != reporter {
					t.Errorf("NewRenderer(%q) text renderer should carry the owning reporter", tc.format)
				}
			}
		})
	}
}

func TestNewRenderer_NeverErrors(t *testing.T) {
	// The previous switch had no unknown-format arm: any non-empty,
	// non-"json", non-"text" value is treated as a template path. The
	// factory preserves that — it never rejects a format string. Unknown
	// values surface as template-execution errors at Render time, not here.
	r, err := NewRenderer("xml", &Reporter{})
	if err != nil {
		t.Fatalf("NewRenderer(\"xml\"): unexpected error: %v", err)
	}
	if _, ok := r.(TemplateRenderer); !ok {
		t.Errorf("NewRenderer(\"xml\") = %T, want TemplateRenderer", r)
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	result := &appvalidation.Report{}
	report := buildReport(result, false, hintContext{})
	payload := renderPayload{result: result, report: report}

	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"text", TextRenderer{reporter: &Reporter{}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			// TextRenderer delegates to the reporter's writeText, which
			// writes to the reporter's own writer; point it at buf.
			if tr, ok := tc.renderer.(TextRenderer); ok {
				tr.reporter.Writer = &buf
			}
			if err := tc.renderer.Render(&buf, payload); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestTemplateRenderer_BadTemplateErrors(t *testing.T) {
	result := &appvalidation.Report{}
	payload := renderPayload{result: result, report: buildReport(result, false, hintContext{})}
	var buf bytes.Buffer
	// ExecuteTemplate treats the format string as a literal template; a
	// malformed action triggers the wrapped error path.
	r := TemplateRenderer{template: "{{.Unclosed"}
	if err := r.Render(&buf, payload); err == nil {
		t.Fatalf("Render with malformed template: want error, got nil")
	} else if !strings.Contains(err.Error(), "execute output template") {
		t.Errorf("error should wrap %q, got: %q", "execute output template", err.Error())
	}
}

func TestTemplateRenderer_RendersLiteralTemplate(t *testing.T) {
	result := &appvalidation.Report{}
	payload := renderPayload{result: result, report: buildReport(result, false, hintContext{})}
	var buf bytes.Buffer
	r := TemplateRenderer{template: "valid={{.Valid}}"}
	if err := r.Render(&buf, payload); err != nil {
		t.Fatalf("Render: unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Errorf("Render produced empty output")
	}
}
