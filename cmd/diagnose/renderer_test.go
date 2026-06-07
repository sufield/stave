package diagnose

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
)

// --- ExplainResultRenderer ---

func TestNewExplainResultRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   any
	}{
		{appcontracts.FormatJSON, ExplainResultJSONRenderer{}},
		{appcontracts.FormatText, ExplainResultTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewExplainResultRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewExplainResultRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewExplainResultRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewExplainResultRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewExplainResultRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewExplainResultRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestExplainResultRenderers_NoError(t *testing.T) {
	result := appcontracts.ExplainResult{}
	cases := []struct {
		name     string
		renderer ExplainResultRenderer
	}{
		{"json", ExplainResultJSONRenderer{}},
		{"text", ExplainResultTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, result); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// --- ReportRenderer ---

func TestNewReportRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   any
	}{
		{appcontracts.FormatJSON, ReportJSONRenderer{}},
		{appcontracts.FormatText, ReportTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewReportRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewReportRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewReportRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewReportRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewReportRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewReportRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestReportRenderers_NoError(t *testing.T) {
	report := &diagnosis.Report{}
	cases := []struct {
		name     string
		renderer ReportRenderer
	}{
		{"json", ReportJSONRenderer{}},
		{"text", ReportTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, report); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// --- DetailRenderer ---

func TestNewDetailRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   any
	}{
		{appcontracts.FormatJSON, DetailJSONRenderer{}},
		{appcontracts.FormatText, DetailTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewDetailRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewDetailRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewDetailRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewDetailRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewDetailRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewDetailRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestDetailRenderers_NoError(t *testing.T) {
	detail := &evaluation.FindingDetail{}
	cases := []struct {
		name     string
		renderer DetailRenderer
	}{
		{"json", DetailJSONRenderer{}},
		{"text", DetailTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, detail); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// --- TraceRenderer ---

// fakeTraceResult is a minimal evaluation.TraceRenderer used to smoke
// the trace renderers without standing up the full tracer pipeline.
type fakeTraceResult struct{}

func (fakeTraceResult) RenderText(w io.Writer) error {
	if _, err := io.WriteString(w, "trace-text"); err != nil {
		return fmt.Errorf("write trace text: %w", err)
	}
	return nil
}

func (fakeTraceResult) RenderJSON(w io.Writer) error {
	if _, err := io.WriteString(w, `{"trace":"json"}`); err != nil {
		return fmt.Errorf("write trace json: %w", err)
	}
	return nil
}

func TestNewTraceRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   any
	}{
		{appcontracts.FormatJSON, TraceJSONRenderer{}},
		{appcontracts.FormatText, TraceTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewTraceRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewTraceRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewTraceRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewTraceRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewTraceRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewTraceRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestTraceRenderers_NoError(t *testing.T) {
	result := fakeTraceResult{}
	cases := []struct {
		name     string
		renderer TraceRenderer
	}{
		{"json", TraceJSONRenderer{}},
		{"text", TraceTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, result); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

// --- detailGatingError ---

func TestDetailGatingError(t *testing.T) {
	if err := detailGatingError(appcontracts.FormatJSON); err != nil {
		t.Errorf("detailGatingError(FormatJSON) = %v, want nil", err)
	}
	if err := detailGatingError(appcontracts.FormatText); err == nil {
		t.Errorf("detailGatingError(FormatText) = nil, want ErrViolationsFound")
	}
}
