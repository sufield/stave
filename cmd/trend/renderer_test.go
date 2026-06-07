package trend

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/forecast"
	"github.com/sufield/stave/internal/app/oscillation"
	"github.com/sufield/stave/internal/app/trendpredict"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", JSONRenderer{}},
		{"openmetrics", OpenMetricsRenderer{}},
		{"executive-summary", ExecutiveSummaryRenderer{}},
		{"table", TableRenderer{}},
		{"", TableRenderer{}},
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
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	rep := &trendReport{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"openmetrics", OpenMetricsRenderer{}},
		{"executive-summary", ExecutiveSummaryRenderer{}},
		{"table", TableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, rep); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestNewForecastRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", ForecastJSONRenderer{}},
		{"table", ForecastTableRenderer{}},
		{"", ForecastTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewForecastRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewForecastRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewForecastRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewForecastRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewForecastRenderer("xml")
	if err == nil {
		t.Fatalf("NewForecastRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestForecastRenderers_NonEmptyOutput(t *testing.T) {
	res := &forecast.Result{}
	cases := []struct {
		name     string
		renderer ForecastRenderer
	}{
		{"json", ForecastJSONRenderer{}},
		{"table", ForecastTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, res); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestNewOscillationRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", OscillationJSONRenderer{}},
		{"table", OscillationTableRenderer{}},
		{"", OscillationTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewOscillationRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewOscillationRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewOscillationRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewOscillationRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewOscillationRenderer("xml")
	if err == nil {
		t.Fatalf("NewOscillationRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestOscillationRenderers_NonEmptyOutput(t *testing.T) {
	results := []oscillation.Classification{}
	cases := []struct {
		name     string
		renderer OscillationRenderer
	}{
		{"json", OscillationJSONRenderer{}},
		{"table", OscillationTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, results); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestNewPredictRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", PredictJSONRenderer{}},
		{"text", PredictTextRenderer{}},
		{"", PredictTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewPredictRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewPredictRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewPredictRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewPredictRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewPredictRenderer("xml")
	if err == nil {
		t.Fatalf("NewPredictRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestPredictRenderers_NonEmptyOutput(t *testing.T) {
	pred := &trendpredict.Prediction{}
	cases := []struct {
		name     string
		renderer PredictRenderer
	}{
		{"json", PredictJSONRenderer{}},
		{"text", PredictTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, pred); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}
