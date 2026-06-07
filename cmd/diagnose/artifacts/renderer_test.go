package artifacts

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/app/catalogquality"
	"github.com/sufield/stave/internal/app/catalogsearch"
)

func TestNewControlsRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", ControlsJSONRenderer{}},
		{"text", ControlsTableRenderer{}},
		{"", ControlsTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewControlsRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewControlsRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewControlsRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewControlsRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewControlsRenderer("xml")
	if err == nil {
		t.Fatalf("NewControlsRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestControlsRenderers_NonEmptyOutput(t *testing.T) {
	results := []catalogsearch.SearchResult{
		{ControlID: "CTL.S3.PUBLIC.001", Severity: "high", Name: "Public bucket"},
	}
	cases := []struct {
		name     string
		renderer ControlsRenderer
	}{
		{"json", ControlsJSONRenderer{}},
		{"table", ControlsTableRenderer{}},
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

func TestNewQualityRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", QualityJSONRenderer{}},
		{"table", QualityTableRenderer{}},
		{"", QualityTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewQualityRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewQualityRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewQualityRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewQualityRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewQualityRenderer("xml")
	if err == nil {
		t.Fatalf("NewQualityRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestQualityRenderers_NonEmptyOutput(t *testing.T) {
	report := catalogquality.Report{TotalControls: 1, OverallPct: 50}
	cases := []struct {
		name     string
		renderer QualityRenderer
	}{
		{"json", QualityJSONRenderer{}},
		{"table", QualityTableRenderer{}},
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
