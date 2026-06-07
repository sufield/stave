package exempt

import (
	"bytes"
	"strings"
	"testing"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
)

func TestNewHistoryRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", HistoryJSONRenderer{}},
		{"table", HistoryTableRenderer{}},
		{"", HistoryTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewHistoryRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewHistoryRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewHistoryRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewHistoryRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewHistoryRenderer("xml")
	if err == nil {
		t.Fatalf("NewHistoryRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestHistoryRenderers_NonEmptyOutput(t *testing.T) {
	entries := []appexempt.AcknowledgmentEntry{{ControlID: "CTL.S3.PUBLIC.001", AssetID: "arn:aws:s3:::bucket"}}
	cases := []struct {
		name     string
		renderer HistoryRenderer
	}{
		{"json", HistoryJSONRenderer{}},
		{"table", HistoryTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, entries); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}

func TestNewSuggestRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", SuggestJSONRenderer{}},
		{"table", SuggestTableRenderer{}},
		{"", SuggestTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := NewSuggestRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewSuggestRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewSuggestRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewSuggestRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewSuggestRenderer("xml")
	if err == nil {
		t.Fatalf("NewSuggestRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestSuggestRenderers_NonEmptyOutput(t *testing.T) {
	result := &exemptionsuggest.Result{WindowDays: 30, MinDwellDays: 14}
	cases := []struct {
		name     string
		renderer SuggestRenderer
	}{
		{"json", SuggestJSONRenderer{}},
		{"table", SuggestTableRenderer{}},
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
