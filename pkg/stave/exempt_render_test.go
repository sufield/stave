package stave

import (
	"bytes"
	"strings"
	"testing"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
)

func TestExemptNewHistoryRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", exemptHistoryJSONRenderer{}},
		{"table", exemptHistoryTableRenderer{}},
		{"", exemptHistoryTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := exemptNewHistoryRenderer(tc.format)
			if err != nil {
				t.Fatalf("exemptNewHistoryRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("exemptNewHistoryRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestExemptNewHistoryRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := exemptNewHistoryRenderer("xml")
	if err == nil {
		t.Fatalf("exemptNewHistoryRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestExemptHistoryRenderers_NonEmptyOutput(t *testing.T) {
	entries := []appexempt.AcknowledgmentEntry{{ControlID: "CTL.S3.PUBLIC.001", AssetID: "arn:aws:s3:::bucket"}}
	cases := []struct {
		name     string
		renderer exemptHistoryRenderer
	}{
		{"json", exemptHistoryJSONRenderer{}},
		{"table", exemptHistoryTableRenderer{}},
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

func TestExemptNewSuggestRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", exemptSuggestJSONRenderer{}},
		{"table", exemptSuggestTableRenderer{}},
		{"", exemptSuggestTableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.format, func(t *testing.T) {
			r, err := exemptNewSuggestRenderer(tc.format)
			if err != nil {
				t.Fatalf("exemptNewSuggestRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("exemptNewSuggestRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestExemptNewSuggestRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := exemptNewSuggestRenderer("xml")
	if err == nil {
		t.Fatalf("exemptNewSuggestRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("error should mention \"unknown format\", got: %q", err.Error())
	}
}

func TestExemptSuggestRenderers_NonEmptyOutput(t *testing.T) {
	result := &exemptionsuggest.Result{WindowDays: 30, MinDwellDays: 14}
	cases := []struct {
		name     string
		renderer exemptSuggestRenderer
	}{
		{"json", exemptSuggestJSONRenderer{}},
		{"table", exemptSuggestTableRenderer{}},
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
