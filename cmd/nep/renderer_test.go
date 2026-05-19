package nep

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

// --- PrincipalRenderer ---

func TestNewPrincipalRenderer_KnownFormats(t *testing.T) {
	opts := &principalOpts{}
	for _, format := range []string{"json", "table", ""} {
		r, err := NewPrincipalRenderer(format, opts)
		if err != nil {
			t.Errorf("NewPrincipalRenderer(%q): %v", format, err)
			continue
		}
		switch format {
		case "json":
			if _, ok := r.(PrincipalJSONRenderer); !ok {
				t.Errorf("got %T, want PrincipalJSONRenderer", r)
			}
		default:
			if _, ok := r.(PrincipalTableRenderer); !ok {
				t.Errorf("got %T, want PrincipalTableRenderer", r)
			}
		}
	}
}

func TestNewPrincipalRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewPrincipalRenderer("xml", &principalOpts{}); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestPrincipalRenderers_NonEmptyOutput(t *testing.T) {
	result := iam.ResolvedPermissions{}
	opts := &principalOpts{}
	for _, r := range []PrincipalRenderer{PrincipalJSONRenderer{}, PrincipalTableRenderer{Opts: opts}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, result); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}

// --- ResourceRenderer ---

func TestNewResourceRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format string
		want   any
	}{
		{"json", ResourceJSONRenderer{}},
		{"dot", ResourceDOTRenderer{}},
		{"table", ResourceTableRenderer{}},
		{"", ResourceTableRenderer{}},
	}
	for _, tc := range cases {
		r, err := NewResourceRenderer(tc.format)
		if err != nil {
			t.Errorf("NewResourceRenderer(%q): %v", tc.format, err)
			continue
		}
		if r != tc.want {
			t.Errorf("NewResourceRenderer(%q) = %T, want %T", tc.format, r, tc.want)
		}
	}
}

func TestNewResourceRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewResourceRenderer("xml"); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestResourceRenderers_NonEmptyOutput(t *testing.T) {
	payload := ResourcePayload{
		ResourceARN:    "arn:aws:s3:::test-bucket",
		DisplayEntries: []iam.ResourceAccessEntry{},
		AllEntries:     []iam.ResourceAccessEntry{},
		Designated:     map[string]bool{},
		ShowDesignated: false,
	}
	for _, r := range []ResourceRenderer{ResourceJSONRenderer{}, ResourceDOTRenderer{}, ResourceTableRenderer{}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, payload); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}

// --- SummaryRenderer ---

func TestNewSummaryRenderer_KnownFormats(t *testing.T) {
	opts := &summaryOpts{}
	for _, format := range []string{"json", "table", ""} {
		r, err := NewSummaryRenderer(format, opts)
		if err != nil {
			t.Errorf("NewSummaryRenderer(%q): %v", format, err)
			continue
		}
		switch format {
		case "json":
			if _, ok := r.(SummaryJSONRenderer); !ok {
				t.Errorf("got %T, want SummaryJSONRenderer", r)
			}
		default:
			if _, ok := r.(SummaryTableRenderer); !ok {
				t.Errorf("got %T, want SummaryTableRenderer", r)
			}
		}
	}
}

func TestNewSummaryRenderer_UnknownFormatErrors(t *testing.T) {
	if _, err := NewSummaryRenderer("xml", &summaryOpts{}); err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestSummaryRenderers_NonEmptyOutput(t *testing.T) {
	summary := nepSummary{}
	opts := &summaryOpts{}
	for _, r := range []SummaryRenderer{SummaryJSONRenderer{}, SummaryTableRenderer{Opts: opts}} {
		var buf bytes.Buffer
		if err := r.Render(&buf, summary); err != nil {
			t.Errorf("%T.Render: %v", r, err)
		}
		if buf.Len() == 0 {
			t.Errorf("%T produced empty output", r)
		}
	}
}
