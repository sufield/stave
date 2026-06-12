package nepcmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/platform/providers/aws/iam"
)

func TestRenderPrincipal_KnownFormats(t *testing.T) {
	for _, format := range []string{"json", "table", ""} {
		var buf bytes.Buffer
		if err := renderPrincipal(format, &buf, iam.ResolvedPermissions{}, PrincipalConfig{}); err != nil {
			t.Errorf("renderPrincipal(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderPrincipal(%q) produced empty output", format)
		}
	}
}

func TestRenderPrincipal_UnknownFormatErrors(t *testing.T) {
	err := renderPrincipal("xml", &bytes.Buffer{}, iam.ResolvedPermissions{}, PrincipalConfig{})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestRenderResource_KnownFormats(t *testing.T) {
	payload := resourcePayload{
		ResourceARN:    "arn:aws:s3:::test-bucket",
		DisplayEntries: []iam.ResourceAccessEntry{},
		AllEntries:     []iam.ResourceAccessEntry{},
		Designated:     map[string]bool{},
	}
	for _, format := range []string{"json", "dot", "table", ""} {
		var buf bytes.Buffer
		if err := renderResource(format, &buf, payload); err != nil {
			t.Errorf("renderResource(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderResource(%q) produced empty output", format)
		}
	}
}

func TestRenderResource_UnknownFormatErrors(t *testing.T) {
	err := renderResource("xml", &bytes.Buffer{}, resourcePayload{})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}

func TestRenderSummary_KnownFormats(t *testing.T) {
	for _, format := range []string{"json", "table", ""} {
		var buf bytes.Buffer
		if err := renderSummary(format, &buf, nepSummary{}, SummaryConfig{}); err != nil {
			t.Errorf("renderSummary(%q): %v", format, err)
			continue
		}
		if buf.Len() == 0 {
			t.Errorf("renderSummary(%q) produced empty output", format)
		}
	}
}

func TestRenderSummary_UnknownFormatErrors(t *testing.T) {
	err := renderSummary("xml", &bytes.Buffer{}, nepSummary{}, SummaryConfig{})
	if err == nil || !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("expected unsupported-format error, got: %v", err)
	}
}
