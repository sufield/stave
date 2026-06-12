package graphcmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/sanitize"
)

func TestNewCoverageRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format Format
		want   any
	}{
		{FormatDot, coverageDotRenderer{}},
		{FormatJSON, coverageJSONRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewCoverageRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewCoverageRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewCoverageRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewCoverageRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewCoverageRenderer(Format("yaml"))
	if err == nil {
		t.Fatalf("NewCoverageRenderer(\"yaml\"): want error, got %T", r)
	}
	if r != nil {
		t.Errorf("NewCoverageRenderer(\"yaml\"): want nil renderer, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported coverage format") {
		t.Errorf("error should mention \"unsupported coverage format\", got: %q", err.Error())
	}
}

func TestCoverageRenderers_NonEmptyOutput(t *testing.T) {
	result := CoverageResult{
		Controls:        []kernel.ControlID{"CTL.A.FOO.001"},
		Assets:          []asset.ID{"bucket-1"},
		Edges:           []CoverageEdge{{ControlID: "CTL.A.FOO.001", AssetID: "bucket-1"}},
		UncoveredAssets: []asset.ID{},
	}
	san := sanitize.New()
	cases := []struct {
		name     string
		renderer CoverageRenderer
	}{
		{"dot", coverageDotRenderer{}},
		{"json", coverageJSONRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, result, san); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}
