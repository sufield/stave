package test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/stave"
)

func TestNewRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format  string
		verbose bool
		wantTbl bool // expect TableRenderer with given Verbose
		want    any
	}{
		{format: "json", want: JSONRenderer{}},
		{format: "tap", want: TAPRenderer{}},
		{format: "table", verbose: false, wantTbl: true},
		{format: "table", verbose: true, wantTbl: true},
		{format: "", verbose: false, wantTbl: true},
	}
	for _, tc := range cases {
		name := tc.format
		if tc.verbose {
			name += "+verbose"
		}
		if name == "" {
			name = "empty"
		}
		t.Run(name, func(t *testing.T) {
			r, err := NewRenderer(tc.format, tc.verbose)
			if err != nil {
				t.Fatalf("NewRenderer(%q,%v): unexpected error: %v", tc.format, tc.verbose, err)
			}
			if tc.wantTbl {
				got, ok := r.(TableRenderer)
				if !ok {
					t.Fatalf("NewRenderer(%q,%v) = %T, want TableRenderer", tc.format, tc.verbose, r)
				}
				if got.Verbose != tc.verbose {
					t.Errorf("Verbose: got %v, want %v", got.Verbose, tc.verbose)
				}
				return
			}
			if r != tc.want {
				t.Errorf("NewRenderer(%q) = %T, want %T", tc.format, r, tc.want)
			}
		})
	}
}

func TestNewRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewRenderer("xml", false)
	if err == nil {
		t.Fatalf("NewRenderer(\"xml\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestRenderers_NonEmptyOutput(t *testing.T) {
	results := []stave.TestResult{}
	summary := stave.TestSummary{}
	cases := []struct {
		name     string
		renderer Renderer
	}{
		{"json", JSONRenderer{}},
		{"tap", TAPRenderer{}},
		{"table", TableRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := tc.renderer.Render(&buf, results, summary); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if buf.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}
