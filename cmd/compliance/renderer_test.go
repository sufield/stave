package compliance

import (
	"bytes"
	"strings"
	"testing"

	cm "github.com/sufield/stave/internal/compliancemapping"
)

func sampleReport() *cm.Report {
	return &cm.Report{
		Framework: "TEST", FrameworkVersion: "1.0", TotalControls: 4,
		Covered: []cm.ControlResult{
			{ID: "X-01", Title: "Pass One", Status: cm.StatusPass, Bucket: cm.BucketCovered, StaveControls: []string{"CTL.A"}},
			{ID: "X-02", Title: "Fail One", Status: cm.StatusFail, Bucket: cm.BucketCovered, StaveControls: []string{"CTL.B"}, FailedControls: []string{"CTL.B"}, Partial: true},
		},
		Gaps:       []cm.ControlResult{{ID: "X-03", Title: "Gap One", Status: cm.StatusNotVerified, Bucket: cm.BucketGap, Detail: "build a control"}},
		OutOfScope: []cm.ControlResult{{ID: "X-04", Title: "Org One", Status: cm.StatusOutOfScope, Bucket: cm.BucketOutOfScope, OutOfScopeKind: "ORGANIZATIONAL"}},
		InScope:    3, Verified: 2, Passed: 1, Failed: 1, CoveragePercent: 66.67,
	}
}

func TestNewRenderer_UnknownFormat(t *testing.T) {
	if _, err := NewRenderer("yaml"); err == nil {
		t.Fatal("expected error for unknown format")
	}
	for _, f := range []string{"", "text", "json", "markdown", "md"} {
		if _, err := NewRenderer(f); err != nil {
			t.Errorf("format %q: unexpected error %v", f, err)
		}
	}
}

func TestRenderers_ContainKeyFacts(t *testing.T) {
	for _, format := range []string{"text", "json", "markdown"} {
		r, err := NewRenderer(format)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		if err := r.Render(&buf, sampleReport()); err != nil {
			t.Fatalf("%s render: %v", format, err)
		}
		out := buf.String()
		for _, want := range []string{"X-01", "X-02", "X-03", "X-04"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s output missing %q", format, want)
			}
		}
		// Coverage figure surfaces in every format.
		if !strings.Contains(out, "2") || !strings.Contains(out, "3") {
			t.Errorf("%s output missing coverage figures", format)
		}
	}
}
