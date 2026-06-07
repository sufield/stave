package apply

import (
	"bytes"
	"strings"
	"testing"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	validation "github.com/sufield/stave/internal/core/schemaval"
)

func TestNewReadinessRenderer_KnownFormats(t *testing.T) {
	cases := []struct {
		format appcontracts.OutputFormat
		want   any
	}{
		{appcontracts.FormatJSON, ReadinessJSONRenderer{}},
		{appcontracts.FormatText, ReadinessTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(string(tc.format), func(t *testing.T) {
			r, err := NewReadinessRenderer(tc.format)
			if err != nil {
				t.Fatalf("NewReadinessRenderer(%q): unexpected error: %v", tc.format, err)
			}
			if got, want := r, tc.want; got != want {
				t.Errorf("NewReadinessRenderer(%q) = %T, want %T", tc.format, got, want)
			}
		})
	}
}

func TestNewReadinessRenderer_UnknownFormatErrors(t *testing.T) {
	r, err := NewReadinessRenderer(appcontracts.OutputFormat("bogus"))
	if err == nil {
		t.Fatalf("NewReadinessRenderer(\"bogus\"): want error, got %T", r)
	}
	if !strings.Contains(err.Error(), "unsupported format") {
		t.Errorf("error should mention \"unsupported format\", got: %q", err.Error())
	}
}

func TestReadinessRenderers_NonEmptyOutput(t *testing.T) {
	report := validation.ReadinessAssessment{
		IsSafe:            true,
		ControlSource:     "controls/s3",
		ObservationSource: "observations",
		Summary: validation.AssessmentSummary{
			ControlsVerified:  5,
			StatesVerified:    3,
			ResourcesAnalyzed: 10,
		},
	}
	cases := []struct {
		name     string
		renderer ReadinessRenderer
	}{
		{"json", ReadinessJSONRenderer{}},
		{"text", ReadinessTextRenderer{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := tc.renderer.Render(&stdout, &stderr, report); err != nil {
				t.Fatalf("Render: unexpected error: %v", err)
			}
			if stdout.Len() == 0 {
				t.Errorf("Render produced empty output")
			}
		})
	}
}
