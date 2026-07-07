package text

import (
	"bytes"
	"strings"
	"testing"
	"time"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/coverage"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
)

// TestFindingWriter_OmitsCoveragePosture locks in the removal of the
// "Coverage posture" / "Not covered (prowler …)" section from text output.
// That section listed external-tool checks Stave does not cover — a
// catalog-comparison artifact with no actionable next step for an operator
// triaging findings (coverage analysis is the separate stave-coverage tool's
// job). It was pure noise on every verbose run.
func TestFindingWriter_OmitsCoveragePosture(t *testing.T) {
	w := &FindingWriter{Verbose: true}
	enricher := remediation.NewPlanner()
	result := evaluation.ComplianceReport{
		Run: evaluation.RunInfo{
			StaveVersion:   "test",
			Offline:        true,
			EvalTime:       time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC),
			Snapshots:      1,
			EvaluatedState: "deployed",
		},
		Summary: evaluation.ComplianceSummary{TotalAssets: 1, ExposedResources: 0, Violations: 0},
	}
	enriched, err := appeval.Enrich(enricher, nil, &result)
	if err != nil {
		t.Fatal(err)
	}
	// Populate the coverage data that used to render the noisy section.
	enriched.CoveragePosture = &coverage.CoverageIndex{
		ByTool: map[string]map[string]coverage.DomainCoverage{
			"prowler": {"s3": {Covered: 20, Total: 21, NotCoveredChecks: []string{"s3_bucket_event_notifications_enabled"}}},
		},
	}

	data, err := w.MarshalFindings(&enriched)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.Write(data)
	out := buf.String()

	for _, noise := range []string{"Coverage posture", "Not covered", "checks covered"} {
		if strings.Contains(out, noise) {
			t.Errorf("verbose text output must not include coverage-posture noise %q:\n%s", noise, out)
		}
	}
}
