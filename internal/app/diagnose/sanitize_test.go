package diagnose

import (
	"strings"
	"testing"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
)

type stubSanitizer struct{}

func (stubSanitizer) ID(id string) string { return "REDACTED" }

func TestSanitizeDiagnosisReport(t *testing.T) {
	r := &diagnosis.Report{
		Issues: []diagnosis.Issue{
			{
				Case:     "violation_evidence",
				Signal:   "test",
				Evidence: "asset=my-bucket duration=24h",
				AssetID:  "my-bucket",
			},
			{
				Case:   "empty_findings",
				Signal: "no asset",
			},
		},
	}

	s := stubSanitizer{}
	out := SanitizeDiagnosisReport(s, r)

	if out == r {
		t.Error("expected new report, got same pointer")
	}
	if string(out.Issues[0].AssetID) != "REDACTED" {
		t.Errorf("AssetID = %q, want REDACTED", out.Issues[0].AssetID)
	}
	if strings.Contains(string(out.Issues[0].Evidence), "my-bucket") {
		t.Error("Evidence still contains raw asset ID")
	}
	if out.Issues[1].AssetID != "" {
		t.Error("empty AssetID should remain empty")
	}
}

func TestSanitizeDiagnosisReport_Nil(t *testing.T) {
	if got := SanitizeDiagnosisReport(stubSanitizer{}, nil); got != nil {
		t.Error("expected nil for nil input")
	}
}
