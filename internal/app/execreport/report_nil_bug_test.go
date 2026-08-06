package execreport

import (
	"testing"
)

func TestGenerateSummary_NilReportHandledSafely(t *testing.T) {
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("GenerateSummary panicked on nil report: %v", rec)
		}
	}()

	summary := GenerateSummary(nil)
	if summary.OneLiner != "" || summary.Paragraph != "" {
		t.Errorf("expected empty ExecutiveSummary for nil report")
	}
}
