package collectorcontract

import (
	"bytes"
	"testing"
)

func TestReport_NilReportGuards(t *testing.T) {
	var r *Report

	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("collectorcontract report functions panicked on nil report: %v", rec)
		}
	}()

	var buf bytes.Buffer
	errText := WriteText(&buf, r, false)
	if errText == nil {
		t.Errorf("expected error from WriteText on nil report")
	}

	errJSON := WriteJSON(&buf, r)
	if errJSON == nil {
		t.Errorf("expected error from WriteJSON on nil report")
	}

	if r.HasViolations() {
		t.Errorf("expected HasViolations false for nil report")
	}
	if r.HasWarnings() {
		t.Errorf("expected HasWarnings false for nil report")
	}
	if r.ViolationCount() != 0 {
		t.Errorf("expected ViolationCount 0 for nil report")
	}
	if r.CoveragePercent() != 0 {
		t.Errorf("expected CoveragePercent 0 for nil report")
	}
}
