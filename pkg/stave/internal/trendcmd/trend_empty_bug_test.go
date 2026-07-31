package trendcmd

import (
	"context"
	"testing"
)

func TestTrendReport_EmptyAssessments_ReturnsErrorNotPanic(t *testing.T) {
	tmpDir := t.TempDir() // Empty directory

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("TrendReport panicked on empty assessments: %v", r)
		}
	}()

	cfg := TrendConfig{
		HistoryDir: tmpDir,
		MinRuns:    0, // MinRuns = 0 should not bypass empty assessments check
	}

	_, _, err := TrendReport(context.Background(), cfg)
	if err == nil {
		t.Fatalf("expected error for empty assessment history, got nil")
	}
}
