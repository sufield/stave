package applycmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/findings"
	"github.com/sufield/stave/internal/core/kernel"
)

func writeSnapshot(t *testing.T, dir, filename string, capturedAt time.Time) {
	t.Helper()
	snap := map[string]any{
		"schema_version": "obs.v0.1",
		"captured_at":    capturedAt.Format(time.RFC3339),
		"generated_by":   map[string]any{"source_type": "test"},
		"source":         "deployed",
		"assets": []map[string]any{{
			"id":     "asset-1",
			"type":   "aws_s3_bucket",
			"vendor": "aws",
			"properties": map[string]any{
				"storage": map[string]any{"access": map[string]any{"public_read": false}},
			},
		}},
	}
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filename), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func testReport(n int) *evaluation.ComplianceReport {
	fs := make([]evaluation.Finding, n)
	for i := range fs {
		fs[i] = evaluation.Finding{
			ControlID: kernel.ControlID("CTL.TEST." + string(rune('A'+i))),
		}
	}
	return &evaluation.ComplianceReport{Findings: fs}
}

func TestAnnotateFreshness(t *testing.T) {
	t.Parallel()

	t.Run("stale snapshot downgrades to LOW", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		captured := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
		writeSnapshot(t, dir, "2026-01-10T000000Z.json", captured)

		report := testReport(3)
		now := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC) // 48h after capture
		err := annotateFreshness(report, dir, "24h", false, now)
		if err != nil {
			t.Fatal(err)
		}
		for i, f := range report.Findings {
			if f.Confidence != evaluation.ConfidenceLow {
				t.Errorf("finding[%d] confidence = %q, want LOW", i, f.Confidence)
			}
			if f.FreshnessReason == "" {
				t.Errorf("finding[%d] freshness_reason empty", i)
			}
		}
		if report.InputFreshness == nil {
			t.Fatal("InputFreshness not set")
		}
		if !report.InputFreshness.Stale {
			t.Error("InputFreshness.Stale = false, want true")
		}
		if report.InputFreshness.StaleFindings != 3 {
			t.Errorf("StaleFindings = %d, want 3", report.InputFreshness.StaleFindings)
		}
	})

	t.Run("fresh snapshot keeps HIGH", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		captured := time.Date(2026, 1, 14, 23, 0, 0, 0, time.UTC)
		writeSnapshot(t, dir, "2026-01-14T230000Z.json", captured)

		report := testReport(2)
		now := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC) // 1h after capture
		err := annotateFreshness(report, dir, "24h", false, now)
		if err != nil {
			t.Fatal(err)
		}
		for i, f := range report.Findings {
			if f.Confidence != evaluation.ConfidenceHigh {
				t.Errorf("finding[%d] confidence = %q, want HIGH", i, f.Confidence)
			}
			if f.FreshnessReason != "" {
				t.Errorf("finding[%d] freshness_reason should be empty", i)
			}
		}
		if report.InputFreshness == nil {
			t.Fatal("InputFreshness not set")
		}
		if report.InputFreshness.Stale {
			t.Error("InputFreshness.Stale = true, want false")
		}
	})

	t.Run("skip-freshness preserves original confidence", func(t *testing.T) {
		t.Parallel()
		report := testReport(1)
		err := annotateFreshness(report, "/nonexistent", "24h", true, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if report.Findings[0].Confidence != "" {
			t.Errorf("confidence should be empty when skipped, got %q", report.Findings[0].Confidence)
		}
		if report.InputFreshness != nil {
			t.Error("InputFreshness should be nil when skipped")
		}
	})

	t.Run("eval-time close to captured_at is fresh", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		captured := time.Date(2026, 1, 15, 0, 0, 0, 0, time.UTC)
		writeSnapshot(t, dir, "2026-01-15T000000Z.json", captured)

		report := testReport(1)
		now := time.Date(2026, 1, 15, 0, 5, 0, 0, time.UTC) // 5 min after
		err := annotateFreshness(report, dir, "24h", false, now)
		if err != nil {
			t.Fatal(err)
		}
		if report.Findings[0].Confidence != evaluation.ConfidenceHigh {
			t.Errorf("confidence = %q, want HIGH", report.Findings[0].Confidence)
		}
	})

	t.Run("compound chain findings downgraded when stale", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		captured := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)
		writeSnapshot(t, dir, "2026-01-10T000000Z.json", captured)

		report := testReport(1)
		report.ChainFindings = []findings.CompoundFinding{{
			ChainID:  "test_chain",
			Severity: 4,
		}}
		now := time.Date(2026, 1, 12, 0, 0, 0, 0, time.UTC)
		err := annotateFreshness(report, dir, "24h", false, now)
		if err != nil {
			t.Fatal(err)
		}
		if report.ChainFindings[0].Confidence != "LOW" {
			t.Errorf("chain confidence = %q, want LOW", report.ChainFindings[0].Confidence)
		}
	})

	t.Run("bad threshold returns ErrInvalidInput", func(t *testing.T) {
		t.Parallel()
		report := testReport(0)
		err := annotateFreshness(report, "/some/dir", "not-a-duration", false, time.Now())
		if err == nil {
			t.Fatal("expected error for bad threshold")
		}
	})

	t.Run("stdin observations are skipped", func(t *testing.T) {
		t.Parallel()
		report := testReport(1)
		err := annotateFreshness(report, "-", "24h", false, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if report.InputFreshness != nil {
			t.Error("stdin mode should skip freshness")
		}
	})
}
