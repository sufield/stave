package snapshot

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/sufield/stave/internal/core/asset"
)

// Verify that TOO_FEW_SNAPSHOTS evidence carries the actual values, not zeros.
// Sanity check on the new(value) pattern in checkCount.
func TestQualityEvidence_TooFewSnapshots_ActualValues(t *testing.T) {
	report := assessQuality(qualityParams{
		Snapshots:    []asset.Snapshot{{CapturedAt: time.Now().UTC(), Assets: []asset.Asset{{ID: "x"}}}},
		Now:          time.Now().UTC(),
		MinSnapshots: 5,
		MaxStaleness: 48 * time.Hour,
		MaxGap:       7 * 24 * time.Hour,
	})
	var found *qualityIssue
	for i := range report.Issues {
		if report.Issues[i].Code == "TOO_FEW_SNAPSHOTS" {
			found = &report.Issues[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("expected TOO_FEW_SNAPSHOTS issue, got %+v", report.Issues)
	}
	if found.Evidence == nil || found.Evidence.MinSnapshots == nil || found.Evidence.Actual == nil {
		t.Fatalf("expected non-nil evidence with both pointers, got %+v", found.Evidence)
	}
	if *found.Evidence.MinSnapshots != 5 {
		t.Errorf("MinSnapshots = %d, want 5", *found.Evidence.MinSnapshots)
	}
	if *found.Evidence.Actual != 1 {
		t.Errorf("Actual = %d, want 1", *found.Evidence.Actual)
	}
	b, _ := json.Marshal(found.Evidence)
	if !strings.Contains(string(b), `"min_snapshots":5`) || !strings.Contains(string(b), `"actual":1`) {
		t.Errorf("JSON evidence missing expected values: %s", b)
	}
}
