package domain

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
)

// TestRunInfo_OfflineField verifies the offline field is always present and true in JSON.
func TestRunInfo_OfflineField(t *testing.T) {
	info := evaluation.RunInfo{
		StaveVersion:      "test",
		Offline:           true,
		Now:               time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		MaxUnsafeDuration: kernel.Duration(168 * time.Hour),
		Snapshots:         2,
	}

	data, err := json.Marshal(info)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	offline, ok := raw["offline"]
	if !ok {
		t.Fatal("JSON output missing 'offline' field")
	}
	if offline != true {
		t.Errorf("offline field = %v, want true", offline)
	}
}
