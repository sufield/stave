package contracts

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/risk"
)

func TestOutputFormat_String(t *testing.T) {
	if FormatJSON.String() != "json" {
		t.Errorf("FormatJSON.String() = %q", FormatJSON.String())
	}
	if FormatText.String() != "text" {
		t.Errorf("FormatText.String() = %q", FormatText.String())
	}
}

func TestOutputFormat_IsJSON(t *testing.T) {
	if !FormatJSON.IsJSON() {
		t.Error("FormatJSON.IsJSON() should be true")
	}
	if FormatText.IsJSON() {
		t.Error("FormatText.IsJSON() should be false")
	}
}

func TestSnapshotStats_Total(t *testing.T) {
	s := SnapshotStats{Active: 3, Archived: 2}
	if s.Total() != 5 {
		t.Errorf("Total() = %d, want 5", s.Total())
	}
}

func TestSnapshotStats_MarshalJSON(t *testing.T) {
	s := SnapshotStats{Active: 3, Archived: 2}
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["total"] != float64(5) {
		t.Errorf("total = %v", m["total"])
	}
}

func TestRiskStats_UpcomingTotal(t *testing.T) {
	r := RiskStats{Overdue: 1, DueNow: 2, DueSoon: 3, Later: 4}
	if r.UpcomingTotal() != 10 {
		t.Errorf("UpcomingTotal() = %d, want 10", r.UpcomingTotal())
	}
}

func TestRiskStats_MarshalJSON(t *testing.T) {
	r := RiskStats{Overdue: 1, DueNow: 2, DueSoon: 3, Later: 4}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["upcoming_total"] != float64(10) {
		t.Errorf("upcoming_total = %v", m["upcoming_total"])
	}
}

// --- LoadControls / LoadSnapshots wrappers ---

type stubCtlRepo struct {
	controls []policy.ControlDefinition
	err      error
}

func (s stubCtlRepo) LoadControls(_ context.Context, _ string) ([]policy.ControlDefinition, error) {
	return s.controls, s.err
}

type stubObsRepo struct {
	result LoadResult
	err    error
}

func (s stubObsRepo) LoadSnapshots(_ context.Context, _ string) (LoadResult, error) {
	return s.result, s.err
}

func TestLoadControls_Success(t *testing.T) {
	repo := stubCtlRepo{controls: []policy.ControlDefinition{{ID: "CTL.A"}}}
	result, err := LoadControls(context.Background(), repo, "/ctl")
	if err != nil {
		t.Fatalf("LoadControls() error = %v", err)
	}
	if len(result) != 1 || result[0].ID != "CTL.A" {
		t.Errorf("result = %v", result)
	}
}

func TestLoadControls_Error(t *testing.T) {
	repo := stubCtlRepo{err: errors.New("boom")}
	_, err := LoadControls(context.Background(), repo, "/ctl")
	if err == nil || !strings.Contains(err.Error(), "failed to load controls") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}

func TestLoadSnapshots_Success(t *testing.T) {
	repo := stubObsRepo{result: LoadResult{}}
	_, err := LoadSnapshots(context.Background(), repo, "/obs")
	if err != nil {
		t.Fatalf("LoadSnapshots() error = %v", err)
	}
}

func TestLoadSnapshots_Error(t *testing.T) {
	repo := stubObsRepo{err: errors.New("boom")}
	_, err := LoadSnapshots(context.Background(), repo, "/obs")
	if err == nil || !strings.Contains(err.Error(), "failed to load observations") {
		t.Fatalf("expected wrapped error, got: %v", err)
	}
}

func TestNewRiskStats(t *testing.T) {
	summary := risk.ThresholdSummary{
		Overdue: 1,
		DueNow:  2,
		DueSoon: 3,
		Later:   4,
	}
	r := NewRiskStats(5, summary)
	if r.CurrentViolations != 5 {
		t.Errorf("CurrentViolations = %d", r.CurrentViolations)
	}
	if r.Overdue != 1 || r.DueNow != 2 || r.DueSoon != 3 || r.Later != 4 {
		t.Errorf("risk stats mismatch: %+v", r)
	}
}
