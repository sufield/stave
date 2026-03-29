package upcoming

import (
	"bytes"
	"testing"
	"time"

	appupcoming "github.com/sufield/stave/internal/app/prune/upcoming"
	"github.com/sufield/stave/internal/cli/ui"
)

func TestParsePositiveDuration_Valid(t *testing.T) {
	dur, err := parsePositiveDuration("24h", "--max-unsafe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dur != 24*time.Hour {
		t.Fatalf("dur = %v", dur)
	}
}

func TestParsePositiveDuration_Negative(t *testing.T) {
	_, err := parsePositiveDuration("-1h", "--max-unsafe")
	if err == nil {
		t.Fatal("expected error for negative duration")
	}
}

func TestParsePositiveDuration_Zero(t *testing.T) {
	dur, err := parsePositiveDuration("0h", "--max-unsafe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dur != 0 {
		t.Fatalf("dur = %v, want 0", dur)
	}
}

func TestParsePositiveDuration_DaySuffix(t *testing.T) {
	dur, err := parsePositiveDuration("7d", "--max-unsafe")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if dur != 7*24*time.Hour {
		t.Fatalf("dur = %v", dur)
	}
}

func TestToAdapterItems(t *testing.T) {
	items := []appupcoming.UpcomingSnapshot{
		{
			ControlID: "CTL.A.001",
			AssetID:   "bucket-1",
			Status:    "OVERDUE",
		},
	}
	result := toAdapterItems(items)
	if len(result) != 1 {
		t.Fatalf("len = %d", len(result))
	}
	if result[0].ControlID != "CTL.A.001" {
		t.Fatalf("ControlID = %q", result[0].ControlID)
	}
	if result[0].Status != "OVERDUE" {
		t.Fatalf("Status = %q", result[0].Status)
	}
}

func TestToAdapterSummary(t *testing.T) {
	s := appupcoming.UpcomingSummary{
		Overdue: 1,
		DueNow:  2,
		DueSoon: 3,
		Later:   4,
		Total:   10,
	}
	result := toAdapterSummary(s)
	if result.Overdue != 1 || result.DueNow != 2 || result.DueSoon != 3 || result.Later != 4 || result.Total != 10 {
		t.Fatalf("summary mismatch: %+v", result)
	}
}

func TestRenderOutput_JSON(t *testing.T) {
	report := appupcoming.UpcomingReport{}
	var buf bytes.Buffer
	err := renderOutput(&buf, ui.OutputFormatJSON, report, 24*time.Hour)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected output")
	}
}

func TestOptionsNormalize(t *testing.T) {
	opts := &options{
		CtlDir: "controls",
		ObsDir: "observations",
	}
	opts.normalize()
	if opts.CtlDir == "" {
		t.Fatal("CtlDir should not be empty after normalize")
	}
	if opts.ObsDir == "" {
		t.Fatal("ObsDir should not be empty after normalize")
	}
}
