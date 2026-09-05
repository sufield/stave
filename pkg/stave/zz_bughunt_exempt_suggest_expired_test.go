package stave

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	appexempt "github.com/sufield/stave/internal/app/exempt"
	"github.com/sufield/stave/internal/app/exemptionsuggest"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
)

func TestBugHunt_SuggestExemptions_ExpiredException(t *testing.T) {
	tmp := t.TempDir()
	historyDir := filepath.Join(tmp, "history")
	if err := os.MkdirAll(historyDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// 1. Create a historical assessment with a failing finding.
	// We want it to be chronic (dwell > 14 days). Let's make it 30 days ago.
	t0 := time.Now().UTC().Add(-30 * 24 * time.Hour)
	tLatest := time.Now().UTC()
	assess := &report.Assessment{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          report.KindAssessment,
		Run:           evaluation.RunInfo{EvalTime: t0},
		Findings: []remediation.Finding{
			{
				ControlID:       kernel.ControlID("CTL.A.001"),
				AssetID:         asset.ID("asset-1"),
				ControlSeverity: policy.SeverityHigh,
			},
		},
	}
	// And the latest assessment still has it.
	assessLatest := &report.Assessment{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          report.KindAssessment,
		Run:           evaluation.RunInfo{EvalTime: tLatest},
		Findings: []remediation.Finding{
			{
				ControlID:       kernel.ControlID("CTL.A.001"),
				AssetID:         asset.ID("asset-1"),
				ControlSeverity: policy.SeverityHigh,
			},
		},
	}

	writeAssessment := func(name string, a *report.Assessment) {
		data, err := json.Marshal(a)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(historyDir, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeAssessment("t0.json", assess)
	writeAssessment("tLatest.json", assessLatest)

	// 2. Create an acceptance file with an EXPIRED exception for this finding.
	// Since today is tLatest, we set expiry to 10 days ago.
	expiredDate := tLatest.Add(-10 * 24 * time.Hour).Format("2006-01-02")
	af := &appexempt.AcceptanceFile{
		SchemaVersion: "1",
		Exceptions: []appexempt.ExceptionEntry{
			{
				ControlID:  "CTL.A.001",
				AssetID:    "asset-1",
				ExpiryDate: expiredDate,
				Reason:     "temporary bypass",
			},
		},
	}
	afData, err := json.Marshal(af)
	if err != nil {
		t.Fatal(err)
	}
	acceptancePath := filepath.Join(tmp, "exemptions.yaml")
	if writeErr := os.WriteFile(acceptancePath, afData, 0o644); writeErr != nil {
		t.Fatal(writeErr)
	}

	// 3. Run suggest. Since the exception is expired, we expect it to NOT be exempted.
	// So CTL.A.001@asset-1 should be suggested as a chronic candidate.
	resBytes, err := SuggestExemptions(context.Background(), SuggestConfig{
		HistoryDir:     historyDir,
		Window:         "90d",
		MinDwell:       "14d",
		Format:         "json",
		AcceptanceFile: acceptancePath,
	})
	if err != nil {
		t.Fatalf("SuggestExemptions failed: %v", err)
	}

	var res exemptionsuggest.Result
	if err := json.Unmarshal(resBytes, &res); err != nil {
		t.Fatalf("unmarshal suggest result: %v (raw: %s)", err, string(resBytes))
	}

	// Under the buggy code: len(res.Chronic) == 0 (because the expired exception was still counted).
	// Under the correct code: len(res.Chronic) == 1.
	if len(res.Chronic) != 1 {
		t.Errorf("expected 1 chronic candidate, got %d (likely skipped expired exception incorrectly)", len(res.Chronic))
	}
}
