package fix

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/domain/policy"
)

func TestRunFix_WithExistingRemediationPlan(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "evaluation.json")
	payload := map[string]any{
		"findings": []remediation.Finding{
			{
				Finding: evaluation.Finding{
					ControlID:   "CTL.S3.PUBLIC.001",
					ControlName: "No Public S3 Bucket Read",
					AssetID:     "bucket-a",
					AssetType:   "storage_bucket",
				},
				RemediationSpec: policy.RemediationSpec{Action: "Enable controls."},
				RemediationPlan: &evaluation.RemediationPlan{
					ID: "fix-123",
					Target: evaluation.RemediationTarget{
						AssetID:   "bucket-a",
						AssetType: "storage_bucket",
					},
					Actions: []evaluation.RemediationAction{{ActionType: "set", Path: "p", Value: true}},
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	cmd := NewFixCmd()
	fixInputPath = in
	fixFindingRef = "CTL.S3.PUBLIC.001@bucket-a"
	cmd.SetOut(buf)
	if err := runFix(cmd, nil); err != nil {
		t.Fatalf("runFix error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "Fix Plan") {
		t.Fatalf("missing fix plan section: %s", out)
	}
	if !strings.Contains(out, "fix-123") {
		t.Fatalf("missing fix plan id: %s", out)
	}
}

func TestRunFix_MissingFinding(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "evaluation.json")
	payload := map[string]any{
		"findings": []remediation.Finding{
			{Finding: evaluation.Finding{ControlID: "CTL.S3.PUBLIC.001", AssetID: "bucket-a"}},
		},
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := NewFixCmd()
	fixInputPath = in
	fixFindingRef = "CTL.S3.PUBLIC.001@missing"
	cmd.SetOut(&bytes.Buffer{})
	err := runFix(cmd, nil)
	if err == nil {
		t.Fatal("expected missing finding error")
	}
	if !strings.Contains(err.Error(), "available finding IDs") {
		t.Fatalf("unexpected error: %v", err)
	}
}
