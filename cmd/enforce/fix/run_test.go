package fix

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	stavecel "github.com/sufield/stave/internal/cel"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/core/predicate"
)

func newTestRunner(t *testing.T) *Runner {
	t.Helper()
	celEval, err := stavecel.NewPredicateEval()
	if err != nil {
		t.Fatalf("create CEL evaluator: %v", err)
	}
	return NewRunner(celEval, ports.RealClock{})
}

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
					Actions: []evaluation.RemediationAction{{ActionType: "set", Path: predicate.NewFieldPath("p"), Value: true}},
				},
			},
		},
	}
	data, _ := json.Marshal(payload)
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}

	buf := &bytes.Buffer{}
	runner := newTestRunner(t)
	if err := runner.Run(context.Background(), Request{
		InputPath:  in,
		FindingRef: "CTL.S3.PUBLIC.001@bucket-a",
		Stdout:     buf,
	}); err != nil {
		t.Fatalf("Fix error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, `"fix_plan"`) {
		t.Fatalf("missing fix_plan in JSON output: %s", out)
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

	runner := newTestRunner(t)
	err := runner.Run(context.Background(), Request{
		InputPath:  in,
		FindingRef: "CTL.S3.PUBLIC.001@missing",
		Stdout:     &bytes.Buffer{},
	})
	if err == nil {
		t.Fatal("expected missing finding error")
	}
	if !strings.Contains(err.Error(), "available findings") {
		t.Fatalf("unexpected error: %v", err)
	}
}
