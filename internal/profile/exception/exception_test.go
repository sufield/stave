package exception

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/profile"
)

func writeYAML(t *testing.T, dir, content string) string {
	t.Helper()
	path := filepath.Join(dir, "stave.yaml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadExceptions_Valid(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, `
exceptions:
  - control_id: ACCESS.001
    bucket: my-bucket
    rationale: "CloudFront OAI pattern"
    acknowledged_by: bala@example.com
    acknowledged_date: "2026-03-28"
    requires_passing:
      - CONTROLS.001
      - AUDIT.001
`)
	excs, err := LoadExceptions(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(excs) != 1 {
		t.Fatalf("got %d exceptions, want 1", len(excs))
	}
	if excs[0].ControlID != "ACCESS.001" {
		t.Errorf("ControlID: got %q", excs[0].ControlID)
	}
	if len(excs[0].RequiresPassing) != 2 {
		t.Errorf("RequiresPassing: got %d", len(excs[0].RequiresPassing))
	}
	if excs[0].AcknowledgedDate.IsZero() {
		t.Error("AcknowledgedDate should be parsed")
	}
}

func TestLoadExceptions_MissingFile(t *testing.T) {
	excs, err := LoadExceptions("/nonexistent/stave.yaml")
	if err != nil {
		t.Fatalf("missing file should not error: %v", err)
	}
	if excs != nil {
		t.Error("expected nil exceptions")
	}
}

func TestLoadExceptions_NoRequiresPassing(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, `
exceptions:
  - control_id: ACCESS.001
    bucket: my-bucket
    rationale: "Some reason"
    acknowledged_by: test@example.com
`)
	_, err := LoadExceptions(path)
	if err == nil {
		t.Fatal("expected error for missing requires_passing")
	}
	if !strings.Contains(err.Error(), "requires_passing") {
		t.Errorf("error should mention requires_passing: %v", err)
	}
}

func TestLoadExceptions_MissingRationale(t *testing.T) {
	dir := t.TempDir()
	path := writeYAML(t, dir, `
exceptions:
  - control_id: ACCESS.001
    bucket: my-bucket
    requires_passing:
      - CONTROLS.001
`)
	_, err := LoadExceptions(path)
	if err == nil {
		t.Fatal("expected error for missing rationale")
	}
}

func TestApplyExceptions_ValidException(t *testing.T) {
	results := []profile.ProfileResult{
		{Result: compliance.Result{ControlID: "ACCESS.001", Pass: false, Severity: policy.SeverityCritical, Finding: "BPA disabled"}},
		{Result: compliance.Result{ControlID: "CONTROLS.001", Pass: true, Severity: policy.SeverityHigh}},
		{Result: compliance.Result{ControlID: "AUDIT.001", Pass: true, Severity: policy.SeverityCritical}},
	}

	excs := []ExceptionConfig{{
		ControlID:       "ACCESS.001",
		Bucket:          "my-bucket",
		Rationale:       "CloudFront OAI",
		AcknowledgedBy:  "bala@example.com",
		RequiresPassing: []kernel.ControlID{"CONTROLS.001", "AUDIT.001"},
	}}

	acks := ApplyExceptions(excs, results)
	if len(acks) != 1 {
		t.Fatalf("got %d acks, want 1", len(acks))
	}
	if !acks[0].Valid {
		t.Error("exception should be valid")
	}

	// Result should now be ACKNOWLEDGED (pass=true).
	if !results[0].Pass {
		t.Error("ACCESS.001 result should be changed to pass")
	}
	if !strings.Contains(results[0].Finding, "ACKNOWLEDGED") {
		t.Error("finding should contain ACKNOWLEDGED")
	}
}

func TestApplyExceptions_CompensatingControlFailing(t *testing.T) {
	results := []profile.ProfileResult{
		{Result: compliance.Result{ControlID: "ACCESS.001", Pass: false, Severity: policy.SeverityCritical, Finding: "BPA disabled"}},
		{Result: compliance.Result{ControlID: "CONTROLS.001", Pass: false, Severity: policy.SeverityHigh}},
		{Result: compliance.Result{ControlID: "AUDIT.001", Pass: true, Severity: policy.SeverityCritical}},
	}

	excs := []ExceptionConfig{{
		ControlID:       "ACCESS.001",
		Bucket:          "my-bucket",
		Rationale:       "CloudFront OAI",
		AcknowledgedBy:  "bala@example.com",
		RequiresPassing: []kernel.ControlID{"CONTROLS.001", "AUDIT.001"},
	}}

	acks := ApplyExceptions(excs, results)
	if len(acks) != 1 {
		t.Fatalf("got %d acks, want 1", len(acks))
	}
	if acks[0].Valid {
		t.Error("exception should be invalid")
	}
	if acks[0].InvalidReason != InvalidReasonCompensatingFailed {
		t.Errorf("InvalidReason = %q, want %q", acks[0].InvalidReason, InvalidReasonCompensatingFailed)
	}
	if !strings.Contains(acks[0].InvalidDetail, "CONTROLS.001") {
		t.Errorf("InvalidDetail should mention CONTROLS.001: %s", acks[0].InvalidDetail)
	}

	// Result should still be FAIL.
	if results[0].Pass {
		t.Error("ACCESS.001 should remain failing")
	}
	if !strings.Contains(results[0].Finding, "compensating control") {
		t.Error("finding should note failed compensating control")
	}
}

func TestApplyExceptions_NoExceptions(t *testing.T) {
	results := []profile.ProfileResult{
		{Result: compliance.Result{ControlID: "ACCESS.001", Pass: false}},
	}
	acks := ApplyExceptions(nil, results)
	if len(acks) != 0 {
		t.Error("expected no acks")
	}
}

func TestApplyExceptions_AlreadyPassing(t *testing.T) {
	results := []profile.ProfileResult{
		{Result: compliance.Result{ControlID: "ACCESS.001", Pass: true}},
	}
	excs := []ExceptionConfig{{
		ControlID:       "ACCESS.001",
		Bucket:          "my-bucket",
		Rationale:       "test",
		RequiresPassing: []kernel.ControlID{"CONTROLS.001"},
	}}
	acks := ApplyExceptions(excs, results)
	if len(acks) != 0 {
		t.Error("already passing invariant should not produce ack")
	}
}
