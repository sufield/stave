package enginetest

import (
	"encoding/json"
	"testing"

	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestIssue_MarshalJSON_SensitiveEvidence(t *testing.T) {
	evidence := kernel.NewSanitizableMap(map[string]string{
		"control_id": "CTL.EXP.STATE.001",
	})
	evidence.SetSensitive("error", "parse error at /secret/path")

	issue := diag.Diagnostic{
		Code:     diag.CodeControlBadDurationParam,
		Signal:   diag.SignalError,
		Evidence: evidence,
		Action:   "Fix the issue",
	}

	data, err := json.Marshal(issue)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	var evidenceMap map[string]string
	if err := json.Unmarshal(raw["evidence"], &evidenceMap); err != nil {
		t.Fatalf("Unmarshal evidence error: %v", err)
	}

	if evidenceMap["control_id"] != "CTL.EXP.STATE.001" {
		t.Errorf("control_id = %q, want %q", evidenceMap["control_id"], "CTL.EXP.STATE.001")
	}
	if evidenceMap["error"] != kernel.Redacted {
		t.Errorf("error = %q, want %q (should be sanitized)", evidenceMap["error"], kernel.Redacted)
	}
}

func TestIssue_MarshalJSON_NonSensitiveEvidence(t *testing.T) {
	issue := diag.Diagnostic{
		Code:   diag.CodeSingleSnapshot,
		Signal: diag.SignalWarn,
		Evidence: kernel.NewSanitizableMap(map[string]string{
			"snapshot_count": "1",
		}),
		Action: "Add more snapshots",
	}

	data, err := json.Marshal(issue)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	// Non-sensitive evidence should serialize identically to a plain map
	type plainIssue struct {
		Code     string            `json:"code"`
		Signal   diag.Signal       `json:"signal"`
		Evidence map[string]string `json:"evidence"`
		Action   string            `json:"action"`
	}

	plain := plainIssue{
		Code:   string(diag.CodeSingleSnapshot),
		Signal: diag.SignalWarn,
		Evidence: map[string]string{
			"snapshot_count": "1",
		},
		Action: "Add more snapshots",
	}

	plainData, err := json.Marshal(plain)
	if err != nil {
		t.Fatalf("Marshal plain error: %v", err)
	}

	// Unmarshal both and compare (can't compare bytes directly due to map ordering)
	var fromIssue, fromPlain map[string]json.RawMessage
	if err := json.Unmarshal(data, &fromIssue); err != nil {
		t.Fatalf("Unmarshal issue error: %v", err)
	}
	if err := json.Unmarshal(plainData, &fromPlain); err != nil {
		t.Fatalf("Unmarshal plain error: %v", err)
	}

	var issueEvidence, plainEvidence map[string]string
	if err := json.Unmarshal(fromIssue["evidence"], &issueEvidence); err != nil {
		t.Fatalf("Unmarshal issue evidence error: %v", err)
	}
	if err := json.Unmarshal(fromPlain["evidence"], &plainEvidence); err != nil {
		t.Fatalf("Unmarshal plain evidence error: %v", err)
	}

	if issueEvidence["snapshot_count"] != plainEvidence["snapshot_count"] {
		t.Errorf("evidence mismatch: issue=%v, plain=%v", issueEvidence, plainEvidence)
	}
}
