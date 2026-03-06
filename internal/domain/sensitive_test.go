package domain

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/kernel"
)

func TestSensitive_String(t *testing.T) {
	s := kernel.Sensitive("my-secret")
	if got := s.String(); got != kernel.SanitizedValue {
		t.Errorf("String() = %q, want %q", got, kernel.SanitizedValue)
	}
}

func TestSensitive_GoString(t *testing.T) {
	s := kernel.Sensitive("my-secret")
	if got := s.GoString(); got != kernel.SanitizedValue {
		t.Errorf("GoString() = %q, want %q", got, kernel.SanitizedValue)
	}
}

func TestSensitive_Value(t *testing.T) {
	s := kernel.Sensitive("my-secret")
	if got := s.Value(); got != "my-secret" {
		t.Errorf("Value() = %q, want %q", got, "my-secret")
	}
}

func TestSensitive_MarshalJSON(t *testing.T) {
	s := kernel.Sensitive("my-secret")
	data, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("MarshalJSON error: %v", err)
	}
	want := `"` + kernel.SanitizedValue + `"`
	if string(data) != want {
		t.Errorf("MarshalJSON() = %s, want %s", data, want)
	}
}

func TestSensitive_MarshalYAML(t *testing.T) {
	s := kernel.Sensitive("my-secret")
	val, err := s.MarshalYAML()
	if err != nil {
		t.Fatalf("MarshalYAML error: %v", err)
	}
	if val != kernel.SanitizedValue {
		t.Errorf("MarshalYAML() = %v, want %v", val, kernel.SanitizedValue)
	}
}

func TestSensitive_FmtVerbs(t *testing.T) {
	s := kernel.Sensitive("my-secret")

	tests := []struct {
		format string
		want   string
	}{
		{"%s", kernel.SanitizedValue},
		{"%v", kernel.SanitizedValue},
		{"%#v", kernel.SanitizedValue},
	}

	for _, tt := range tests {
		got := fmt.Sprintf(tt.format, s)
		if got != tt.want {
			t.Errorf("Sprintf(%q, s) = %q, want %q", tt.format, got, tt.want)
		}
	}
}

func TestSensitive_JSONStructField(t *testing.T) {
	type config struct {
		Name   string           `json:"name"`
		Secret kernel.Sensitive `json:"secret"`
	}

	c := config{Name: "test", Secret: kernel.Sensitive("hunter2")}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}

	var raw map[string]string
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if raw["name"] != "test" {
		t.Errorf("name = %q, want %q", raw["name"], "test")
	}
	if raw["secret"] != kernel.SanitizedValue {
		t.Errorf("secret = %q, want %q", raw["secret"], kernel.SanitizedValue)
	}
}

func TestIssue_MarshalJSON_SensitiveEvidence(t *testing.T) {
	evidence := kernel.NewSanitizableMap(map[string]string{
		"control_id": "CTL.EXP.STATE.001",
	})
	evidence.SetSensitive("error", "parse error at /secret/path")

	issue := diag.Issue{
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
	if evidenceMap["error"] != kernel.SanitizedValue {
		t.Errorf("error = %q, want %q (should be sanitized)", evidenceMap["error"], kernel.SanitizedValue)
	}
}

func TestIssue_MarshalJSON_NonSensitiveEvidence(t *testing.T) {
	issue := diag.Issue{
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
		Code:   diag.CodeSingleSnapshot,
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
