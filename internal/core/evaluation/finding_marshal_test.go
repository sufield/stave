package evaluation

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

// TestFindingSuggestedFixAndLogicalProof_AbsentByDefault pins the
// Iter 5.2 contract: the new fields are optional. A finding
// produced without solver enrichment must NOT serialize empty
// values for SuggestedFix / LogicalProof — both are absent from
// the JSON until populated.
func TestFindingSuggestedFixAndLogicalProof_AbsentByDefault(t *testing.T) {
	t.Parallel()
	f := Finding{
		ControlID: "CTL.TEST.001",
		AssetID:   "arn:aws:s3:::demo",
	}
	raw, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)
	if strings.Contains(body, "suggested_fix") {
		t.Errorf("default Finding must not serialize suggested_fix: %s", body)
	}
	if strings.Contains(body, "logical_proof") {
		t.Errorf("default Finding must not serialize logical_proof: %s", body)
	}
}

// TestFindingSuggestedFixAndLogicalProof_RoundTrip pins symmetric
// JSON encoding for the new fields. A finding populated with
// solver-derived values marshals through the shadow path and
// round-trips back to the same values.
func TestFindingSuggestedFixAndLogicalProof_RoundTrip(t *testing.T) {
	t.Parallel()
	f := Finding{
		ControlID: "CTL.TEST.002",
		AssetID:   "arn:aws:s3:::demo",
		SuggestedFix: map[string]any{
			"action": "set_block_public_policy",
			"value":  true,
		},
		LogicalProof: "principal == * AND network == public; setting BlockPublicPolicy=true makes the invariant SAT",
	}

	raw, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	body := string(raw)
	if !strings.Contains(body, "suggested_fix") {
		t.Errorf("suggested_fix missing from output: %s", body)
	}
	if !strings.Contains(body, "logical_proof") {
		t.Errorf("logical_proof missing from output: %s", body)
	}

	var decoded Finding
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.LogicalProof != f.LogicalProof {
		t.Errorf("LogicalProof: want %q, got %q", f.LogicalProof, decoded.LogicalProof)
	}
	if got := decoded.SuggestedFix["action"]; got != "set_block_public_policy" {
		t.Errorf("SuggestedFix[action]: want set_block_public_policy, got %v", got)
	}
}

// TestFindingMarshalShadow pins the wire-format invariant: the
// Shadow Struct in MarshalJSON must emit the original sla_*
// JSON tags so external consumers see the identical payload
// after the field-privatization refactor.
func TestFindingMarshalShadow(t *testing.T) {
	t.Parallel()
	deadline := 168.0
	overdue := 24.0
	f := Finding{
		ControlID: "CTL.S3.ACCESS.001",
		AssetID:   "arn:aws:s3:::test",
	}
	f.RehydrateSLA(&deadline, true, &overdue, policy.SeverityCritical,
		kernel.SLAPolicySourceProfile("default"))

	raw, err := json.Marshal(&f)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out := string(raw)

	for _, want := range []string{
		`"sla_deadline_hours":168`,
		`"sla_breached":true`,
		`"sla_overdue_hours":24`,
		`"sla_escalated_severity":"critical"`,
		`"sla_policy_source":"profile:default"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("marshal output missing %q\nfull: %s", want, out)
		}
	}
}

// TestFindingMarshalRoundtrip pins symmetric encoding: a Finding
// rehydrated, marshaled, and unmarshaled must reproduce the same
// SLA state. UnmarshalJSON must populate the private slots from
// the shadow's exported tags.
func TestFindingMarshalRoundtrip(t *testing.T) {
	t.Parallel()
	deadline := 72.0
	overdue := 12.0
	original := Finding{ControlID: "CTL.X.001", AssetID: "arn:test"}
	original.RehydrateSLA(&deadline, true, &overdue, policy.SeverityHigh,
		kernel.SLAPolicySourceControlOverride)

	raw, err := json.Marshal(&original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var roundtripped Finding
	if err := json.Unmarshal(raw, &roundtripped); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	dl, ok := roundtripped.SLADeadlineValue()
	if !ok || dl != deadline {
		t.Errorf("deadline = (%v, %v), want (%v, true)", dl, ok, deadline)
	}
	if !roundtripped.IsAnyBreach() {
		t.Error("breach flag lost in round-trip")
	}
	od, ok := roundtripped.OverdueHours()
	if !ok || od != overdue {
		t.Errorf("overdue = (%v, %v), want (%v, true)", od, ok, overdue)
	}
	if got := roundtripped.SLAEscalatedSeverityValue(); got != policy.SeverityHigh {
		t.Errorf("escalated severity = %v, want high", got)
	}
	if got := roundtripped.SLAPolicySourceLabel(); got != "control_override" {
		t.Errorf("policy source = %q, want control_override", got)
	}
}
