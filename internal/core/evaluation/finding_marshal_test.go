package evaluation

import (
	"encoding/json"
	"strings"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

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
