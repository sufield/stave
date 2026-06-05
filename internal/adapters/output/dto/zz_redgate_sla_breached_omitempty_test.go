package dto

import (
	"encoding/json"
	"testing"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
)

// Test_RedGate_SLABreachedOmitempty asserts the CORRECT behavior:
// a finding that DOES carry an SLA deadline but is currently within
// it (breached=false) must serialise an explicit "sla_breached": false
// so a compliance consumer can distinguish "has an SLA, not breached"
// from "has no SLA at all".
//
// Current code (types_finding.go:32) tags SLABreached as
// `sla_breached,omitempty`, which drops the field whenever the value
// is false — silently erasing the within-SLA signal. This test fails
// against that code: it expects the key present-as-false, the bug
// emits no key.
func Test_RedGate_SLABreachedOmitempty(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic during SLA-breached omitempty red gate: %v", r)
		}
	}()

	// Build a finding with an SLA deadline set (72h) but NOT breached.
	deadline := 72.0
	var f remediation.Finding
	f.RehydrateSLA(
		&deadline,           // non-nil deadline => SLADeadlinePtr() returns *72.0
		false,               // breached=false => SLABreachedFlag() returns false
		nil,                 // no overdue dwell
		policy.SeverityNone, // no escalation
		kernel.SLAPolicySourceControlOverride,
	)

	// Sanity-check the trigger preconditions via the public predicates
	// the mapper relies on, so the test is self-documenting.
	if got := f.SLADeadlinePtr(); got == nil || *got != deadline {
		t.Fatalf("precondition: SLADeadlinePtr() = %v, want non-nil *%v", got, deadline)
	}
	if f.SLABreachedFlag() {
		t.Fatalf("precondition: SLABreachedFlag() = true, want false (within SLA)")
	}

	dto := FromFinding(&f)

	raw, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal FindingDTO: %v", err)
	}

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("decode FindingDTO JSON into map: %v", err)
	}

	// Guard the trigger: the SLA-bearing deadline IS emitted, proving
	// this finding carries an SLA. Only the breach flag is at issue.
	if _, ok := decoded["sla_deadline_hours"]; !ok {
		t.Fatalf("expected sla_deadline_hours key present (SLA-bearing finding); JSON: %s", raw)
	}

	// CORRECT behavior: sla_breached must be present and explicitly false.
	val, ok := decoded["sla_breached"]
	if !ok {
		t.Fatalf("sla_breached key absent for an SLA-bearing, within-SLA finding; "+
			"the false breach state was silently dropped by omitempty. JSON: %s", raw)
	}
	if string(val) != "false" {
		t.Fatalf("sla_breached = %s, want false", val)
	}
}
