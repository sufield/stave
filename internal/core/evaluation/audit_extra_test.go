package evaluation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/predicate"
)

// --- CalculateReadiness ---

func makeReportWithFindings(failingIDs ...kernel.ControlID) *ComplianceReport {
	r := &ComplianceReport{}
	for _, id := range failingIDs {
		r.Findings = append(r.Findings, Finding{ControlID: id})
	}
	return r
}

func TestCalculateReadiness_EmptyFrameworks(t *testing.T) {
	r := makeReportWithFindings()
	r.CalculateReadiness(nil, nil, nil)
	if r.Summary.FrameworkReadiness != nil {
		t.Error("empty frameworks should result in nil readiness slice")
	}
}

func TestCalculateReadiness_AllPassing(t *testing.T) {
	allControls := []kernel.ControlID{"CTL.A.001", "CTL.B.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"hipaa": "164.312"},
		"CTL.B.001": {"hipaa": "164.308"},
	}
	r := makeReportWithFindings() // No findings = all passing.
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	if len(r.Summary.FrameworkReadiness) != 1 {
		t.Fatalf("expected 1 framework, got %d", len(r.Summary.FrameworkReadiness))
	}
	fr := r.Summary.FrameworkReadiness[0]
	if fr.Framework != "hipaa" {
		t.Errorf("Framework = %q, want hipaa", fr.Framework)
	}
	if fr.ReadinessPercent != 100 {
		t.Errorf("ReadinessPercent = %d, want 100", fr.ReadinessPercent)
	}
	if fr.TotalControls != 2 {
		t.Errorf("TotalControls = %d, want 2", fr.TotalControls)
	}
	if fr.PassingControls != 2 {
		t.Errorf("PassingControls = %d, want 2", fr.PassingControls)
	}
}

func TestCalculateReadiness_SomeFailing(t *testing.T) {
	allControls := []kernel.ControlID{"CTL.A.001", "CTL.B.001", "CTL.C.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"hipaa": "164.312"},
		"CTL.B.001": {"hipaa": "164.308"},
		"CTL.C.001": {"hipaa": "164.310"},
	}
	r := makeReportWithFindings("CTL.A.001") // One failing.
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	fr := r.Summary.FrameworkReadiness[0]
	if fr.PassingControls != 2 {
		t.Errorf("PassingControls = %d, want 2", fr.PassingControls)
	}
	// 2/3 = 66%
	if fr.ReadinessPercent != 66 {
		t.Errorf("ReadinessPercent = %d, want 66", fr.ReadinessPercent)
	}
}

func TestCalculateReadiness_ZeroControlsInFramework(t *testing.T) {
	// Controls exist but none mapped to the requested framework.
	allControls := []kernel.ControlID{"CTL.A.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"soc2": "CC6.1"},
	}
	r := makeReportWithFindings()
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	fr := r.Summary.FrameworkReadiness[0]
	// 0 total controls in hipaa → should return 100% (all 0 are passing).
	if fr.ReadinessPercent != 100 {
		t.Errorf("ReadinessPercent = %d, want 100 (no controls = fully compliant)", fr.ReadinessPercent)
	}
	if fr.TotalControls != 0 {
		t.Errorf("TotalControls = %d, want 0", fr.TotalControls)
	}
}

// --- computeSuperFix (via CalculateReadiness) ---

func TestCalculateReadiness_SuperFix(t *testing.T) {
	allControls := []kernel.ControlID{"CTL.A.001", "CTL.B.001"}
	compliance := map[kernel.ControlID]map[string]string{
		// CTL.A.001 covers both frameworks — should be the super fix.
		"CTL.A.001": {"hipaa": "164.312", "soc2": "CC6.1"},
		"CTL.B.001": {"hipaa": "164.308"},
	}
	r := makeReportWithFindings("CTL.A.001", "CTL.B.001") // Both failing.
	r.CalculateReadiness([]string{"hipaa", "soc2"}, allControls, compliance)

	sf := r.Summary.SuperFix
	if sf == nil {
		t.Fatal("expected a SuperFix, got nil")
	}
	if sf.ControlID != "CTL.A.001" {
		t.Errorf("SuperFix.ControlID = %q, want CTL.A.001", sf.ControlID)
	}
	if sf.FrameworkCount != 2 {
		t.Errorf("SuperFix.FrameworkCount = %d, want 2", sf.FrameworkCount)
	}
}

func TestCalculateReadiness_SuperFix_NoFailingControls(t *testing.T) {
	allControls := []kernel.ControlID{"CTL.A.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"hipaa": "164.312"},
	}
	r := makeReportWithFindings() // All passing.
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	if r.Summary.SuperFix != nil {
		t.Error("no failing controls → SuperFix should be nil")
	}
}

// --- computeNearbyFrameworks (via CalculateReadiness) ---

func TestCalculateReadiness_NearbyFrameworks(t *testing.T) {
	// We have two controls. CTL.A covers hipaa (requested) AND soc2 (not requested).
	// CTL.B covers only hipaa.
	// Both are passing, so soc2 readiness would be 100% → it should appear as nearby.
	allControls := []kernel.ControlID{"CTL.A.001", "CTL.B.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"hipaa": "164.312", "soc2": "CC6.1"},
		"CTL.B.001": {"hipaa": "164.308"},
	}
	r := makeReportWithFindings() // All passing.
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	if len(r.Summary.NearbyFrameworks) == 0 {
		t.Fatal("expected soc2 as a nearby framework")
	}
	found := false
	for _, nf := range r.Summary.NearbyFrameworks {
		if nf.Framework == "soc2" {
			found = true
			if nf.ReadinessPercent != 100 {
				t.Errorf("soc2 readiness = %d, want 100", nf.ReadinessPercent)
			}
		}
	}
	if !found {
		t.Error("soc2 not found in NearbyFrameworks")
	}
}

func TestCalculateReadiness_NearbyFrameworks_LowReadinessExcluded(t *testing.T) {
	// All controls failing → nearby framework with 0% should NOT appear.
	allControls := []kernel.ControlID{"CTL.A.001", "CTL.B.001", "CTL.C.001", "CTL.D.001", "CTL.E.001"}
	compliance := map[kernel.ControlID]map[string]string{
		"CTL.A.001": {"hipaa": "1", "soc2": "A"},
		"CTL.B.001": {"hipaa": "2", "soc2": "B"},
		"CTL.C.001": {"soc2": "C"},
		"CTL.D.001": {"soc2": "D"},
		"CTL.E.001": {"soc2": "E"},
	}
	// All 5 soc2 controls failing → 0% readiness → not nearby.
	r := makeReportWithFindings("CTL.A.001", "CTL.B.001", "CTL.C.001", "CTL.D.001", "CTL.E.001")
	r.CalculateReadiness([]string{"hipaa"}, allControls, compliance)

	for _, nf := range r.Summary.NearbyFrameworks {
		if nf.Framework == "soc2" {
			t.Errorf("soc2 at 0%% should not appear in nearby frameworks")
		}
	}
}

// --- RemediationAction.CanonicalKey ---

func TestRemediationAction_CanonicalKey(t *testing.T) {
	a := RemediationAction{
		ActionType: ActionSet,
		Path:       predicate.NewFieldPath("security_posture.block_public_access"),
		Value:      true,
	}
	key := a.CanonicalKey()
	if key == "" {
		t.Fatal("CanonicalKey should not be empty")
	}
	// Key must contain the action type and path.
	if !strings.Contains(key, "set") {
		t.Errorf("key should contain action type 'set': %q", key)
	}
	if !strings.Contains(key, "security_posture.block_public_access") {
		t.Errorf("key should contain path: %q", key)
	}
}

func TestRemediationAction_CanonicalKey_Deterministic(t *testing.T) {
	a := RemediationAction{
		ActionType: ActionSet,
		Path:       predicate.NewFieldPath("x"),
		Value:      false,
	}
	k1 := a.CanonicalKey()
	k2 := a.CanonicalKey()
	if k1 != k2 {
		t.Errorf("CanonicalKey not deterministic: %q vs %q", k1, k2)
	}
}

func TestRemediationAction_CanonicalKey_Format(t *testing.T) {
	// Key format is: "<action_type>|<path>|<json_value>"
	a := RemediationAction{
		ActionType: ActionSet,
		Path:       predicate.NewFieldPath("foo"),
		Value:      42,
	}
	key := a.CanonicalKey()
	valJSON, _ := json.Marshal(42)
	expected := "set|foo|" + string(valJSON)
	if key != expected {
		t.Errorf("CanonicalKey = %q, want %q", key, expected)
	}
}

func TestRemediationAction_CanonicalKey_NilValue(t *testing.T) {
	a := RemediationAction{
		ActionType: ActionSet,
		Path:       predicate.NewFieldPath("bar"),
		Value:      nil,
	}
	key := a.CanonicalKey()
	if !strings.Contains(key, "null") {
		t.Errorf("nil value should serialize to 'null': %q", key)
	}
}

// --- ComputeFingerprint (via RemediationPlan) ---

func TestComputeFingerprint_CanonicalKey_UsedForHashing(t *testing.T) {
	// Two plans with same actions in different order should produce the same fingerprint.
	d := stubDigester{}
	plan1 := &RemediationPlan{
		Actions: []RemediationAction{
			{ActionType: ActionSet, Path: predicate.NewFieldPath("a"), Value: true},
			{ActionType: ActionSet, Path: predicate.NewFieldPath("b"), Value: false},
		},
	}
	plan2 := &RemediationPlan{
		Actions: []RemediationAction{
			{ActionType: ActionSet, Path: predicate.NewFieldPath("b"), Value: false},
			{ActionType: ActionSet, Path: predicate.NewFieldPath("a"), Value: true},
		},
	}
	plan1.ComputeFingerprint(d)
	plan2.ComputeFingerprint(d)
	if plan1.ActionsFingerprint != plan2.ActionsFingerprint {
		t.Errorf("different action order should produce same fingerprint: %q vs %q",
			plan1.ActionsFingerprint, plan2.ActionsFingerprint)
	}
}

// stubDigester is a test double for ports.Digester.
type stubDigester struct{}

func (stubDigester) Digest(parts []string, sep byte) kernel.Digest {
	combined := ""
	for i, p := range parts {
		if i > 0 {
			combined += string(sep)
		}
		combined += p
	}
	// Return a 24-char digest so [:16] slice works.
	padded := combined + "000000000000000000000000"
	return kernel.Digest(padded[:24])
}

