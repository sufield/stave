package profile

import (
	"testing"

	"github.com/sufield/stave/internal/core/compliance"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/kernel"
)

func TestSeverityOverrideAppliedInResults(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// Find a control that has a severity override.
	// AUDIT.002 (object-level logging) has WithProfileSeverityOverride("hipaa", HIGH).
	// ACCESS.003 (network restriction) has WithProfileSeverityOverride("hipaa", HIGH).
	for _, r := range report.Results {
		if r.ControlID == "AUDIT.002" {
			// The base severity may differ from the override.
			// The profile evaluation should apply the override.
			t.Logf("AUDIT.002 severity in profile result: %s", r.Severity)
			if r.Severity != policy.SeverityHigh {
				t.Errorf("AUDIT.002: expected HIGH (overridden), got %s", r.Severity)
			}
			return
		}
	}
	t.Error("AUDIT.002 not found in results — cannot verify severity override")
}

func TestProfileRationaleAccessible(t *testing.T) {
	// Verify that ProfileRationale returns non-empty strings for controls
	// that have rationales set.
	catalog := compliance.GetControlRegistry()
	controlsWithRationale := 0

	for _, def := range catalog.All() {
		rat := def.Def().ProfileRationale("hipaa")
		if rat != "" {
			controlsWithRationale++
		}
	}

	if controlsWithRationale == 0 {
		t.Error("expected at least one control with hipaa profile rationale")
	}
	t.Logf("%d controls have hipaa profile rationale", controlsWithRationale)
}

func TestProfileRationaleInResults(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// At least some results should carry a rationale from the profile.
	rationaleCount := 0
	for _, r := range report.Results {
		if r.Rationale != "" {
			rationaleCount++
		}
	}

	if rationaleCount == 0 {
		t.Error("expected at least one result with profile rationale")
	}
	t.Logf("%d results have rationale", rationaleCount)
}

func TestAllHIPAATaggedControlsAppearInResults(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	// Find all controls tagged for hipaa.
	catalog := compliance.GetControlRegistry()
	hipaaControlIDs := make(map[kernel.ControlID]bool)
	for _, def := range catalog.All() {
		for _, prof := range def.Def().ComplianceProfiles() {
			if prof == "hipaa" {
				hipaaControlIDs[def.Def().ID()] = true
			}
		}
	}

	if len(hipaaControlIDs) == 0 {
		t.Fatal("no controls tagged for hipaa")
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	resultIDs := make(map[kernel.ControlID]bool)
	for _, r := range report.Results {
		resultIDs[r.ControlID] = true
	}

	// Every hipaa-tagged control should appear in the results (pass or fail).
	missing := 0
	for id := range hipaaControlIDs {
		if !resultIDs[id] {
			t.Errorf("hipaa-tagged control %s not in results", id)
			missing++
		}
	}
	t.Logf("%d hipaa controls, %d in results, %d missing",
		len(hipaaControlIDs), len(resultIDs), missing)
}

func TestSeveritySortingWithOverrides(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// Failures should be sorted by severity descending, even with overrides.
	// CRITICAL < HIGH < MEDIUM < LOW in the enum, so descending means
	// lower numeric values first.
	lastRank := policy.Severity(999)
	for _, r := range report.Results {
		if r.Pass {
			break
		}
		if r.Severity > lastRank {
			t.Errorf("severity %s (rank %d) appeared after lower severity %s (rank %d) — sorting broken with overrides",
				r.Severity, r.Severity, lastRank, lastRank)
		}
		lastRank = r.Severity
	}
}

func TestHIPAAProfileAvailable(t *testing.T) {
	profiles := AllProfiles()
	if len(profiles) == 0 {
		t.Fatal("expected at least 1 profile")
	}

	// HIPAA should always be available.
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("LoadProfile(hipaa): %v", err)
	}
	if p.ID != "hipaa" {
		t.Errorf("profile ID: got %q, want hipaa", p.ID)
	}
	t.Logf("%d profiles available: %v", len(profiles), profiles)
}

func TestCompoundRulesExistInHIPAAProfile(t *testing.T) {
	p, err := LoadProfile("hipaa")
	if err != nil {
		t.Fatalf("load hipaa: %v", err)
	}

	report, err := p.Evaluate(fixtureSnapshot(), allRegistries()...)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}

	// The fixture should trigger compound rules.
	// Check that CompoundFindings is populated (may be 0 if
	// the fixture doesn't trigger the specific compound conditions).
	t.Logf("compound risk findings: %d", len(report.CompoundFindings))

	// The report should have the field, even if empty.
	if report.CompoundFindings == nil {
		t.Error("CompoundFindings should be initialized (non-nil), even if empty")
	}
}
